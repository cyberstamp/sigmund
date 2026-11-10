package dev.cyberstamp.sigmund.core;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

/**
 * Where Bouncy Castle's keys live: finding them, storing them, and saying where each came from.
 *
 * <p>
 * Key sources are searched in order:
 * <ol>
 * <li>Keys fetched from keyservers this session and kept in memory</li>
 * <li>GnuPG pubring ({@code pubring.kbx} or legacy {@code pubring.gpg}) — read-only</li>
 * <li>Shared cert-d directory — read/write for certs</li>
 * <li>BC-owned private key store — read/write for TSKs</li>
 * </ol>
 *
 * <p>
 * A fetched key is kept in memory or persisted to cert-d according to the store's
 * {@code import-to-keyring} setting, and the keyserver that served it is recorded with it in
 * the same step.
 */
class BcKeyStore {

    /**
     * The result of looking a key up: where it was looked for or came from, and the key.
     *
     * @param source the keyserver that served the key this session, or the store consulted
     * @param ring the key ring, or {@code null} when an inspected store has none; a lookup
     *        that finds nothing anywhere returns no {@code KeyLookup} at all
     */
    record KeyLookup(TrustRootRef source, PGPPublicKeyRing ring) {
    }

    /**
     * The result of searching every store for a key: a readable copy, or one that could not be
     * read.
     *
     * @param found the key and its source, or {@code null} when no store holds a readable copy
     * @param unreadable when nothing was found, a copy of this very key that could not be read;
     *        {@code null} when something was found, or no copy at all
     */
    record PublicKeySearch(KeyLookup found, UnreadableCertificate unreadable) {
    }

    private final Path gnupgHome;
    private final Path certDHome;
    private final Path bcPrivateHome;
    private final Map<String, PGPPublicKeyRing> ephemeralKeys = new ConcurrentHashMap<>();
    private final Map<String, String> fetchedFrom = new ConcurrentHashMap<>();
    private final Set<String> warnedUnreadable = ConcurrentHashMap.newKeySet();
    private final boolean persistFetched;

    /**
     * Creates a key store that keeps fetched keys in memory for the session.
     *
     * @param gnupgHome the GnuPG home directory, or {@code null} to skip GnuPG lookup
     * @param certDHome the shared cert-d directory
     * @param bcPrivateHome the BC private key store directory
     */
    BcKeyStore(Path gnupgHome, Path certDHome, Path bcPrivateHome) {
        this(gnupgHome, certDHome, bcPrivateHome, false);
    }

    /**
     * Creates a key store.
     *
     * @param gnupgHome the GnuPG home directory, or {@code null} to skip GnuPG lookup
     * @param certDHome the shared cert-d directory
     * @param bcPrivateHome the BC private key store directory
     * @param persistFetched whether fetched keys are written to cert-d — the
     *        {@code import-to-keyring} setting — rather than kept in memory for the session
     */
    BcKeyStore(Path gnupgHome, Path certDHome, Path bcPrivateHome, boolean persistFetched) {
        this.gnupgHome = gnupgHome;
        this.certDHome = certDHome;
        this.bcPrivateHome = bcPrivateHome;
        this.persistFetched = persistFetched;
    }

    /**
     * Returns the cert-d store this key store reads and writes.
     *
     * @return the cert-d directory
     */
    Path certDHome() {
        return certDHome;
    }

    /**
     * Finds the key ring holding a fingerprint, together with where it came from.
     *
     * <p>
     * Stores are searched in order: the in-memory cache of keys fetched this session, the
     * GnuPG keyring, the cert-d store, then Bouncy Castle's private store. A key fetched in
     * this session names the keyserver that served it, wherever it was then stored; otherwise
     * the store it was found in is named. The source explains a differing result — two
     * machines trusting different stores — and is reported, never used to accept a key: the
     * signature proves the key whoever served it.
     *
     * @param fingerprint the fingerprint of the primary key or a subkey
     * @return the key and its source, or {@code null} when no store holds a readable copy
     * @see #searchPublicKey(String)
     */
    KeyLookup findPublicKey(String fingerprint) {
        return searchPublicKey(fingerprint).found();
    }

    /**
     * Searches every store for a key, as {@link #findPublicKey(String)} does, and when no store
     * holds a readable copy says which copies could not be read.
     *
     * <p>
     * A certificate Bouncy Castle cannot read — an algorithm it does not know, a damaged file —
     * is never taken for an absent one, and the search goes on past it. When nothing usable is
     * found, a copy of this very key that could not be read is returned, so that the key is
     * reported as unreadable rather than missing. A copy whose keys cannot be told apart
     * concerns no key in particular: it is a damaged store, warned about once rather than
     * reported with every key.
     *
     * @param fingerprint the fingerprint of the primary key or a subkey, or a 64-bit key ID
     * @return the key found, or a copy of it that could not be read
     */
    PublicKeySearch searchPublicKey(String fingerprint) {
        List<UnreadableCertificate> unreadable = new ArrayList<>();
        KeyLookup found = findInStores(fingerprint, unreadable);
        if (found != null) {
            return new PublicKeySearch(found, null);
        }
        unreadable.stream().filter(certificate -> certificate.keys().isEmpty()).forEach(this::warnOnce);
        return new PublicKeySearch(null, unreadable.stream()
                .filter(certificate -> certificate.holds(fingerprint))
                .findFirst()
                .orElse(null));
    }

    /**
     * Whether two key designations name the same key: equal fingerprints, or a fingerprint and
     * the 64-bit key ID it ends with.
     */
    static boolean sameKey(String one, String other) {
        String a = one.toUpperCase();
        String b = other.toUpperCase();
        return a.equals(b) || a.endsWith(b) || b.endsWith(a);
    }

    private void warnOnce(UnreadableCertificate certificate) {
        if (warnedUnreadable.add(certificate.file() + " " + certificate.message())) {
            System.getLogger(BcKeyStore.class.getName()).log(System.Logger.Level.WARNING,
                    certificate.file() + " in " + certificate.source().displayName() + " cannot be read ("
                            + certificate.message() + "); keys it holds are not available to Bouncy Castle");
        }
    }

    private KeyLookup findInStores(String fingerprint, List<UnreadableCertificate> unreadable) {
        PGPPublicKeyRing ring = findInEphemeral(fingerprint);
        if (ring != null) {
            return new KeyLookup(fetchedFromSource(ring), ring);
        }
        ring = findInGnupgPubring(fingerprint, unreadable);
        if (ring != null) {
            return found(ring, TrustRootRef.gnupgKeyring(gnupgHome));
        }
        ring = findInCertD(fingerprint, unreadable);
        if (ring != null) {
            return found(ring, TrustRootRef.certD(certDHome));
        }
        ring = findInBcPrivate(fingerprint);
        return ring == null ? null : found(ring, TrustRootRef.bcPrivateStore(bcPrivateHome));
    }

    /**
     * Pairs a key ring with where it came from.
     *
     * <p>
     * A keyserver recorded for the ring by {@link #addFetched} takes precedence over
     * the store the ring was found in: a key fetched this session and then persisted to
     * cert-d, or cached in memory, came from that keyserver, and the store only holds it.
     * The ring is identified by its primary fingerprint, so the recorded source applies
     * whether it was looked up by the primary key or a subkey.
     *
     * @param ring the key ring that was found
     * @param store the store it was found in, used when no keyserver is recorded for it
     * @return the key ring and its source
     */
    private KeyLookup found(PGPPublicKeyRing ring, TrustRootRef store) {
        String keyserver = fetchedFrom.get(fingerprintHex(ring).toUpperCase());
        return new KeyLookup(keyserver != null ? TrustRootRef.keyserver(keyserver) : store, ring);
    }

    /**
     * Names the keyserver a key held in memory came from: only fetched keys are kept there,
     * and {@link #addFetched} records the keyserver as it adds them.
     */
    private TrustRootRef fetchedFromSource(PGPPublicKeyRing ring) {
        return TrustRootRef.keyserver(fetchedFrom.get(fingerprintHex(ring).toUpperCase()));
    }

    /**
     * Adds a key fetched from a keyserver, recording the keyserver it came from.
     *
     * <p>
     * Unless the store persists fetched keys, the key is kept in memory: available for
     * verification for the rest of this session, but never written to the cert-d directory,
     * so fetching a key to check one build does not silently grow the machine's trust
     * surface. A persisted key is written to cert-d. Either way, a later lookup in this
     * session reports the keyserver as the key's source.
     *
     * @param keyRing the fetched key ring
     * @param keyserver the keyserver URL it came from
     */
    void addFetched(PGPPublicKeyRing keyRing, String keyserver) {
        String fingerprint = fingerprintHex(keyRing).toUpperCase();
        if (persistFetched) {
            storeCert(keyRing);
        } else {
            ephemeralKeys.put(fingerprint, keyRing);
        }
        fetchedFrom.put(fingerprint, keyserver);
    }

    /**
     * Searches the in-memory ephemeral cache for a key matching the given fingerprint.
     */
    private PGPPublicKeyRing findInEphemeral(String fingerprint) {
        PGPPublicKeyRing direct = ephemeralKeys.get(fingerprint.toUpperCase());
        if (direct != null) {
            return direct;
        }
        for (PGPPublicKeyRing ring : ephemeralKeys.values()) {
            if (matchesFingerprint(ring, fingerprint)) {
                return ring;
            }
        }
        return null;
    }

    /**
     * Searches the BC private key store for a secret key matching the given fingerprint.
     *
     * @param fingerprint the uppercase hex fingerprint to search for
     * @return the matching secret key ring, or {@code null} if not found
     */
    PGPSecretKeyRing findSecretKey(String fingerprint) {
        Path keyFile = secretKeyFile(fingerprint);
        if (!Files.isRegularFile(keyFile)) {
            return null;
        }
        return readSecretKeyRing(keyFile);
    }

    /**
     * Writes a public certificate to the shared cert-d directory.
     *
     * @param keyRing the public key ring to store
     */
    void storeCert(PGPPublicKeyRing keyRing) {
        String fp = fingerprintHex(keyRing).toLowerCase();
        Path certFile = certDFile(fp);
        writeKeyRing(certFile, keyRing);
    }

    /**
     * Writes a secret key to the BC private key store.
     *
     * @param secretKeyRing the secret key ring to store
     */
    void storeSecretKey(PGPSecretKeyRing secretKeyRing) {
        String fp = fingerprintHex(secretKeyRing).toLowerCase();
        Path keyFile = secretKeyFile(fp);
        writeKeyRing(keyFile, secretKeyRing);
    }

    /**
     * Finds the primary user ID for a key matching the given fingerprint.
     *
     * @param fingerprint the uppercase hex fingerprint to search for
     * @return the primary user ID, or {@code null} if no key or UID found
     */
    String findPrimaryUserId(String fingerprint) {
        KeyLookup found = findPublicKey(fingerprint);
        return found == null ? null : primaryUserIdOf(found.ring());
    }

    /**
     * Returns the first user ID on a key ring, for display: a user ID is self-certified and
     * proves nothing about who holds the key.
     *
     * @param keyRing the key ring
     * @return the user ID, or {@code null} when the ring carries none
     */
    String primaryUserIdOf(PGPPublicKeyRing keyRing) {
        Iterator<String> uids = keyRing.getPublicKey().getUserIDs();
        return uids.hasNext() ? uids.next() : null;
    }

    /**
     * Checks whether any User ID on the primary key contains the given email.
     */
    private boolean uidContainsEmail(PGPPublicKeyRing ring, String lowerEmail) {
        Iterator<String> uids = ring.getPublicKey().getUserIDs();
        while (uids.hasNext()) {
            if (uids.next().toLowerCase().contains(lowerEmail)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Searches the GnuPG pubring for a key whose User ID contains the given email.
     * Tries {@code pubring.kbx} first, then falls back to legacy {@code pubring.gpg}.
     */
    private PGPPublicKeyRing findByEmailInPubring(String lowerEmail) {
        if (gnupgHome == null)
            return null;
        Path pubringKbx = gnupgHome.resolve("pubring.kbx");
        if (Files.isRegularFile(pubringKbx)) {
            PGPPublicKeyRing result = findByEmailInKeyBox(pubringKbx, lowerEmail);
            if (result != null) {
                return result;
            }
        }
        Path pubringGpg = gnupgHome.resolve("pubring.gpg");
        if (!Files.isRegularFile(pubringGpg))
            return null;
        return KeyRingFiles.findInKeyRingFile(pubringGpg, ring -> uidContainsEmail(ring, lowerEmail),
                TrustRootRef.gnupgKeyring(gnupgHome), new ArrayList<>());
    }

    /**
     * Scans the cert-d directory for a cert whose User ID contains the given email.
     */
    private PGPPublicKeyRing findByEmailInCertD(String lowerEmail) {
        if (certDHome == null || !Files.isDirectory(certDHome))
            return null;
        try (DirectoryStream<Path> dirs = Files.newDirectoryStream(certDHome, Files::isDirectory)) {
            for (Path dir : dirs) {
                try (DirectoryStream<Path> files = Files.newDirectoryStream(dir, Files::isRegularFile)) {
                    for (Path file : files) {
                        PGPPublicKeyRing ring = readCertDFile(file, new ArrayList<>());
                        if (ring != null && uidContainsEmail(ring, lowerEmail))
                            return ring;
                    }
                }
            }
        } catch (IOException e) {
            // cert-d not accessible
        }
        return null;
    }

    /**
     * Looks a signer up in each local store separately, for an inspection report.
     *
     * <p>
     * The GnuPG pubring and the cert-d store are answered whenever they exist, found or not;
     * the in-memory cache of fetched keys only when it holds the key. The BC private store
     * holds secret keys and is not inspected.
     *
     * @param fingerprint the fingerprint to look for, or {@code null} to look up by email
     * @param email the address to look for in user IDs, used when no fingerprint is given
     * @return one lookup per store — GnuPG pubring, cert-d, then keys fetched this session,
     *         named by the keyserver that served them — or none when neither a fingerprint nor
     *         an address is given
     */
    List<KeyLookup> inspect(String fingerprint, String email) {
        String lowerEmail = email == null || email.isEmpty() ? null : email.toLowerCase();
        if (fingerprint == null && lowerEmail == null) {
            return List.of();
        }
        List<KeyLookup> lookups = new ArrayList<>(3);
        if (hasGnupgPubring()) {
            lookups.add(new KeyLookup(TrustRootRef.gnupgKeyring(gnupgHome), fingerprint != null
                    ? findInGnupgPubring(fingerprint, new ArrayList<>())
                    : findByEmailInPubring(lowerEmail)));
        }
        if (hasCertD()) {
            lookups.add(new KeyLookup(TrustRootRef.certD(certDHome), fingerprint != null
                    ? findInCertD(fingerprint, new ArrayList<>())
                    : findByEmailInCertD(lowerEmail)));
        }
        PGPPublicKeyRing fetched = fingerprint != null
                ? findInEphemeral(fingerprint)
                : findByEmailInEphemeral(lowerEmail);
        if (fetched != null) {
            lookups.add(new KeyLookup(fetchedFromSource(fetched), fetched));
        }
        return List.copyOf(lookups);
    }

    private PGPPublicKeyRing findByEmailInEphemeral(String lowerEmail) {
        for (PGPPublicKeyRing ring : ephemeralKeys.values()) {
            if (uidContainsEmail(ring, lowerEmail)) {
                return ring;
            }
        }
        return null;
    }

    /**
     * Returns {@code true} if a GnuPG pubring file ({@code pubring.kbx} or
     * legacy {@code pubring.gpg}) exists.
     */
    private boolean hasGnupgPubring() {
        return gnupgHome != null
                && (Files.isRegularFile(gnupgHome.resolve("pubring.kbx"))
                        || Files.isRegularFile(gnupgHome.resolve("pubring.gpg")));
    }

    /**
     * Returns {@code true} if the cert-d home directory exists.
     */
    private boolean hasCertD() {
        return certDHome != null && Files.isDirectory(certDHome);
    }

    /**
     * Searches the GnuPG pubring for a key matching the fingerprint.
     * Tries {@code pubring.kbx} (modern GnuPG 2.1+) first, then falls back
     * to the legacy {@code pubring.gpg}; a key that cannot be read is recorded and skipped.
     */
    private PGPPublicKeyRing findInGnupgPubring(String fingerprint, List<UnreadableCertificate> unreadable) {
        if (gnupgHome == null) {
            return null;
        }
        TrustRootRef source = TrustRootRef.gnupgKeyring(gnupgHome);
        Path pubringKbx = gnupgHome.resolve("pubring.kbx");
        if (Files.isRegularFile(pubringKbx)) {
            PGPPublicKeyRing result = KeyRingFiles.findInKeyBox(pubringKbx,
                    ring -> matchesFingerprint(ring, fingerprint), source, unreadable);
            if (result != null) {
                return result;
            }
        }
        Path pubringGpg = gnupgHome.resolve("pubring.gpg");
        if (Files.isRegularFile(pubringGpg)) {
            return KeyRingFiles.findInKeyRingFile(pubringGpg,
                    ring -> matchesFingerprint(ring, fingerprint), source, unreadable);
        }
        return null;
    }

    /**
     * Searches a GnuPG keybox ({@code .kbx}) file for a key whose User ID
     * contains the given email.
     */
    private PGPPublicKeyRing findByEmailInKeyBox(Path kbxFile, String lowerEmail) {
        return KeyRingFiles.findInKeyBox(kbxFile, ring -> uidContainsEmail(ring, lowerEmail),
                TrustRootRef.gnupgKeyring(gnupgHome), new ArrayList<>());
    }

    /**
     * Searches the cert-d directory for a cert matching the fingerprint.
     */
    private PGPPublicKeyRing findInCertD(String fingerprint, List<UnreadableCertificate> unreadable) {
        String lower = fingerprint.toLowerCase();
        if (lower.length() < 3) {
            return null;
        }
        Path certFile = certDFile(lower);
        if (Files.isRegularFile(certFile)) {
            return readCertDFile(certFile, unreadable);
        }
        return scanCertDForSubkey(fingerprint, unreadable);
    }

    /**
     * Reads a cert-d file, which is named after its certificate's primary key: an unreadable one
     * whose packets cannot be told apart is recorded as a copy of that key.
     */
    private PGPPublicKeyRing readCertDFile(Path file, List<UnreadableCertificate> unreadable) {
        String named = file.getParent().getFileName().toString() + file.getFileName();
        return KeyRingFiles.readCertificate(file, TrustRootRef.certD(certDHome),
                named.matches("[0-9a-fA-F]{40}|[0-9a-fA-F]{64}") ? Set.of(named) : Set.of(), unreadable);
    }

    /**
     * Scans the cert-d directory for a cert where the fingerprint matches a subkey.
     */
    private PGPPublicKeyRing scanCertDForSubkey(String fingerprint, List<UnreadableCertificate> unreadable) {
        if (!Files.isDirectory(certDHome)) {
            return null;
        }
        try (DirectoryStream<Path> dirs = Files.newDirectoryStream(certDHome, Files::isDirectory)) {
            for (Path dir : dirs) {
                try (DirectoryStream<Path> files = Files.newDirectoryStream(dir, Files::isRegularFile)) {
                    for (Path file : files) {
                        PGPPublicKeyRing ring = readCertDFile(file, unreadable);
                        if (ring != null && matchesFingerprint(ring, fingerprint)) {
                            return ring;
                        }
                    }
                }
            }
        } catch (IOException e) {
            // cert-d not accessible
        }
        return null;
    }

    /**
     * Searches the BC private store for a public key extracted from a secret key.
     */
    private PGPPublicKeyRing findInBcPrivate(String fingerprint) {
        PGPSecretKeyRing secretRing = findSecretKey(fingerprint);
        if (secretRing == null) {
            return null;
        }
        // Extract public keys from secret key ring
        List<PGPPublicKey> pubKeys = new ArrayList<>();
        secretRing.getPublicKeys().forEachRemaining(pubKeys::add);
        return new PGPPublicKeyRing(pubKeys);
    }

    /**
     * Checks whether a public key ring contains a key matching the given fingerprint.
     */
    static boolean matchesFingerprint(PGPPublicKeyRing ring, String fingerprint) {
        String upper = fingerprint.toUpperCase();
        Iterator<PGPPublicKey> keys = ring.getPublicKeys();
        while (keys.hasNext()) {
            PGPPublicKey key = keys.next();
            String keyFp = bytesToHex(key.getFingerprint()).toUpperCase();
            if (keyFp.equals(upper) || keyFp.endsWith(upper) || upper.endsWith(keyFp)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Reads a PGP public key ring from a file.
     */
    static PGPPublicKeyRing readPublicKeyRing(Path file) {
        return KeyRingFiles.readCertificate(file, TrustRootRef.unknown(), Set.of(), new ArrayList<>());
    }

    /**
     * Reads a PGP secret key ring from a file.
     */
    private PGPSecretKeyRing readSecretKeyRing(Path file) {
        try (InputStream in = new BufferedInputStream(Files.newInputStream(file));
                InputStream decoded = PGPUtil.getDecoderStream(in)) {
            return new PGPSecretKeyRing(decoded, new BcKeyFingerprintCalculator());
        } catch (IOException | PGPException e) {
            return null;
        }
    }

    private static final Set<PosixFilePermission> OWNER_ONLY_PERMS = Set.of(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

    private static final FileAttribute<Set<PosixFilePermission>> OWNER_ONLY_ATTR = PosixFilePermissions
            .asFileAttribute(OWNER_ONLY_PERMS);

    /**
     * Writes a key ring to a file, creating parent directories as needed.
     * Secret key files (under bcPrivateHome) are created with owner-only (600) permissions
     * from the start to avoid a TOCTOU window where the file is world-readable.
     */
    private void writeKeyRing(Path file, org.bouncycastle.openpgp.PGPKeyRing keyRing) {
        try {
            Files.createDirectories(file.getParent());
            boolean isPrivateKey = bcPrivateHome != null && file.startsWith(bcPrivateHome);
            if (isPrivateKey) {
                try {
                    Files.deleteIfExists(file);
                    Files.createFile(file, OWNER_ONLY_ATTR);
                    try (OutputStream out = Files.newOutputStream(file,
                            StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
                        keyRing.encode(out);
                    }
                    return;
                } catch (UnsupportedOperationException e) {
                    // non-POSIX filesystem — fall through to default write
                }
            }
            try (OutputStream out = Files.newOutputStream(file)) {
                keyRing.encode(out);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to write key to " + file, e);
        }
    }

    /**
     * Computes the cert-d file path for a given lowercase hex fingerprint.
     */
    private Path certDFile(String lowerFingerprint) {
        return certDHome.resolve(lowerFingerprint.substring(0, 2))
                .resolve(lowerFingerprint.substring(2));
    }

    /**
     * Computes the secret key file path for a given fingerprint.
     */
    private Path secretKeyFile(String fingerprint) {
        String lower = fingerprint.toLowerCase();
        return bcPrivateHome.resolve(lower.substring(0, 2)).resolve(lower.substring(2));
    }

    /**
     * Extracts the primary key fingerprint as a hex string from a public key ring.
     */
    private static String fingerprintHex(PGPPublicKeyRing ring) {
        return bytesToHex(ring.getPublicKey().getFingerprint());
    }

    /**
     * Extracts the primary key fingerprint as a hex string from a secret key ring.
     */
    private static String fingerprintHex(PGPSecretKeyRing ring) {
        return bytesToHex(ring.getPublicKey().getFingerprint());
    }

    /**
     * Converts a byte array to an uppercase hex string.
     */
    static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
