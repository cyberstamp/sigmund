package dev.cyberstamp.sigmund.core;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;

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

    /** A key a certificate holds as a subkey without a binding signature its primary key made. */
    private static final int HELD = 0;
    /** A subkey with a binding signature its primary key made, but no back signature. */
    private static final int BOUND = 1;
    /** A subkey bound by its primary key and cross-certified by a back signature it made. */
    private static final int CROSS_CERTIFIED = 2;
    /** A certificate's own primary key. */
    private static final int AS_PRIMARY = 3;

    private final Path gnupgHome;
    private final Path certDHome;
    private final Path bcPrivateHome;
    private final Map<String, PGPPublicKeyRing> ephemeralKeys = new ConcurrentHashMap<>();
    private final Map<String, TrustRootRef> fetchedFrom = new ConcurrentHashMap<>();
    private final Map<String, Map<String, PGPPublicKeyRing>> servedCopies = new ConcurrentHashMap<>();
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
        TrustRootRef keyservers = fetchedFromSource(ring);
        return new KeyLookup(keyservers != null ? keyservers : store, ring);
    }

    /**
     * Names the keyservers a fetched key came from, as {@link #addFetched} recorded them, or
     * {@code null} for a key that was not fetched this session. Every key held in memory was
     * fetched, so a key found there always has its keyservers recorded.
     */
    private TrustRootRef fetchedFromSource(PGPPublicKeyRing ring) {
        return fetchedFrom.get(fingerprintHex(ring));
    }

    /**
     * Adds a key fetched from keyservers, recording the keyservers it came from and keeping
     * each server's copy.
     *
     * <p>
     * A keyserver may serve several certificates for one key, and a keyserver that accepts
     * anyone's uploads may serve a certificate of another primary key that holds the key asked
     * for as a subkey. Every certificate served that holds the key is considered, grouped by its
     * primary key, and one group is kept: the one whose primary key is the key asked for; for a
     * subkey, the one that binds it with a binding signature its primary key made and a back
     * signature the subkey made, else one whose primary key made a binding signature for it;
     * when that leaves a choice — a 64-bit key ID two primary keys end with — the group served
     * first. The other certificates are set aside: neither joined nor kept. So a certificate
     * served first can never decide which primary key the asked key belongs to, as only the key's
     * holder can make the signatures that bind it.
     *
     * <p>
     * The kept copies are joined with {@link PGPPublicKeyRing#join} into a single certificate, so
     * a user ID, a signature or a revocation any one server held is in it, together with a copy of
     * the same certificate a local store already holds, so that a revocation held only locally is
     * never hidden by the fetch. The joined certificate is stored once and found as it always was,
     * and its source names every server whose copy was joined, in the order given. Each kept copy
     * stays available for the rest of the session to {@link #userIdsServedBy} and
     * {@link #revocationServedBy}, so a later check can tell which server served what.
     *
     * <p>
     * Unless the store persists fetched keys, the joined certificate is kept in memory:
     * available for verification for the rest of this session, but never written to the cert-d
     * directory, so fetching a key to check one build does not silently grow the machine's trust
     * surface. A persisted certificate is written to cert-d; the copies are kept in memory
     * either way.
     *
     * @param keyId the fingerprint of the primary key or a subkey, or the 64-bit key ID, that
     *        was asked for
     * @param served the certificates each keyserver served, by keyserver URL, in the order the
     *        keyservers are configured; at least one must hold the key asked for
     */
    void addFetched(String keyId, Map<String, List<PGPPublicKeyRing>> served) {
        Map<String, PGPPublicKeyRing> kept = copiesOfAskedCertificate(keyId, served);
        PGPPublicKeyRing joined = withLocalCopy(join(kept.values()));
        String fingerprint = fingerprintHex(joined);
        if (persistFetched) {
            storeCert(joined);
        } else {
            ephemeralKeys.put(fingerprint, joined);
        }
        fetchedFrom.put(fingerprint, TrustRootRef.keyservers(List.copyOf(kept.keySet())));
        servedCopies.put(fingerprint, kept);
    }

    private static Map<String, PGPPublicKeyRing> copiesOfAskedCertificate(String keyId,
            Map<String, List<PGPPublicKeyRing>> served) {
        Map<String, List<PGPPublicKeyRing>> chosen = bestServedGroup(keyId, groupedByPrimary(keyId, served));
        if (chosen == null) {
            throw new IllegalArgumentException("no copy holds " + keyId);
        }
        Map<String, PGPPublicKeyRing> kept = new LinkedHashMap<>(chosen.size());
        chosen.forEach((keyserver, copies) -> kept.put(keyserver, join(copies)));
        return kept;
    }

    /**
     * The certificate of a key among those one keyserver served, chosen as
     * {@link #addFetched(String, Map)} chooses among every server's, with that server's copies of
     * it joined.
     *
     * @param keyId the fingerprint of the primary key or a subkey, or the 64-bit key ID, that
     *        was asked for
     * @param served the certificates the keyserver served, in the order served
     * @return the certificate, or {@code null} when none of them holds the key
     */
    static PGPPublicKeyRing certificateAmong(String keyId, List<PGPPublicKeyRing> served) {
        Map<String, List<PGPPublicKeyRing>> group = bestServedGroup(keyId,
                groupedByPrimary(keyId, Map.of(keyId, served)));
        return group == null ? null : join(group.get(keyId));
    }

    private static Map<String, Map<String, List<PGPPublicKeyRing>>> groupedByPrimary(String keyId,
            Map<String, List<PGPPublicKeyRing>> served) {
        Map<String, Map<String, List<PGPPublicKeyRing>>> groups = new LinkedHashMap<>();
        served.forEach((keyserver, copies) -> copies.stream()
                .filter(copy -> matchesFingerprint(copy, keyId))
                .forEach(copy -> groups.computeIfAbsent(fingerprintHex(copy), primary -> new LinkedHashMap<>())
                        .computeIfAbsent(keyserver, server -> new ArrayList<>())
                        .add(copy)));
        return groups;
    }

    private static Map<String, List<PGPPublicKeyRing>> bestServedGroup(String keyId,
            Map<String, Map<String, List<PGPPublicKeyRing>>> groups) {
        Map<String, List<PGPPublicKeyRing>> best = null;
        int bestStanding = -1;
        for (Map<String, List<PGPPublicKeyRing>> group : groups.values()) {
            int standing = standing(group.values().stream().flatMap(List::stream).toList(), keyId);
            if (standing > bestStanding) {
                best = group;
                bestStanding = standing;
            }
        }
        return best;
    }

    /**
     * Joins the copy of the certificate a local store holds, if any, into the fetched one: a key
     * found in a local store without user IDs is fetched again, and what that copy held must not
     * be lost when the fetched certificate is found first or replaces it in cert-d.
     */
    private PGPPublicKeyRing withLocalCopy(PGPPublicKeyRing fetched) {
        KeyLookup local = findInStores(fingerprintHex(fetched), new ArrayList<>());
        if (local == null || !Arrays.equals(local.ring().getPublicKey().getFingerprint(),
                fetched.getPublicKey().getFingerprint())) {
            return fetched;
        }
        return join(List.of(fetched, local.ring()));
    }

    /**
     * Joins copies of one certificate, in order.
     *
     * <p>
     * A signature the certificate joined so far already holds is removed from the next copy
     * before {@link PGPPublicKeyRing#join} sees it: Bouncy Castle 1.86 rebuilds a signature it
     * finds in both from the signature's integers, which a native Ed25519 or Ed448 signature
     * (RFC 9580 algorithms 27 and 28) does not have, and the certificate it returns can then be
     * neither encoded nor verified.
     *
     * <p>
     * Copies that cannot be joined fail the fetch of that key, so a claim it signed is
     * {@code INDETERMINATE}: leaving a copy out instead could leave out a revocation only that
     * copy carries.
     *
     * @throws IllegalStateException if Bouncy Castle cannot join the copies
     */
    private static PGPPublicKeyRing join(Iterable<PGPPublicKeyRing> copies) {
        Iterator<PGPPublicKeyRing> iterator = copies.iterator();
        PGPPublicKeyRing joined = iterator.next();
        while (iterator.hasNext()) {
            joined = join(joined, iterator.next());
        }
        return joined;
    }

    private static PGPPublicKeyRing join(PGPPublicKeyRing joined, PGPPublicKeyRing copy) {
        try {
            return PGPPublicKeyRing.join(joined, withoutSignaturesIn(copy, joined));
        } catch (PGPException e) {
            throw new IllegalStateException("copies of " + fingerprintHex(joined) + " cannot be joined", e);
        }
    }

    /** The copy without the signatures {@code held} already holds on the same key. */
    private static PGPPublicKeyRing withoutSignaturesIn(PGPPublicKeyRing copy, PGPPublicKeyRing held) {
        List<PGPPublicKey> keys = new ArrayList<>();
        Iterator<PGPPublicKey> copyKeys = copy.getPublicKeys();
        while (copyKeys.hasNext()) {
            PGPPublicKey key = copyKeys.next();
            PGPPublicKey heldKey = held.getPublicKey(key.getFingerprint());
            keys.add(heldKey == null ? key : withoutSignaturesOf(key, heldKey));
        }
        return new PGPPublicKeyRing(keys);
    }

    private static PGPPublicKey withoutSignaturesOf(PGPPublicKey key, PGPPublicKey heldKey) {
        List<PGPSignature> signatures = new ArrayList<>();
        key.getSignatures().forEachRemaining(signatures::add);
        PGPPublicKey stripped = key;
        for (PGPSignature signature : signatures) {
            if (holdsSignature(heldKey, signature)) {
                PGPPublicKey without = PGPPublicKey.removeCertification(stripped, signature);
                stripped = without != null ? without : stripped;
            }
        }
        return stripped;
    }

    private static boolean holdsSignature(PGPPublicKey key, PGPSignature wanted) {
        Iterator<PGPSignature> signatures = key.getSignatures();
        while (signatures.hasNext()) {
            if (sameSignature(signatures.next(), wanted)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Whether two signatures are one: the same type and signature value, which covers all they
     * sign, whatever unhashed subpackets a server added.
     */
    private static boolean sameSignature(PGPSignature one, PGPSignature other) {
        try {
            return one.getSignatureType() == other.getSignatureType()
                    && PGPSignature.isSignatureEncodingEqual(one, other);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * How firmly a set of copies of one certificate holds a key, so that of several
     * certificates holding it the one its holder bound it to is chosen: {@link #AS_PRIMARY} when
     * the key is their primary key, {@link #CROSS_CERTIFIED} when a binding signature the primary
     * key made carries a back signature the subkey made, {@link #BOUND} when the primary key made
     * a binding signature but the subkey made none, and {@link #HELD} otherwise.
     */
    private static int standing(List<PGPPublicKeyRing> copies, String keyId) {
        int standing = HELD;
        for (PGPPublicKeyRing copy : copies) {
            standing = Math.max(standing, standingIn(copy, keyId));
        }
        return standing;
    }

    private static int standingIn(PGPPublicKeyRing copy, String keyId) {
        PGPPublicKey primary = copy.getPublicKey();
        if (sameKey(KeyRingFiles.hex(primary.getFingerprint()), keyId)) {
            return AS_PRIMARY;
        }
        int standing = HELD;
        Iterator<PGPPublicKey> keys = copy.getPublicKeys();
        while (keys.hasNext()) {
            PGPPublicKey key = keys.next();
            if (!key.isMasterKey() && sameKey(KeyRingFiles.hex(key.getFingerprint()), keyId)) {
                standing = Math.max(standing, bindingStanding(key, primary));
            }
        }
        return standing;
    }

    private static int bindingStanding(PGPPublicKey subkey, PGPPublicKey primary) {
        int standing = HELD;
        Iterator<PGPSignature> bindings = subkey.getSignaturesOfType(PGPSignature.SUBKEY_BINDING);
        while (bindings.hasNext()) {
            PGPSignature binding = bindings.next();
            if (verifiesBinding(binding, primary, primary, subkey)) {
                if (hasBackSignature(binding, primary, subkey)) {
                    return CROSS_CERTIFIED;
                }
                standing = BOUND;
            }
        }
        return standing;
    }

    private static boolean hasBackSignature(PGPSignature binding, PGPPublicKey primary, PGPPublicKey subkey) {
        List<PGPSignature> embedded = new ArrayList<>();
        try {
            for (PGPSignatureSubpacketVector area : List.of(binding.getHashedSubPackets(),
                    binding.getUnhashedSubPackets())) {
                area.getEmbeddedSignatures().forEach(embedded::add);
            }
        } catch (PGPException | RuntimeException e) {
            return false;
        }
        return embedded.stream().anyMatch(signature -> signature.getSignatureType() == PGPSignature.PRIMARYKEY_BINDING
                && verifiesBinding(signature, subkey, primary, subkey));
    }

    private static boolean verifiesBinding(PGPSignature signature, PGPPublicKey signer, PGPPublicKey primary,
            PGPPublicKey subkey) {
        try {
            signature.init(new BcPGPContentVerifierBuilderProvider(), signer);
            return signature.verifyCertification(primary, subkey);
        } catch (PGPException | RuntimeException e) {
            return false;
        }
    }

    /**
     * Of the entries of a map by primary fingerprint, the one for the certificate that holds a
     * key most firmly: the entry stored under the key's own fingerprint, else the one whose
     * copies hold it most firmly (see {@link #standing}), the lowest primary fingerprint among
     * equals, so that the answer does not depend on the order entries were added in.
     *
     * @return the entry's value, or {@code null} when no entry holds the key
     */
    private static <T> T holderOf(String fingerprint, Map<String, T> byPrimary,
            Function<T, List<PGPPublicKeyRing>> copiesOf) {
        T direct = byPrimary.get(fingerprint.toUpperCase());
        if (direct != null) {
            return direct;
        }
        T best = null;
        int bestStanding = -1;
        for (String primary : new TreeSet<>(byPrimary.keySet())) {
            List<PGPPublicKeyRing> copies = copiesOf.apply(byPrimary.get(primary));
            if (copies.stream().anyMatch(copy -> matchesFingerprint(copy, fingerprint))) {
                int standing = standing(copies, fingerprint);
                if (standing > bestStanding) {
                    best = byPrimary.get(primary);
                    bestStanding = standing;
                }
            }
        }
        return best;
    }

    /**
     * Returns the user IDs a keyserver served for a certificate this session.
     *
     * <p>
     * The user IDs of the certificate as that one server served it, decoded as UTF-8 with
     * invalid bytes replaced — not those of the joined certificate, which may hold more. Empty
     * when that server served none, did not serve this certificate, its copy does not hold the
     * fingerprint asked about, or the certificate came from a local store.
     *
     * @param fingerprint the fingerprint of the certificate's primary key or a subkey
     * @param keyserver the keyserver URL
     * @return the user IDs, in the order the copy holds them
     */
    List<String> userIdsServedBy(String fingerprint, String keyserver) {
        PGPPublicKeyRing copy = servedCopy(fingerprint, keyserver);
        if (copy == null || !matchesFingerprint(copy, fingerprint)) {
            return List.of();
        }
        List<String> userIds = new ArrayList<>();
        copy.getPublicKey().getRawUserIDs().forEachRemaining(
                raw -> userIds.add(new String(raw, StandardCharsets.UTF_8)));
        return userIds;
    }

    /**
     * Returns the keyservers whose copy of a certificate carried a revocation.
     *
     * <p>
     * The signature is compared by its signature value, which covers everything it signs, so a
     * revocation parsed anew from the joined certificate matches the one in a server's copy, and
     * so does a copy to whose unhashed area a server added subpackets, which joining the copies
     * merges. A revocation of the primary key or of a subkey is found alike.
     *
     * @param fingerprint the fingerprint of the certificate's primary key or a subkey
     * @param revocation the revocation signature
     * @return the keyserver URLs, in the order the copies were given; empty when none carried it
     */
    List<String> revocationServedBy(String fingerprint, PGPSignature revocation) {
        return servedCopiesOf(fingerprint).entrySet().stream()
                .filter(copy -> carries(copy.getValue(), revocation))
                .map(Map.Entry::getKey)
                .toList();
    }

    /**
     * Returns the keyservers that served a copy of a key this session.
     *
     * <p>
     * Only servers whose copy holds the key are named: a server whose copy of the certificate
     * lacks the subkey asked about did not serve that key.
     *
     * @param fingerprint the fingerprint of the certificate's primary key or a subkey
     * @return the keyserver URLs, in the order the copies were given; empty when the
     *         certificate came from a local store
     */
    List<String> keyserversServing(String fingerprint) {
        return servedCopiesOf(fingerprint).entrySet().stream()
                .filter(copy -> matchesFingerprint(copy.getValue(), fingerprint))
                .map(Map.Entry::getKey)
                .toList();
    }

    private PGPPublicKeyRing servedCopy(String fingerprint, String keyserver) {
        return servedCopiesOf(fingerprint).get(keyserver);
    }

    /**
     * The copies kept for the certificate that holds a key, chosen as {@link #holderOf} does
     * when certificates fetched for other keys hold it too.
     */
    private Map<String, PGPPublicKeyRing> servedCopiesOf(String fingerprint) {
        Map<String, PGPPublicKeyRing> copies = holderOf(fingerprint, servedCopies,
                served -> List.copyOf(served.values()));
        return copies == null ? Map.of() : copies;
    }

    private static boolean carries(PGPPublicKeyRing copy, PGPSignature wanted) {
        Iterator<PGPPublicKey> keys = copy.getPublicKeys();
        while (keys.hasNext()) {
            if (holdsSignature(keys.next(), wanted)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Searches the in-memory ephemeral cache for a key matching the given fingerprint: the
     * certificate of that primary key, else the one that binds it as a subkey most firmly.
     */
    private PGPPublicKeyRing findInEphemeral(String fingerprint) {
        return holderOf(fingerprint, ephemeralKeys, List::of);
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
        Iterator<PGPPublicKey> keys = ring.getPublicKeys();
        while (keys.hasNext()) {
            if (sameKey(KeyRingFiles.hex(keys.next().getFingerprint()), fingerprint)) {
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
     *
     * <p>
     * The key ring is encoded in full before any file is touched, then written to a temporary
     * file beside the target and moved over it, atomically where the file system can: a key ring
     * that cannot be encoded, or a write that fails, leaves the file the store held as it was.
     */
    private void writeKeyRing(Path file, org.bouncycastle.openpgp.PGPKeyRing keyRing) {
        try {
            byte[] encoded = keyRing.getEncoded();
            Files.createDirectories(file.getParent());
            Path temporary = temporaryFileBeside(file, bcPrivateHome != null && file.startsWith(bcPrivateHome));
            try {
                Files.write(temporary, encoded);
                replace(temporary, file);
            } finally {
                Files.deleteIfExists(temporary);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to write key to " + file, e);
        }
    }

    /**
     * A new, empty file in the directory of {@code file}, which the written key ring is moved
     * from, so that a store another tool shares never holds a partly written certificate. A
     * secret key's file is readable by its owner only from the start; a certificate's gets the
     * default permissions.
     */
    private static Path temporaryFileBeside(Path file, boolean secret) throws IOException {
        Path temporary = file.resolveSibling("." + file.getFileName() + "." + System.nanoTime() + ".tmp");
        if (secret) {
            try {
                return Files.createFile(temporary, OWNER_ONLY_ATTR);
            } catch (UnsupportedOperationException e) {
                // non-POSIX filesystem — fall through to default permissions
            }
        }
        return Files.createFile(temporary);
    }

    private static void replace(Path temporary, Path file) throws IOException {
        try {
            Files.move(temporary, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(temporary, file, StandardCopyOption.REPLACE_EXISTING);
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
        return KeyRingFiles.hex(ring.getPublicKey().getFingerprint());
    }

    /**
     * Extracts the primary key fingerprint as a hex string from a secret key ring.
     */
    private static String fingerprintHex(PGPSecretKeyRing ring) {
        return KeyRingFiles.hex(ring.getPublicKey().getFingerprint());
    }

}
