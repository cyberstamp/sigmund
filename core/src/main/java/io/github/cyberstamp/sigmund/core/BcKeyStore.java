package io.github.cyberstamp.sigmund.core;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.bc.BcPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

/**
 * Manages key lookup across GnuPG pubring, shared cert-d, and BC's own private key store.
 *
 * <p>
 * Key sources are searched in order:
 * <ol>
 * <li>GnuPG pubring ({@code pubring.gpg}) — read-only</li>
 * <li>Shared cert-d directory — read/write for certs</li>
 * <li>BC-owned private key store — read/write for TSKs</li>
 * </ol>
 */
class BcKeyStore {

    private final Path gnupgHome;
    private final Path certDHome;
    private final Path bcPrivateHome;
    private final Map<String, PGPPublicKeyRing> ephemeralKeys = new ConcurrentHashMap<>();

    /**
     * Creates a new key store.
     *
     * @param gnupgHome the GnuPG home directory, or {@code null} to skip GnuPG lookup
     * @param certDHome the shared cert-d directory
     * @param bcPrivateHome the BC private key store directory
     */
    BcKeyStore(Path gnupgHome, Path certDHome, Path bcPrivateHome) {
        this.gnupgHome = gnupgHome;
        this.certDHome = certDHome;
        this.bcPrivateHome = bcPrivateHome;
    }

    /**
     * Searches all key sources for a public key matching the given fingerprint.
     *
     * @param fingerprint the uppercase hex fingerprint to search for
     * @return the matching public key ring, or {@code null} if not found
     */
    PGPPublicKeyRing findPublicKey(String fingerprint) {
        PGPPublicKeyRing key = findInGnupgPubring(fingerprint);
        if (key != null) {
            return key;
        }
        key = findInCertD(fingerprint);
        if (key != null) {
            return key;
        }
        key = findInBcPrivate(fingerprint);
        if (key != null) {
            return key;
        }
        return findInEphemeral(fingerprint);
    }

    /**
     * Caches a public key ring in memory without writing to disk.
     * <p>
     * Used when {@link DiscoveryConfig#importToKeyring()} is {@code false} — the key
     * is available for verification during this session but is not persisted to the
     * cert-d directory.
     *
     * @param keyRing the public key ring to cache
     */
    void cacheEphemeral(PGPPublicKeyRing keyRing) {
        String fp = fingerprintHex(keyRing).toUpperCase();
        ephemeralKeys.put(fp, keyRing);
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
        PGPPublicKeyRing keyRing = findPublicKey(fingerprint);
        if (keyRing == null) {
            return null;
        }
        return extractPrimaryUserId(keyRing);
    }

    /**
     * Extracts the first user ID from a public key ring.
     */
    private String extractPrimaryUserId(PGPPublicKeyRing keyRing) {
        Iterator<String> uids = keyRing.getPublicKey().getUserIDs();
        return uids.hasNext() ? uids.next() : null;
    }

    /**
     * Searches GnuPG's pubring.gpg for a key matching the fingerprint.
     */
    private PGPPublicKeyRing findInGnupgPubring(String fingerprint) {
        if (gnupgHome == null) {
            return null;
        }
        Path pubringGpg = gnupgHome.resolve("pubring.gpg");
        if (!Files.isRegularFile(pubringGpg)) {
            return null;
        }
        return findInKeyRingCollection(pubringGpg, fingerprint);
    }

    /**
     * Searches a PGP keyring file for a key matching the fingerprint.
     */
    private PGPPublicKeyRing findInKeyRingCollection(Path keyringFile, String fingerprint) {
        try (InputStream in = new BufferedInputStream(Files.newInputStream(keyringFile));
                InputStream decoded = PGPUtil.getDecoderStream(in)) {
            PGPPublicKeyRingCollection collection = new BcPGPPublicKeyRingCollection(decoded);
            for (PGPPublicKeyRing ring : collection) {
                if (matchesFingerprint(ring, fingerprint)) {
                    return ring;
                }
            }
        } catch (IOException | PGPException e) {
            // pubring not readable — skip
        }
        return null;
    }

    /**
     * Searches the cert-d directory for a cert matching the fingerprint.
     */
    private PGPPublicKeyRing findInCertD(String fingerprint) {
        String lower = fingerprint.toLowerCase();
        if (lower.length() < 3) {
            return null;
        }
        Path certFile = certDFile(lower);
        if (Files.isRegularFile(certFile)) {
            return readPublicKeyRing(certFile);
        }
        return scanCertDForSubkey(fingerprint);
    }

    /**
     * Scans the cert-d directory for a cert where the fingerprint matches a subkey.
     */
    private PGPPublicKeyRing scanCertDForSubkey(String fingerprint) {
        if (!Files.isDirectory(certDHome)) {
            return null;
        }
        try (DirectoryStream<Path> dirs = Files.newDirectoryStream(certDHome, Files::isDirectory)) {
            for (Path dir : dirs) {
                try (DirectoryStream<Path> files = Files.newDirectoryStream(dir, Files::isRegularFile)) {
                    for (Path file : files) {
                        PGPPublicKeyRing ring = readPublicKeyRing(file);
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
    private boolean matchesFingerprint(PGPPublicKeyRing ring, String fingerprint) {
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
    private PGPPublicKeyRing readPublicKeyRing(Path file) {
        try (InputStream in = new BufferedInputStream(Files.newInputStream(file));
                InputStream decoded = PGPUtil.getDecoderStream(in)) {
            return new PGPPublicKeyRing(decoded, new BcKeyFingerprintCalculator());
        } catch (IOException e) {
            return null;
        } catch (Exception e) {
            // Catch any other exceptions from malformed key data
            return null;
        }
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

    /**
     * Writes a key ring to a file, creating parent directories as needed.
     */
    private void writeKeyRing(Path file, org.bouncycastle.openpgp.PGPKeyRing keyRing) {
        try {
            Files.createDirectories(file.getParent());
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
    private String fingerprintHex(PGPPublicKeyRing ring) {
        return bytesToHex(ring.getPublicKey().getFingerprint());
    }

    /**
     * Extracts the primary key fingerprint as a hex string from a secret key ring.
     */
    private String fingerprintHex(PGPSecretKeyRing ring) {
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
