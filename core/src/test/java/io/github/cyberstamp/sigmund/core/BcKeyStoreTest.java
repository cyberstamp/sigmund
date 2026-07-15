package io.github.cyberstamp.sigmund.core;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPApi;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

class BcKeyStoreTest {

    @Test
    void findPublicKeyFromCertD(@TempDir Path tempDir) throws Exception {
        Path certD = tempDir.resolve("cert-d");
        Path bcPrivate = tempDir.resolve("bc-private");
        BcKeyStore store = new BcKeyStore(null, certD, bcPrivate);

        OpenPGPKey key = generateEd25519Key("Test <test@example.com>");
        PGPPublicKeyRing pubRing = key.toCertificate().getPGPPublicKeyRing();
        store.storeCert(pubRing);

        String fingerprint = BcKeyStore.bytesToHex(key.getFingerprint());
        PGPPublicKeyRing found = store.findPublicKey(fingerprint);
        assertNotNull(found);
    }

    @Test
    void findPublicKeyNotFound(@TempDir Path tempDir) throws Exception {
        Path certD = tempDir.resolve("cert-d");
        Path bcPrivate = tempDir.resolve("bc-private");
        BcKeyStore store = new BcKeyStore(null, certD, bcPrivate);

        assertNull(store.findPublicKey("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    }

    @Test
    void storeAndFindSecretKey(@TempDir Path tempDir) throws Exception {
        Path certD = tempDir.resolve("cert-d");
        Path bcPrivate = tempDir.resolve("bc-private");
        BcKeyStore store = new BcKeyStore(null, certD, bcPrivate);

        OpenPGPKey key = generateEd25519Key("Test <test@example.com>");
        PGPSecretKeyRing secretRing = key.getPGPSecretKeyRing();
        store.storeSecretKey(secretRing);

        String fingerprint = BcKeyStore.bytesToHex(key.getFingerprint());
        assertNotNull(store.findSecretKey(fingerprint));
    }

    @Test
    void findPrimaryUserId(@TempDir Path tempDir) throws Exception {
        Path certD = tempDir.resolve("cert-d");
        Path bcPrivate = tempDir.resolve("bc-private");
        BcKeyStore store = new BcKeyStore(null, certD, bcPrivate);

        OpenPGPKey key = generateEd25519Key("Alice <alice@example.com>");
        PGPPublicKeyRing pubRing = key.toCertificate().getPGPPublicKeyRing();
        store.storeCert(pubRing);

        String fingerprint = BcKeyStore.bytesToHex(key.getFingerprint());
        String uid = store.findPrimaryUserId(fingerprint);
        assertNotNull(uid);
        assertTrue(uid.contains("alice@example.com"));
    }

    /**
     * Verifies that a key cached via {@link BcKeyStore#cacheEphemeral(PGPPublicKeyRing)}
     * is returned by {@link BcKeyStore#findPublicKey(String)}, making it available for
     * verification without being written to disk.
     */
    @Test
    void cacheEphemeralMakesKeyFindable(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));

        OpenPGPKey key = generateEd25519Key("Ephemeral <ephemeral@example.com>");
        PGPPublicKeyRing pubRing = key.toCertificate().getPGPPublicKeyRing();
        store.cacheEphemeral(pubRing);

        String fingerprint = BcKeyStore.bytesToHex(key.getFingerprint());
        assertNotNull(store.findPublicKey(fingerprint));
    }

    /**
     * Verifies that {@link BcKeyStore#cacheEphemeral(PGPPublicKeyRing)} does not write
     * any files to the cert-d directory. The key exists only in memory.
     */
    @Test
    void ephemeralKeyNotPersistedToDisk(@TempDir Path tempDir) throws Exception {
        Path certD = tempDir.resolve("cert-d");
        BcKeyStore store = new BcKeyStore(null, certD, tempDir.resolve("bc-private"));

        OpenPGPKey key = generateEd25519Key("NoDisk <nodisk@example.com>");
        PGPPublicKeyRing pubRing = key.toCertificate().getPGPPublicKeyRing();
        store.cacheEphemeral(pubRing);

        assertFalse(Files.exists(certD), "cert-d directory should not be created for ephemeral keys");
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void secretKeyFileHasOwnerOnlyPermissions(@TempDir Path tempDir) throws Exception {
        Path certD = tempDir.resolve("cert-d");
        Path bcPrivate = tempDir.resolve("bc-private");
        BcKeyStore store = new BcKeyStore(null, certD, bcPrivate);

        OpenPGPKey key = generateEd25519Key("Perm <perm@example.com>");
        store.storeSecretKey(key.getPGPSecretKeyRing());

        String fp = BcKeyStore.bytesToHex(key.getFingerprint()).toLowerCase();
        Path keyFile = bcPrivate.resolve(fp.substring(0, 2)).resolve(fp.substring(2));
        assertTrue(Files.exists(keyFile));

        Set<PosixFilePermission> perms = Files.getPosixFilePermissions(keyFile);
        assertEquals(Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE), perms);
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void certFileDoesNotGetRestrictedPermissions(@TempDir Path tempDir) throws Exception {
        Path certD = tempDir.resolve("cert-d");
        Path bcPrivate = tempDir.resolve("bc-private");
        BcKeyStore store = new BcKeyStore(null, certD, bcPrivate);

        OpenPGPKey key = generateEd25519Key("Cert <cert@example.com>");
        store.storeCert(key.toCertificate().getPGPPublicKeyRing());

        String fp = BcKeyStore.bytesToHex(key.getFingerprint()).toLowerCase();
        Path certFile = certD.resolve(fp.substring(0, 2)).resolve(fp.substring(2));
        assertTrue(Files.exists(certFile));

        Set<PosixFilePermission> perms = Files.getPosixFilePermissions(certFile);
        assertTrue(perms.contains(PosixFilePermission.OWNER_READ));
        // cert files should keep default permissions (not restricted to owner-only)
        assertTrue(perms.size() > 2, "Cert file should have broader permissions than owner-only");
    }

    // Helper: Generate Ed25519 key using BC 1.85's high-level API
    private OpenPGPKey generateEd25519Key(String userId) throws Exception {
        BcOpenPGPApi api = new BcOpenPGPApi();
        return api.generateKey().ed25519x25519Key(userId).build();
    }
}
