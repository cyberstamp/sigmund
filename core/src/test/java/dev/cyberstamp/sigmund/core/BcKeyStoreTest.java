package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.sig.RevocationReasonTags;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPApi;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
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
        PGPPublicKeyRing found = store.findPublicKey(fingerprint).ring();
        assertThat(found).isNotNull();
    }

    @Test
    void findPublicKeyNotFound(@TempDir Path tempDir) throws Exception {
        Path certD = tempDir.resolve("cert-d");
        Path bcPrivate = tempDir.resolve("bc-private");
        BcKeyStore store = new BcKeyStore(null, certD, bcPrivate);

        assertThat(store.findPublicKey("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).isNull();
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
        assertThat(store.findSecretKey(fingerprint)).isNotNull();
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
        assertThat(uid).isNotNull();
        assertThat(uid.contains("alice@example.com")).isTrue();
    }

    /**
     * Verifies that a key added via {@link BcKeyStore#addFetched(Map)}
     * is returned by {@link BcKeyStore#findPublicKey(String)} with the keyserver it came from.
     */
    @Test
    void fetchedKeyIsFindableWithItsKeyserver(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));

        OpenPGPKey key = generateEd25519Key("Ephemeral <ephemeral@example.com>");
        PGPPublicKeyRing pubRing = key.toCertificate().getPGPPublicKeyRing();
        store.addFetched(Map.of("hkps://keys.example.org", pubRing));

        String fingerprint = BcKeyStore.bytesToHex(key.getFingerprint());
        assertThat(store.findPublicKey(fingerprint).source())
                .isEqualTo(TrustRootRef.keyserver("hkps://keys.example.org"));
    }

    @Test
    void persistingStoreWritesFetchedKeysToCertDAndStillNamesTheKeyserver(@TempDir Path tempDir)
            throws Exception {
        Path certD = tempDir.resolve("cert-d");
        BcKeyStore store = new BcKeyStore(null, certD, tempDir.resolve("bc-private"), true);

        OpenPGPKey key = generateEd25519Key("Persisted <persisted@example.com>");
        store.addFetched(Map.of("hkps://keys.example.org", key.toCertificate().getPGPPublicKeyRing()));

        String fingerprint = BcKeyStore.bytesToHex(key.getFingerprint());
        assertThat(Files.isDirectory(certD)).isTrue();
        BcKeyStore laterSession = new BcKeyStore(null, certD, tempDir.resolve("bc-private"));
        assertThat(laterSession.findPublicKey(fingerprint).source())
                .isEqualTo(TrustRootRef.certD(certD));
        assertThat(store.findPublicKey(fingerprint).source())
                .isEqualTo(TrustRootRef.keyserver("hkps://keys.example.org"));
    }

    @Test
    void inspectionAnswersPerStore(@TempDir Path tempDir) throws Exception {
        Path certD = tempDir.resolve("cert-d");
        BcKeyStore store = new BcKeyStore(null, certD, tempDir.resolve("bc-private"));
        OpenPGPKey stored = generateEd25519Key("Stored <stored@example.com>");
        store.storeCert(stored.toCertificate().getPGPPublicKeyRing());
        OpenPGPKey fetched = generateEd25519Key("Fetched <fetched@example.com>");
        store.addFetched(Map.of("hkps://keys.example.org", fetched.toCertificate().getPGPPublicKeyRing()));

        List<BcKeyStore.KeyLookup> byFingerprint = store.inspect(BcKeyStore.bytesToHex(fetched.getFingerprint()), null);
        assertThat(byFingerprint).extracting(BcKeyStore.KeyLookup::source)
                .containsExactly(TrustRootRef.certD(certD), TrustRootRef.keyserver("hkps://keys.example.org"));
        assertThat(byFingerprint.get(0).ring()).isNull();
        assertThat(byFingerprint.get(1).ring()).isNotNull();

        List<BcKeyStore.KeyLookup> byEmail = store.inspect(null, "Stored@Example.com");
        assertThat(byEmail).extracting(BcKeyStore.KeyLookup::source).containsExactly(TrustRootRef.certD(certD));
        assertThat(byEmail.get(0).ring()).isNotNull();

        assertThat(store.inspect(null, null)).isEmpty();
    }

    /**
     * Verifies that {@link BcKeyStore#addFetched(Map)} does not write
     * any files to the cert-d directory. The key exists only in memory.
     */
    @Test
    void fetchedKeyNotPersistedByDefault(@TempDir Path tempDir) throws Exception {
        Path certD = tempDir.resolve("cert-d");
        BcKeyStore store = new BcKeyStore(null, certD, tempDir.resolve("bc-private"));

        OpenPGPKey key = generateEd25519Key("NoDisk <nodisk@example.com>");
        PGPPublicKeyRing pubRing = key.toCertificate().getPGPPublicKeyRing();
        store.addFetched(Map.of("hkps://keys.example.org", pubRing));

        assertThat(Files.exists(certD)).as("cert-d directory should not be created for ephemeral keys").isFalse();
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
        assertThat(Files.exists(keyFile)).isTrue();

        Set<PosixFilePermission> perms = Files.getPosixFilePermissions(keyFile);
        assertThat(perms).isEqualTo(Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
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
        assertThat(Files.exists(certFile)).isTrue();

        Set<PosixFilePermission> perms = Files.getPosixFilePermissions(certFile);
        assertThat(perms.contains(PosixFilePermission.OWNER_READ)).isTrue();
        // cert files should keep default permissions (not restricted to owner-only)
        assertThat(perms.size() > 2).as("Cert file should have broader permissions than owner-only").isTrue();
    }

    // Helper: Generate Ed25519 key using BC 1.85's high-level API
    @Test
    void userIdsServedByNamesEachServersCopy(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        PGPPublicKeyRing full = generateEd25519Key("Alice Example <alice@example.org>")
                .toCertificate().getPGPPublicKeyRing();
        String fingerprint = BcKeyStore.bytesToHex(full.getPublicKey().getFingerprint());
        Map<String, PGPPublicKeyRing> copies = new LinkedHashMap<>();
        copies.put("hkps://server1", withoutUserIds(full));
        copies.put("hkps://server2", full);
        store.addFetched(copies);

        assertThat(store.userIdsServedBy(fingerprint, "hkps://server1")).isEmpty();
        assertThat(store.userIdsServedBy(fingerprint, "hkps://server2"))
                .containsExactly("Alice Example <alice@example.org>");
        assertThat(store.userIdsServedBy(fingerprint, "hkps://server3")).isEmpty();
    }

    @Test
    void aSubkeyFingerprintFindsTheCopy(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        PGPPublicKeyRing full = generateEd25519Key("Alice Example <alice@example.org>")
                .toCertificate().getPGPPublicKeyRing();
        store.addFetched(Map.of("hkps://server1", full));
        Iterator<PGPPublicKey> keys = full.getPublicKeys();
        keys.next();
        String subkeyFingerprint = BcKeyStore.bytesToHex(keys.next().getFingerprint());

        assertThat(store.userIdsServedBy(subkeyFingerprint, "hkps://server1"))
                .containsExactly("Alice Example <alice@example.org>");
    }

    @Test
    void aSubkeyOnlyTheLaterCopyHoldsFindsThatCopy(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        PGPPublicKeyRing full = generateEd25519Key("Alice Example <alice@example.org>")
                .toCertificate().getPGPPublicKeyRing();
        PGPPublicKeyRing primaryOnly = new PGPPublicKeyRing(List.of(full.getPublicKey()));
        Iterator<PGPPublicKey> keys = full.getPublicKeys();
        keys.next();
        String subkeyFingerprint = BcKeyStore.bytesToHex(keys.next().getFingerprint());
        Map<String, PGPPublicKeyRing> copies = new LinkedHashMap<>();
        copies.put("hkps://server1", primaryOnly);
        copies.put("hkps://server2", full);
        store.addFetched(copies);

        assertThat(store.userIdsServedBy(subkeyFingerprint, "hkps://server2"))
                .containsExactly("Alice Example <alice@example.org>");
    }

    @Test
    void revocationServedByComparesEncoding(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        OpenPGPKey key = generateEd25519Key("Alice Example <alice@example.org>");
        PGPPublicKeyRing full = key.toCertificate().getPGPPublicKeyRing();
        PGPSignature revocation = revocationOf(key);
        PGPPublicKeyRing revoked = new PGPPublicKeyRing(List.of(
                PGPPublicKey.addCertification(full.getPublicKey(), revocation)));
        Map<String, PGPPublicKeyRing> copies = new LinkedHashMap<>();
        copies.put("hkps://server1", full);
        copies.put("hkps://server2", revoked);
        store.addFetched(copies);
        String fingerprint = BcKeyStore.bytesToHex(full.getPublicKey().getFingerprint());

        PGPSignature reparsed = new PGPSignature(new BCPGInputStream(new ByteArrayInputStream(revocation.getEncoded())));
        assertThat(store.revocationServedBy(fingerprint, reparsed)).containsExactly("hkps://server2");
        assertThat(store.revocationServedBy(fingerprint, revocationOf(key, 1))).isEmpty();
    }

    @Test
    void nothingIsServedForAKeyFromALocalStore(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        PGPPublicKeyRing local = generateEd25519Key("Alice Example <alice@example.org>")
                .toCertificate().getPGPPublicKeyRing();
        store.storeCert(local);
        String fingerprint = BcKeyStore.bytesToHex(local.getPublicKey().getFingerprint());

        assertThat(store.userIdsServedBy(fingerprint, "hkps://server1")).isEmpty();
    }

    private static PGPPublicKeyRing withoutUserIds(PGPPublicKeyRing ring) {
        List<PGPPublicKey> keys = new ArrayList<>();
        ring.getPublicKeys().forEachRemaining(keys::add);
        PGPPublicKey primary = keys.get(0);
        Iterator<String> uids = primary.getUserIDs();
        while (uids.hasNext()) {
            primary = PGPPublicKey.removeCertification(primary, uids.next());
        }
        keys.set(0, primary);
        return new PGPPublicKeyRing(keys);
    }

    private static PGPSignature revocationOf(OpenPGPKey key) throws Exception {
        return revocationOf(key, 0);
    }

    private static PGPSignature revocationOf(OpenPGPKey key, int secondsLater) throws Exception {
        PGPSecretKey signer = key.getPGPSecretKeyRing().getSecretKey();
        PGPSignatureGenerator generator = new PGPSignatureGenerator(
                new BcPGPContentSignerBuilder(signer.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256),
                signer.getPublicKey());
        generator.init(PGPSignature.KEY_REVOCATION, signer.extractPrivateKey(null));
        PGPSignatureSubpacketGenerator hashed = new PGPSignatureSubpacketGenerator();
        hashed.setSignatureCreationTime(true, Date.from(Instant.parse("2026-01-01T00:00:00Z").plusSeconds(secondsLater)));
        hashed.setRevocationReason(true, RevocationReasonTags.KEY_COMPROMISED, "compromised");
        generator.setHashedSubpackets(hashed.generate());
        return generator.generateCertification(signer.getPublicKey());
    }

    private OpenPGPKey generateEd25519Key(String userId) throws Exception {
        BcOpenPGPApi api = new BcOpenPGPApi();
        return api.generateKey().ed25519x25519Key(userId).build();
    }
}
