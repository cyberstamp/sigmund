package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
import java.util.stream.Stream;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.PublicSubkeyPacket;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.RevocationReasonTags;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPApi;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
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

        String fingerprint = KeyRingFiles.hex(key.getFingerprint());
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

        String fingerprint = KeyRingFiles.hex(key.getFingerprint());
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

        String fingerprint = KeyRingFiles.hex(key.getFingerprint());
        String uid = store.findPrimaryUserId(fingerprint);
        assertThat(uid).isNotNull();
        assertThat(uid.contains("alice@example.com")).isTrue();
    }

    /**
     * Verifies that a key added via {@link BcKeyStore#addFetched(String, Map)}
     * is returned by {@link BcKeyStore#findPublicKey(String)} with the keyserver it came from.
     */
    @Test
    void fetchedKeyIsFindableWithItsKeyserver(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));

        OpenPGPKey key = generateEd25519Key("Ephemeral <ephemeral@example.com>");
        PGPPublicKeyRing pubRing = key.toCertificate().getPGPPublicKeyRing();
        BcTestKeys.addFetched(store, Map.of("hkps://keys.example.org", pubRing));

        String fingerprint = KeyRingFiles.hex(key.getFingerprint());
        assertThat(store.findPublicKey(fingerprint).source())
                .isEqualTo(TrustRootRef.keyserver("hkps://keys.example.org"));
    }

    @Test
    void persistingStoreWritesFetchedKeysToCertDAndStillNamesTheKeyserver(@TempDir Path tempDir)
            throws Exception {
        Path certD = tempDir.resolve("cert-d");
        BcKeyStore store = new BcKeyStore(null, certD, tempDir.resolve("bc-private"), true);

        OpenPGPKey key = generateEd25519Key("Persisted <persisted@example.com>");
        BcTestKeys.addFetched(store, Map.of("hkps://keys.example.org", key.toCertificate().getPGPPublicKeyRing()));

        String fingerprint = KeyRingFiles.hex(key.getFingerprint());
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
        BcTestKeys.addFetched(store, Map.of("hkps://keys.example.org", fetched.toCertificate().getPGPPublicKeyRing()));

        List<BcKeyStore.KeyLookup> byFingerprint = store.inspect(KeyRingFiles.hex(fetched.getFingerprint()), null);
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
     * Verifies that {@link BcKeyStore#addFetched(String, Map)} does not write
     * any files to the cert-d directory. The key exists only in memory.
     */
    @Test
    void fetchedKeyNotPersistedByDefault(@TempDir Path tempDir) throws Exception {
        Path certD = tempDir.resolve("cert-d");
        BcKeyStore store = new BcKeyStore(null, certD, tempDir.resolve("bc-private"));

        OpenPGPKey key = generateEd25519Key("NoDisk <nodisk@example.com>");
        PGPPublicKeyRing pubRing = key.toCertificate().getPGPPublicKeyRing();
        BcTestKeys.addFetched(store, Map.of("hkps://keys.example.org", pubRing));

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

        String fp = KeyRingFiles.hex(key.getFingerprint()).toLowerCase();
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

        String fp = KeyRingFiles.hex(key.getFingerprint()).toLowerCase();
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
        String fingerprint = KeyRingFiles.hex(full.getPublicKey().getFingerprint());
        Map<String, PGPPublicKeyRing> copies = new LinkedHashMap<>();
        copies.put("hkps://server1", withoutUserIds(full));
        copies.put("hkps://server2", full);
        BcTestKeys.addFetched(store, copies);

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
        BcTestKeys.addFetched(store, Map.of("hkps://server1", full));
        Iterator<PGPPublicKey> keys = full.getPublicKeys();
        keys.next();
        String subkeyFingerprint = KeyRingFiles.hex(keys.next().getFingerprint());

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
        String subkeyFingerprint = KeyRingFiles.hex(keys.next().getFingerprint());
        Map<String, PGPPublicKeyRing> copies = new LinkedHashMap<>();
        copies.put("hkps://server1", primaryOnly);
        copies.put("hkps://server2", full);
        BcTestKeys.addFetched(store, copies);

        assertThat(store.userIdsServedBy(subkeyFingerprint, "hkps://server2"))
                .containsExactly("Alice Example <alice@example.org>");
    }

    @Test
    void aServerWhoseCopyLacksTheSubkeyServesNoUserIdsForIt(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        PGPPublicKeyRing full = generateEd25519Key("Alice Example <alice@example.org>")
                .toCertificate().getPGPPublicKeyRing();
        PGPPublicKeyRing primaryOnly = new PGPPublicKeyRing(List.of(full.getPublicKey()));
        Iterator<PGPPublicKey> keys = full.getPublicKeys();
        keys.next();
        String subkeyFingerprint = KeyRingFiles.hex(keys.next().getFingerprint());
        Map<String, PGPPublicKeyRing> copies = new LinkedHashMap<>();
        copies.put("hkps://keys.openpgp.org", primaryOnly);
        copies.put("hkps://server2", full);
        BcTestKeys.addFetched(store, copies);

        assertThat(store.userIdsServedBy(subkeyFingerprint, "hkps://keys.openpgp.org")).isEmpty();
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
        BcTestKeys.addFetched(store, copies);
        String fingerprint = KeyRingFiles.hex(full.getPublicKey().getFingerprint());

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
        String fingerprint = KeyRingFiles.hex(local.getPublicKey().getFingerprint());

        assertThat(store.userIdsServedBy(fingerprint, "hkps://server1")).isEmpty();
    }

    /**
     * A keyserver that accepts anyone's uploads can serve, first, a certificate of another
     * primary key holding the asked key as a subkey; the certificate whose primary key is the one
     * asked for is the one kept, and the impostor is set aside.
     */
    @Test
    void anImpostorServedFirstIsSetAsideForTheCertificateOfTheAskedPrimary(@TempDir Path tempDir)
            throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        OpenPGPKey victim = generateV4Key("Alice Example <alice@example.org>");
        PGPPublicKeyRing real = victim.toCertificate().getPGPPublicKeyRing();
        String fingerprint = KeyRingFiles.hex(victim.getFingerprint());
        Map<String, List<PGPPublicKeyRing>> served = new LinkedHashMap<>();
        served.put("hkps://impostor.example.org", List.of(impostorHolding(real.getPublicKey())));
        served.put("hkps://real.example.org", List.of(real));
        store.addFetched(fingerprint, served);

        BcKeyStore.KeyLookup found = store.findPublicKey(fingerprint);
        assertThat(KeyRingFiles.hex(found.ring().getPublicKey().getFingerprint())).isEqualTo(fingerprint);
        assertThat(found.source()).isEqualTo(TrustRootRef.keyserver("hkps://real.example.org"));
        assertThat(store.keyserversServing(fingerprint)).containsExactly("hkps://real.example.org");
    }

    @Test
    void aSubkeyLookupKeepsTheCertificateThatBindsTheSubkey(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        PGPPublicKeyRing real = generateV4Key("Alice Example <alice@example.org>").toCertificate()
                .getPGPPublicKeyRing();
        PGPPublicKey subkey = signingSubkeyOf(real);
        String subkeyFingerprint = KeyRingFiles.hex(subkey.getFingerprint());
        Map<String, List<PGPPublicKeyRing>> served = new LinkedHashMap<>();
        served.put("hkps://impostor.example.org", List.of(impostorHolding(subkey)));
        served.put("hkps://real.example.org", List.of(real));
        store.addFetched(subkeyFingerprint, served);

        assertThat(store.findPublicKey(subkeyFingerprint).ring().getPublicKey().getFingerprint())
                .isEqualTo(real.getPublicKey().getFingerprint());
        assertThat(store.keyserversServing(subkeyFingerprint)).containsExactly("hkps://real.example.org");
    }

    @Test
    void everyCertificateAServerServedForTheKeyIsConsidered(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        OpenPGPKey victim = generateV4Key("Alice Example <alice@example.org>");
        PGPPublicKeyRing real = victim.toCertificate().getPGPPublicKeyRing();
        String fingerprint = KeyRingFiles.hex(victim.getFingerprint());
        store.addFetched(fingerprint, Map.of("hkps://keys.example.org",
                List.of(impostorHolding(real.getPublicKey()), real)));

        assertThat(store.findPublicKey(fingerprint).ring().getPublicKey().getFingerprint())
                .isEqualTo(real.getPublicKey().getFingerprint());
        assertThat(store.userIdsServedBy(fingerprint, "hkps://keys.example.org"))
                .containsExactly("Alice Example <alice@example.org>");
    }

    /**
     * Certificates fetched for other keys can hold a subkey too; what was served for that subkey
     * is answered from the certificate that binds it, whichever was fetched first.
     */
    @Test
    void aSubkeyHeldByCertificatesOfOtherKeysIsAnsweredFromTheOneThatBindsIt(@TempDir Path tempDir)
            throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        PGPPublicKeyRing real = generateV4Key("Alice Example <alice@example.org>").toCertificate()
                .getPGPPublicKeyRing();
        PGPPublicKey subkey = signingSubkeyOf(real);
        String subkeyFingerprint = KeyRingFiles.hex(subkey.getFingerprint());
        for (int i = 0; i < 4; i++) {
            BcTestKeys.addFetched(store, Map.of("hkps://impostor" + i + ".example.org", impostorHolding(subkey)));
        }
        BcTestKeys.addFetched(store, Map.of("hkps://real.example.org", real));
        for (int i = 4; i < 8; i++) {
            BcTestKeys.addFetched(store, Map.of("hkps://impostor" + i + ".example.org", impostorHolding(subkey)));
        }

        assertThat(store.keyserversServing(subkeyFingerprint)).containsExactly("hkps://real.example.org");
        assertThat(store.userIdsServedBy(subkeyFingerprint, "hkps://real.example.org"))
                .containsExactly("Alice Example <alice@example.org>");
        assertThat(store.findPublicKey(subkeyFingerprint).ring().getPublicKey().getFingerprint())
                .isEqualTo(real.getPublicKey().getFingerprint());
    }

    /**
     * A keyserver may add unhashed subpackets to a signature it serves, and joining copies merges
     * them; the revocation is still the one each server served.
     */
    @Test
    void revocationServedByIgnoresUnhashedSubpacketsAServerAdded(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        BcKeyStore generated = new BcKeyStore(null, tempDir.resolve("keys-cert-d"), tempDir.resolve("keys-bc"));
        String fingerprint = BcTestKeys.generate(generated, "Alice Example <alice@example.org>", "ed25519", "pgp4");
        PGPPublicKeyRing full = generated.findPublicKey(fingerprint).ring();
        PGPSecretKey signer = generated.findSecretKey(fingerprint).getSecretKey();
        PGPSignature revocation = revocationOf(signer, 0, false);
        PGPSignature annotated = revocationOf(signer, 0, true);
        assertThat(PGPSignature.isSignatureEncodingEqual(annotated, revocation)).isTrue();
        assertThat(annotated.getEncoded()).isNotEqualTo(revocation.getEncoded());
        Map<String, PGPPublicKeyRing> copies = new LinkedHashMap<>();
        copies.put("hkps://server1", reparsed(new PGPPublicKeyRing(List.of(
                PGPPublicKey.addCertification(full.getPublicKey(), revocation)))));
        copies.put("hkps://server2", reparsed(new PGPPublicKeyRing(List.of(
                PGPPublicKey.addCertification(full.getPublicKey(), annotated)))));
        BcTestKeys.addFetched(store, copies);
        PGPSignature joined = store.findPublicKey(fingerprint).ring().getPublicKey()
                .getSignaturesOfType(PGPSignature.KEY_REVOCATION).next();

        assertThat(store.revocationServedBy(fingerprint, joined))
                .containsExactly("hkps://server1", "hkps://server2");
    }

    @Test
    void aLocalCopyIsJoinedWithTheFetchedOnes(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        OpenPGPKey key = generateEd25519Key("Alice Example <alice@example.org>");
        PGPPublicKeyRing full = key.toCertificate().getPGPPublicKeyRing();
        store.storeCert(withoutUserIds(new PGPPublicKeyRing(List.of(
                PGPPublicKey.addCertification(full.getPublicKey(), revocationOf(key))))));
        BcTestKeys.addFetched(store, Map.of("hkps://keys.example.org", full));
        String fingerprint = KeyRingFiles.hex(full.getPublicKey().getFingerprint());

        PGPPublicKey found = store.findPublicKey(fingerprint).ring().getPublicKey();
        assertThat(found.hasRevocation()).isTrue();
        assertThat(found.getUserIDs()).toIterable().containsExactly("Alice Example <alice@example.org>");
    }

    @Test
    void aPersistedFetchKeepsWhatTheLocalCopyHeld(@TempDir Path tempDir) throws Exception {
        Path certD = tempDir.resolve("cert-d");
        BcKeyStore store = new BcKeyStore(null, certD, tempDir.resolve("bc-private"), true);
        OpenPGPKey key = generateEd25519Key("Alice Example <alice@example.org>");
        PGPPublicKeyRing full = key.toCertificate().getPGPPublicKeyRing();
        store.storeCert(withoutUserIds(new PGPPublicKeyRing(List.of(
                PGPPublicKey.addCertification(full.getPublicKey(), revocationOf(key))))));
        BcTestKeys.addFetched(store, Map.of("hkps://keys.example.org", full));
        String fingerprint = KeyRingFiles.hex(full.getPublicKey().getFingerprint());

        PGPPublicKey persisted = new BcKeyStore(null, certD, tempDir.resolve("bc-private"))
                .findPublicKey(fingerprint).ring().getPublicKey();
        assertThat(persisted.hasRevocation()).isTrue();
        assertThat(persisted.getUserIDs()).toIterable().containsExactly("Alice Example <alice@example.org>");
    }

    /**
     * Bouncy Castle 1.86 corrupts a native Ed25519 (algorithm 27) v4 signature when it joins two
     * copies of it; a local copy joined with a fetched one must still be a certificate.
     */
    @Test
    void aLocalCopyOfAV4Ed25519KeyJoinsWithAFetchedOne(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        byte[] encoded = generateV4Key("Alice Example <alice@example.org>").toCertificate()
                .getPGPPublicKeyRing().getEncoded();
        store.storeCert(parsed(encoded));
        BcTestKeys.addFetched(store, Map.of("hkps://keys.example.org", parsed(encoded)));
        PGPPublicKeyRing found = store.findPublicKey(KeyRingFiles.hex(parsed(encoded).getPublicKey()
                .getFingerprint())).ring();

        assertThat(found.getEncoded()).isEqualTo(encoded);
        assertThat(new OpenPGPCertificate(found).getPrimaryKey().isBoundAt(new Date())).isTrue();
    }

    @Test
    void aPersistedV4Ed25519KeyServedTwiceIsAReadableFile(@TempDir Path tempDir) throws Exception {
        Path certD = tempDir.resolve("cert-d");
        BcKeyStore store = new BcKeyStore(null, certD, tempDir.resolve("bc-private"), true);
        byte[] encoded = generateV4Key("Alice Example <alice@example.org>").toCertificate()
                .getPGPPublicKeyRing().getEncoded();
        Map<String, PGPPublicKeyRing> copies = new LinkedHashMap<>();
        copies.put("hkps://server1", parsed(encoded));
        copies.put("hkps://server2", parsed(encoded));
        BcTestKeys.addFetched(store, copies);
        String fingerprint = KeyRingFiles.hex(parsed(encoded).getPublicKey().getFingerprint());

        PGPPublicKeyRing persisted = new BcKeyStore(null, certD, tempDir.resolve("later"))
                .findPublicKey(fingerprint).ring();
        assertThat(persisted.getEncoded()).isEqualTo(encoded);
    }

    /**
     * A certificate that cannot be encoded — here one Bouncy Castle 1.86 corrupted by joining two
     * copies of a native Ed25519 v4 key itself — never truncates the file a store already holds.
     */
    @Test
    void aCertificateThatCannotBeEncodedLeavesTheStoredFileIntact(@TempDir Path tempDir) throws Exception {
        Path certD = tempDir.resolve("cert-d");
        BcKeyStore store = new BcKeyStore(null, certD, tempDir.resolve("bc-private"));
        byte[] encoded = generateV4Key("Alice Example <alice@example.org>").toCertificate()
                .getPGPPublicKeyRing().getEncoded();
        PGPPublicKeyRing corrupted = PGPPublicKeyRing.join(parsed(encoded), parsed(encoded));
        assertThatThrownBy(corrupted::getEncoded).isInstanceOf(RuntimeException.class);
        store.storeCert(parsed(encoded));
        String fp = KeyRingFiles.hex(parsed(encoded).getPublicKey().getFingerprint()).toLowerCase();
        Path certFile = certD.resolve(fp.substring(0, 2)).resolve(fp.substring(2));

        assertThatThrownBy(() -> store.storeCert(corrupted)).isInstanceOf(RuntimeException.class);

        assertThat(Files.readAllBytes(certFile)).isEqualTo(encoded);
        try (Stream<Path> files = Files.list(certFile.getParent())) {
            assertThat(files).containsExactly(certFile);
        }
    }

    private static PGPPublicKeyRing parsed(byte[] encoded) throws Exception {
        return new PGPPublicKeyRing(encoded, new BcKeyFingerprintCalculator());
    }

    /**
     * A certificate of a newly generated key holding {@code held} as a subkey, bound by that
     * key's primary: what anyone can upload to a keyserver that does not validate uploads. It
     * carries no binding signature made by {@code held}, which only its holder could make.
     */
    private PGPPublicKeyRing impostorHolding(PGPPublicKey held) throws Exception {
        PGPSecretKey impostor = generateV4Key("Mallory <mallory@example.org>").getPGPSecretKeyRing().getSecretKey();
        PublicKeyPacket packet = held.getPublicKeyPacket();
        PGPPublicKey asSubkey = new PGPPublicKey(new PublicSubkeyPacket(packet.getVersion(), packet.getAlgorithm(),
                packet.getTime(), packet.getKey()), new BcKeyFingerprintCalculator());
        PGPSignatureGenerator generator = new PGPSignatureGenerator(
                new BcPGPContentSignerBuilder(impostor.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256),
                impostor.getPublicKey());
        generator.init(PGPSignature.SUBKEY_BINDING, impostor.extractPrivateKey(null));
        PGPSignatureSubpacketGenerator hashed = new PGPSignatureSubpacketGenerator();
        hashed.setSignatureCreationTime(true, new Date());
        hashed.setKeyFlags(false, KeyFlags.SIGN_DATA);
        generator.setHashedSubpackets(hashed.generate());
        PGPSignature binding = generator.generateCertification(impostor.getPublicKey(), asSubkey);
        return new PGPPublicKeyRing(List.of(impostor.getPublicKey(), PGPPublicKey.addCertification(asSubkey, binding)));
    }

    /**
     * The certificate as a keyserver serves it: encoded, and parsed again, as Bouncy Castle
     * compares the signature values of signatures it parsed.
     */
    private static PGPPublicKeyRing reparsed(PGPPublicKeyRing ring) throws Exception {
        return new PGPPublicKeyRing(ring.getEncoded(), new BcKeyFingerprintCalculator());
    }

    private static PGPPublicKey signingSubkeyOf(PGPPublicKeyRing ring) {
        Iterator<PGPPublicKey> keys = ring.getPublicKeys();
        PGPPublicKey last = keys.next();
        while (keys.hasNext()) {
            last = keys.next();
        }
        return last;
    }

    /** A v4 key with a signing subkey, which carries a binding signature it made itself. */
    private static OpenPGPKey generateV4Key(String userId) throws Exception {
        return new BcOpenPGPApi().generateKey(PublicKeyPacket.VERSION_4)
                .ed25519x25519Key(userId)
                .addSigningSubkey()
                .build();
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
        return revocationOf(key.getPGPSecretKeyRing().getSecretKey(), secondsLater, false);
    }

    /**
     * A revocation of the key for compromise; when {@code annotated}, with a notation in its
     * unhashed area, as a keyserver may add, and otherwise the same signature for an EdDSA key,
     * whose signatures are deterministic.
     */
    private static PGPSignature revocationOf(PGPSecretKey signer, int secondsLater, boolean annotated)
            throws Exception {
        PGPSignatureGenerator generator = new PGPSignatureGenerator(
                new BcPGPContentSignerBuilder(signer.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256),
                signer.getPublicKey());
        generator.init(PGPSignature.KEY_REVOCATION, signer.extractPrivateKey(null));
        PGPSignatureSubpacketGenerator hashed = new PGPSignatureSubpacketGenerator();
        hashed.setSignatureCreationTime(true, Date.from(Instant.parse("2026-01-01T00:00:00Z").plusSeconds(secondsLater)));
        hashed.setRevocationReason(true, RevocationReasonTags.KEY_COMPROMISED, "compromised");
        generator.setHashedSubpackets(hashed.generate());
        if (annotated) {
            PGPSignatureSubpacketGenerator unhashed = new PGPSignatureSubpacketGenerator();
            unhashed.addNotationData(false, true, "served@example.org", "yes");
            generator.setUnhashedSubpackets(unhashed.generate());
        }
        return generator.generateCertification(signer.getPublicKey());
    }

    private OpenPGPKey generateEd25519Key(String userId) throws Exception {
        BcOpenPGPApi api = new BcOpenPGPApi();
        return api.generateKey().ed25519x25519Key(userId).build();
    }
}
