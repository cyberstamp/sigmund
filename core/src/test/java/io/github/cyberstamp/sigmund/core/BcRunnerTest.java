package io.github.cyberstamp.sigmund.core;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BcRunnerTest {

    private BcRunner createVerifyOnly(Path tempDir) {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        return new BcRunner(store, null, null);
    }

    @Test
    void nameReturnsBc() {
        BcRunner runner = createVerifyOnly(Path.of(System.getProperty("java.io.tmpdir")));
        assertEquals("bc", runner.name());
    }

    @Test
    void isAvailableAlwaysTrue() {
        BcRunner runner = createVerifyOnly(Path.of(System.getProperty("java.io.tmpdir")));
        assertTrue(runner.isAvailable());
    }

    @Test
    void canSignFalseWhenNoFingerprint() {
        BcRunner runner = createVerifyOnly(Path.of(System.getProperty("java.io.tmpdir")));
        assertFalse(runner.canSign());
    }

    @Test
    void supportedCredentialTypesBothV4AndV6() {
        BcRunner runner = createVerifyOnly(Path.of(System.getProperty("java.io.tmpdir")));
        assertEquals(Set.of("openpgp4", "openpgp6"), runner.supportedCredentialTypes());
    }

    @Test
    void canVerifyAcceptsAnyOpenPgpUnit() {
        BcRunner runner = createVerifyOnly(Path.of(System.getProperty("java.io.tmpdir")));
        assertTrue(runner.canVerify(new OpenPgpVerificationUnit("block", 4, "FP", 27)));
        assertTrue(runner.canVerify(new OpenPgpVerificationUnit("block", 6, "FP", 27)));
    }

    @Test
    void canVerifyRejectsSigstoreUnit() {
        BcRunner runner = createVerifyOnly(Path.of(System.getProperty("java.io.tmpdir")));
        assertFalse(runner.canVerify(new SigstoreVerificationUnit("{}")));
    }

    @Test
    void extractCredentialsV4ProducesOpenpgp4(@TempDir Path tempDir) {
        BcRunner runner = createVerifyOnly(tempDir);
        OpenPgpVerifyResult result = new OpenPgpVerifyResult(
                Verdict.PASS, "User <user@example.com>", "Ed25519",
                4, "AABBCCDD", "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD");
        var creds = runner.extractCredentials(result);
        assertEquals(2, creds.size());
        assertInstanceOf(FingerprintCredential.class, creds.get(0));
        assertEquals("openpgp4", creds.get(0).type());
        assertInstanceOf(EmailCredential.class, creds.get(1));
    }

    @Test
    void extractCredentialsV6ProducesOpenpgp6(@TempDir Path tempDir) {
        BcRunner runner = createVerifyOnly(tempDir);
        OpenPgpVerifyResult result = new OpenPgpVerifyResult(
                Verdict.PASS, "User <user@example.com>", "Ed25519",
                6, null, "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD");
        var creds = runner.extractCredentials(result);
        assertEquals(2, creds.size());
        assertEquals("openpgp6", creds.get(0).type());
    }

    @Test
    void extractCredentialsFailReturnsEmpty(@TempDir Path tempDir) {
        BcRunner runner = createVerifyOnly(tempDir);
        OpenPgpVerifyResult result = new OpenPgpVerifyResult(
                Verdict.FAIL, null, null, 4, null, null);
        assertTrue(runner.extractCredentials(result).isEmpty());
    }

    @Test
    void signAndVerifyRoundTripEd25519(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        BcRunner runner = new BcRunner(store, null, null);

        String fingerprint = runner.generateKey("Test <test@example.com>", "ed25519");
        BcRunner signer = new BcRunner(store, fingerprint, null);

        Path artifact = tempDir.resolve("artifact.txt");
        Files.writeString(artifact, "test content");
        Path sigFile = tempDir.resolve("artifact.txt.asc");

        SignResult signResult = signer.sign(artifact, sigFile);
        assertNotNull(signResult.algorithm());

        String armored = Files.readString(sigFile);
        OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);
        OpenPgpVerificationUnit unit = new OpenPgpVerificationUnit(
                armored, info.version(), info.issuerFingerprint(), info.algorithmId());

        VerifyResult result = signer.verify(artifact, unit);
        assertEquals(Verdict.PASS, result.verdict());
    }

    @Test
    void verifyFallsBackToKeyIdWhenFingerprintMissing(@TempDir Path tempDir) throws Exception {
        // Use ECDSA P-256 which produces v4 keys — the real scenario where
        // Issuer Fingerprint subpackets (type 33) are often absent
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        BcRunner runner = new BcRunner(store, null, null);

        String fingerprint = runner.generateKey("Test <test@example.com>", "nistp256");
        BcRunner signer = new BcRunner(store, fingerprint, null);

        Path artifact = tempDir.resolve("artifact.txt");
        Files.writeString(artifact, "test content");
        Path sigFile = tempDir.resolve("artifact.txt.asc");
        signer.sign(artifact, sigFile);

        String armored = Files.readString(sigFile);
        OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);

        // Create a unit with null fingerprint, simulating a v4 signature
        // without Issuer Fingerprint subpacket (type 33)
        OpenPgpVerificationUnit unitNoFp = new OpenPgpVerificationUnit(
                armored, info.version(), null, info.algorithmId());

        // BC should extract the key ID from the signature bytes and find the key
        VerifyResult result = runner.verify(artifact, unitNoFp);
        assertEquals(Verdict.PASS, result.verdict());
    }

    @Test
    void verifyNullFingerprintNoKeyReturnsNoKey(@TempDir Path tempDir) throws Exception {
        // Use an empty key store — no keys available
        BcKeyStore emptyStore = new BcKeyStore(null, tempDir.resolve("empty-cert-d"),
                tempDir.resolve("empty-bc-private"));
        BcRunner runner = new BcRunner(emptyStore, null, null);

        // Generate a key in a separate store just to produce a valid signature
        BcKeyStore signerStore = new BcKeyStore(null, tempDir.resolve("signer-cert-d"),
                tempDir.resolve("signer-bc-private"));
        BcRunner signerRunner = new BcRunner(signerStore, null, null);
        String fp = signerRunner.generateKey("Signer <signer@example.com>", "nistp256");
        BcRunner signer = new BcRunner(signerStore, fp, null);

        Path artifact = tempDir.resolve("artifact.txt");
        Files.writeString(artifact, "test content");
        Path sigFile = tempDir.resolve("artifact.txt.asc");
        signer.sign(artifact, sigFile);

        String armored = Files.readString(sigFile);
        OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);

        // Verify with null fingerprint against the empty store
        OpenPgpVerificationUnit unitNoFp = new OpenPgpVerificationUnit(
                armored, info.version(), null, info.algorithmId());

        VerifyResult result = runner.verify(artifact, unitNoFp);
        assertEquals(Verdict.NO_KEY, result.verdict());
        assertNotNull(((OpenPgpVerifyResult) result).fingerprint());
    }

    /**
     * Verifies that {@link BcRunner#fetchKeyEphemeral(String, String)} caches a key
     * in memory (via {@link BcKeyStore#cacheEphemeral}) so that subsequent verification
     * succeeds, while no key file is written to the cert-d directory on disk.
     *
     * <p>
     * This simulates the {@code importToKeyring=false} (default) flow: the key is
     * fetched for the current session only and discarded when the JVM exits.
     */
    @Test
    void fetchKeyEphemeralVerifiesWithoutPersisting(@TempDir Path tempDir) throws Exception {
        // Signer store: generate key and sign
        BcKeyStore signerStore = new BcKeyStore(null, tempDir.resolve("signer-cd"), tempDir.resolve("signer-bp"));
        BcRunner signerRunner = new BcRunner(signerStore, null, null);
        String fp = signerRunner.generateKey("Eph <eph@example.com>", "nistp256");
        BcRunner signer = new BcRunner(signerStore, fp, null);

        Path artifact = tempDir.resolve("artifact.txt");
        Files.writeString(artifact, "ephemeral test");
        Path sigFile = tempDir.resolve("artifact.txt.asc");
        signer.sign(artifact, sigFile);

        // Verifier store: empty, isolated from signer
        Path verifierCertD = tempDir.resolve("verifier-cd");
        BcKeyStore verifierStore = new BcKeyStore(null, verifierCertD, tempDir.resolve("verifier-bp"));
        BcRunner verifier = new BcRunner(verifierStore, null, null);

        // Export the key, then simulate ephemeral fetch by calling cacheEphemeral directly
        // (fetchKeyEphemeral would call fetchKeyFromHkp which needs a real keyserver)
        var pubRing = signerStore.findPublicKey(fp);
        verifierStore.cacheEphemeral(pubRing);

        String armored = Files.readString(sigFile);
        OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);
        OpenPgpVerificationUnit unit = new OpenPgpVerificationUnit(
                armored, info.version(), info.issuerFingerprint(), info.algorithmId());

        VerifyResult result = verifier.verify(artifact, unit);
        assertEquals(Verdict.PASS, result.verdict());
        assertFalse(Files.exists(verifierCertD), "cert-d should not exist — key was ephemeral");
    }

    @Test
    void verifyNoKeyReturnsNoKeyVerdict(@TempDir Path tempDir) throws Exception {
        BcRunner runner = createVerifyOnly(tempDir);
        OpenPgpVerificationUnit unit = new OpenPgpVerificationUnit(
                "-----BEGIN PGP SIGNATURE-----\nfake\n-----END PGP SIGNATURE-----\n",
                4, "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF", 27);

        VerifyResult result = runner.verify(tempDir.resolve("nonexistent"), unit);
        assertEquals(Verdict.NO_KEY, result.verdict());
    }

    // --- Passphrase-protected key tests ---

    private static final char[] TEST_PASSPHRASE = "test-secret".toCharArray();

    private static PassphraseProvider fixedPassphrase(char[] passphrase) {
        return fp -> passphrase.clone();
    }

    @Test
    void generateKeyWithPassphraseStoresEncrypted(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        BcRunner runner = new BcRunner(store, null, null, fixedPassphrase(TEST_PASSPHRASE));

        String fingerprint = runner.generateKey("Test <test@example.com>", "ed25519");
        PGPSecretKeyRing ring = store.findSecretKey(fingerprint);
        assertNotNull(ring);

        for (var keys = ring.getSecretKeys(); keys.hasNext();) {
            PGPSecretKey sk = keys.next();
            assertNotEquals(SymmetricKeyAlgorithmTags.NULL, sk.getKeyEncryptionAlgorithm(),
                    "Secret key should be encrypted");
        }
    }

    @Test
    void signAndVerifyWithEncryptedKey(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        PassphraseProvider provider = fixedPassphrase(TEST_PASSPHRASE);
        BcRunner runner = new BcRunner(store, null, null, provider);

        String fingerprint = runner.generateKey("Test <test@example.com>", "ed25519");
        BcRunner signer = new BcRunner(store, fingerprint, null, provider);

        Path artifact = tempDir.resolve("artifact.txt");
        Files.writeString(artifact, "encrypted key content");
        Path sigFile = tempDir.resolve("artifact.txt.asc");

        SignResult signResult = signer.sign(artifact, sigFile);
        assertNotNull(signResult.algorithm());

        String armored = Files.readString(sigFile);
        OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);
        OpenPgpVerificationUnit unit = new OpenPgpVerificationUnit(
                armored, info.version(), info.issuerFingerprint(), info.algorithmId());

        VerifyResult result = signer.verify(artifact, unit);
        assertEquals(Verdict.PASS, result.verdict());
    }

    @Test
    void signWithEncryptedKeyNoProviderThrows(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        BcRunner generator = new BcRunner(store, null, null, fixedPassphrase(TEST_PASSPHRASE));
        String fingerprint = generator.generateKey("Test <test@example.com>", "ed25519");

        // signer has no passphrase provider
        BcRunner signer = new BcRunner(store, fingerprint, null);

        Path artifact = tempDir.resolve("artifact.txt");
        Files.writeString(artifact, "content");
        Path sigFile = tempDir.resolve("artifact.txt.asc");

        ToolExecutionException ex = assertThrows(ToolExecutionException.class,
                () -> signer.sign(artifact, sigFile));
        assertTrue(ex.getMessage().contains("passphrase"), ex.getMessage());
    }

    @Test
    void signWithWrongPassphraseThrows(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        BcRunner generator = new BcRunner(store, null, null, fixedPassphrase(TEST_PASSPHRASE));
        String fingerprint = generator.generateKey("Test <test@example.com>", "ed25519");

        BcRunner signer = new BcRunner(store, fingerprint, null,
                fixedPassphrase("wrong-passphrase".toCharArray()));

        Path artifact = tempDir.resolve("artifact.txt");
        Files.writeString(artifact, "content");
        Path sigFile = tempDir.resolve("artifact.txt.asc");

        assertThrows(ToolExecutionException.class, () -> signer.sign(artifact, sigFile));
    }

    @Test
    void signWithNullPassphraseFromProviderThrows(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        BcRunner generator = new BcRunner(store, null, null, fixedPassphrase(TEST_PASSPHRASE));
        String fingerprint = generator.generateKey("Test <test@example.com>", "ed25519");

        BcRunner signer = new BcRunner(store, fingerprint, null, fp -> null);

        Path artifact = tempDir.resolve("artifact.txt");
        Files.writeString(artifact, "content");
        Path sigFile = tempDir.resolve("artifact.txt.asc");

        ToolExecutionException ex = assertThrows(ToolExecutionException.class,
                () -> signer.sign(artifact, sigFile));
        assertTrue(ex.getMessage().contains("passphrase"), ex.getMessage());
    }

    @Test
    void generateKeyNullPassphraseFromProviderStoresUnencrypted(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        BcRunner runner = new BcRunner(store, null, null, fp -> null);

        String fingerprint = runner.generateKey("Test <test@example.com>", "ed25519");
        PGPSecretKeyRing ring = store.findSecretKey(fingerprint);
        assertNotNull(ring);

        PGPSecretKey primary = ring.getSecretKey();
        assertEquals(SymmetricKeyAlgorithmTags.NULL, primary.getKeyEncryptionAlgorithm());
    }

    @Test
    void generateKeyEmptyPassphraseStoresUnencrypted(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        BcRunner runner = new BcRunner(store, null, null, fp -> new char[0]);

        String fingerprint = runner.generateKey("Test <test@example.com>", "ed25519");
        PGPSecretKeyRing ring = store.findSecretKey(fingerprint);

        PGPSecretKey primary = ring.getSecretKey();
        assertEquals(SymmetricKeyAlgorithmTags.NULL, primary.getKeyEncryptionAlgorithm());
    }

    @Test
    void signAndVerifyEncryptedKeyRsa(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        PassphraseProvider provider = fixedPassphrase(TEST_PASSPHRASE);
        BcRunner runner = new BcRunner(store, null, null, provider);

        String fingerprint = runner.generateKey("Test <test@example.com>", "rsa4096");
        BcRunner signer = new BcRunner(store, fingerprint, null, provider);

        Path artifact = tempDir.resolve("artifact.txt");
        Files.writeString(artifact, "rsa encrypted key");
        Path sigFile = tempDir.resolve("artifact.txt.asc");
        signer.sign(artifact, sigFile);

        String armored = Files.readString(sigFile);
        OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);
        OpenPgpVerificationUnit unit = new OpenPgpVerificationUnit(
                armored, info.version(), info.issuerFingerprint(), info.algorithmId());

        assertEquals(Verdict.PASS, signer.verify(artifact, unit).verdict());
    }

    @Test
    void signAndVerifyEncryptedKeyEcdsaV4(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        PassphraseProvider provider = fixedPassphrase(TEST_PASSPHRASE);
        BcRunner runner = new BcRunner(store, null, null, provider);

        String fingerprint = runner.generateKey("Test <test@example.com>", "nistp256");
        BcRunner signer = new BcRunner(store, fingerprint, null, provider);

        Path artifact = tempDir.resolve("artifact.txt");
        Files.writeString(artifact, "ecdsa v4 encrypted key");
        Path sigFile = tempDir.resolve("artifact.txt.asc");
        signer.sign(artifact, sigFile);

        String armored = Files.readString(sigFile);
        OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);
        OpenPgpVerificationUnit unit = new OpenPgpVerificationUnit(
                armored, info.version(), info.issuerFingerprint(), info.algorithmId());

        assertEquals(Verdict.PASS, signer.verify(artifact, unit).verdict());
    }

    @Test
    void builderPassphraseProviderThreadsToBcRunner(@TempDir Path tempDir) throws Exception {
        PassphraseProvider provider = fixedPassphrase(TEST_PASSPHRASE);

        String certD = tempDir.resolve("cert-d").toString();
        String bcPrivate = tempDir.resolve("bc-private").toString();

        // Generate an encrypted key via direct BcRunner
        BcKeyStore store = new BcKeyStore(null, Path.of(certD), Path.of(bcPrivate));
        BcRunner generator = new BcRunner(store, null, null, provider);
        String fingerprint = generator.generateKey("Test <test@example.com>", "ed25519");

        // Sign via Sigmund builder with bcPassphraseProvider — point to same key store
        Sigmund sigmund = Sigmund.builder()
                .bcPassphraseProvider(provider)
                .addSigningTool("bc", Map.of(
                        "signing-fingerprint", fingerprint,
                        "cert-d-home", certD,
                        "bc-private-home", bcPrivate))
                .build();

        Path artifact = tempDir.resolve("artifact.txt");
        Files.writeString(artifact, "builder test");

        SigningOutput output = sigmund.signer().sign(artifact, tempDir);
        assertFalse(output.files().isEmpty());
    }
}
