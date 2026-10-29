package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BcRunnerTest {

    /**
     * bc generates v4 keys unless asked for v6: v4 is what keyservers serve and gpg signs with,
     * so a key from a plain {@code keygen --tool bc} can be published and used anywhere.
     */
    @Nested
    class KeyVersion {

        private BcKeyStore store(Path dir) {
            return new BcKeyStore(null, dir.resolve("cert-d"), dir.resolve("bc-private"));
        }

        private Set<String> typesOf(BcKeyStore store, String fingerprint) {
            return new BcRunner(store, fingerprint, null).signingInfo().get(0).credentialTypes();
        }

        @Test
        void withoutACredentialTypeTheKeyIsV4(@TempDir Path dir) {
            BcKeyStore store = store(dir);

            String fingerprint = new BcRunner(store, null, null).generateKey("A <a@example.com>", "ed25519", null);

            assertThat(fingerprint).hasSize(40);
            assertThat(typesOf(store, fingerprint)).containsExactly(Credential.TYPE_PGP4);
        }

        @Test
        void aV4Ed25519KeyUsesTheLegacyEncodingGnuPgReads(@TempDir Path dir) {
            BcKeyStore store = store(dir);
            BcRunner runner = new BcRunner(store, null, null);

            String fingerprint = runner.generateKey("A <a@example.com>", "ed25519", Credential.TYPE_PGP4);

            PGPPublicKeyRing ring = store.findPublicKey(fingerprint).ring();
            ring.getPublicKeys().forEachRemaining(key -> assertThat(key.getAlgorithm())
                    .isEqualTo(PublicKeyAlgorithmTags.EDDSA_LEGACY));
        }

        @Test
        void pgp6GivesAV6Key(@TempDir Path dir) {
            BcKeyStore store = store(dir);

            String fingerprint = new BcRunner(store, null, null)
                    .generateKey("A <a@example.com>", "ed25519", Credential.TYPE_PGP6);

            assertThat(fingerprint).hasSize(64);
            assertThat(typesOf(store, fingerprint)).containsExactly(Credential.TYPE_PGP6);
        }

        @Test
        void anEcdsaKeyCannotBeV6(@TempDir Path dir) {
            assertThatThrownBy(() -> new BcRunner(store(dir), null, null)
                    .generateKey("A <a@example.com>", "nistp256", Credential.TYPE_PGP6))
                    .isInstanceOf(ToolExecutionException.class)
                    .hasMessageContaining("nistp256 produces v4 keys only");
        }

        @Test
        void anEd448KeyIsV6Only(@TempDir Path dir) {
            assertThatThrownBy(() -> new BcRunner(store(dir), null, null)
                    .generateKey("A <a@example.com>", "ed448", null))
                    .isInstanceOf(ToolExecutionException.class)
                    .hasMessageContaining("ed448 produces pgp6 keys only");
        }

        @Test
        void anUnknownCredentialTypeIsRejected(@TempDir Path dir) {
            assertThatThrownBy(() -> new BcRunner(store(dir), null, null)
                    .generateKey("A <a@example.com>", "ed25519", "sigstore"))
                    .isInstanceOf(ToolExecutionException.class)
                    .hasMessageContaining("Unsupported credential type for bc keys: sigstore");
        }
    }

    @Nested
    class KeyExpiry {

        @Test
        void signatureDatedBeforeTheKeyExistedIsRejected(@TempDir Path tempDir) throws Exception {
            BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"),
                    tempDir.resolve("bc-private"));
            String fingerprint;
            try (BcRunner bcRunner = new BcRunner(store, null, null)) {
                fingerprint = bcRunner.generateKey("Test <test@example.com>", "nistp256", null);
            }
            Path artifact = Files.writeString(tempDir.resolve("artifact.txt"), "content");

            // a signature whose signed creation time predates the key it was made with, as a
            // leaked key could produce to date a signature into an earlier window
            OpenPgpClaim backdated = lowLevelSignature(store, fingerprint, artifact,
                    HashAlgorithmTags.SHA256, Instant.ofEpochSecond(1));

            try (BcRunner bcRunner = new BcRunner(store, null, null)) {
                VerifyResult result = bcRunner.verify(artifact, backdated);

                assertThat(backdated.claimTime()).isEqualTo(Instant.ofEpochSecond(1));
                assertThat(result.isFailed()).isTrue();
            }
        }

        @Test
        void sha1SignatureStillVerifies(@TempDir Path tempDir) throws Exception {
            BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"),
                    tempDir.resolve("bc-private"));
            String fingerprint;
            try (BcRunner bcRunner = new BcRunner(store, null, null)) {
                fingerprint = bcRunner.generateKey("Test <test@example.com>", "nistp256", null);
            }
            Path artifact = Files.writeString(tempDir.resolve("artifact.txt"), "content");

            // older artifacts in Maven repositories are signed with SHA-1; rejecting weak
            // algorithms is a separate policy decision, not a failed signature
            OpenPgpClaim claim = lowLevelSignature(store, fingerprint, artifact,
                    HashAlgorithmTags.SHA1, Instant.now());

            try (BcRunner bcRunner = new BcRunner(store, null, null)) {
                assertThat(bcRunner.verify(artifact, claim).isVerified()).isTrue();
            }
        }

        @Test
        void signatureMadeWhileTheKeyWasValidVerifies(@TempDir Path tempDir) throws Exception {
            try (BcRunner signer = createSigningRunner(tempDir)) {
                Path artifact = Files.writeString(tempDir.resolve("artifact.txt"), "content");
                Path signature = tempDir.resolve("artifact.txt.asc");
                signer.sign(artifact, signature);

                OpenPgpClaim claim = (OpenPgpClaim) new OpenPgpSignatureFormat()
                        .parse(Evidence.read(signature, Evidence.SOURCE_SIDECAR)).get(0);

                assertThat(signer.verify(artifact, claim).isVerified()).isTrue();
            }
        }
    }

    @Nested
    class FailureMapping {

        @Test
        void signatureWithoutIssuerIsMalformedNotUnsupported(@TempDir Path tempDir)
                throws Exception {
            try (BcRunner runner = createVerifyOnly(tempDir)) {
                Path artifact = Files.writeString(tempDir.resolve("artifact.txt"), "content");
                OpenPgpClaim noIssuer = new OpenPgpClaim("not an armored signature", 4, null, 1, null);

                VerifyResult result = runner.verify(artifact, noIssuer);

                assertThat(result.isIndeterminate(IndeterminateReason.EVIDENCE_MALFORMED)).isTrue();
            }
        }

        @Test
        void aClaimOfAnotherKindIsUnsupported(@TempDir Path tempDir) throws Exception {
            try (BcRunner runner = createVerifyOnly(tempDir)) {
                Path artifact = Files.writeString(tempDir.resolve("artifact.txt"), "content");

                VerifyResult result = runner.verify(artifact, new SigstoreClaim("{}", null));

                assertThat(result.isIndeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM)).isTrue();
            }
        }
    }

    @Nested
    class KeyValidity {

        @Test
        void aSubkeyBoundWithARejectedHashIsUnsupportedNotFailed(@TempDir Path tempDir)
                throws Exception {
            PGPKeyPair primary = rsaKeyPair();
            PGPKeyPair subkey = rsaKeyPair();
            PGPPublicKeyRing certificate = PGPPublicKeyRing.insertPublicKey(
                    keyRing(primary, null, HashAlgorithmTags.SHA256).generatePublicKeyRing(),
                    keyRing(primary, subkey, HashAlgorithmTags.MD5).generatePublicKeyRing()
                            .getPublicKey(subkey.getKeyID()));
            BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"),
                    tempDir.resolve("bc-private"));
            store.addFetched(certificate, "hkps://keys.example.org");
            Path artifact = Files.writeString(tempDir.resolve("artifact.txt"), "content");
            OpenPgpClaim claim = lowLevelSignature(subkey.getPublicKey(), subkey.getPrivateKey(),
                    artifact, HashAlgorithmTags.SHA256, Instant.now());

            try (BcRunner bcRunner = new BcRunner(store, null, null)) {
                VerifyResult result = bcRunner.verify(artifact, claim);

                assertThat(result.isIndeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM))
                        .as(result.outcome() + " " + result.reason()).isTrue();
            }
        }

        private static PGPKeyPair rsaKeyPair() throws Exception {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA",
                    new BouncyCastleProvider());
            generator.initialize(2048, new SecureRandom());
            return new JcaPGPKeyPair(PublicKeyPacket.VERSION_4, PublicKeyAlgorithmTags.RSA_GENERAL,
                    generator.generateKeyPair(), Date.from(Instant.now().minusSeconds(3600)));
        }

        /**
         * The primary key with a user ID certified using the given hash and, when a subkey is
         * given, that subkey bound for signing using the same hash and back-signed with SHA-256.
         */
        private static PGPKeyRingGenerator keyRing(PGPKeyPair primary, PGPKeyPair subkey,
                int selfSignatureHash) throws Exception {
            PGPSignatureSubpacketGenerator flags = new PGPSignatureSubpacketGenerator();
            flags.setKeyFlags(false, KeyFlags.CERTIFY_OTHER);
            PGPKeyRingGenerator generator = new PGPKeyRingGenerator(
                    PGPSignature.POSITIVE_CERTIFICATION, primary, "Signer <signer@example.org>",
                    new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1),
                    flags.generate(), null,
                    new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_GENERAL,
                            selfSignatureHash),
                    new JcePBESecretKeyEncryptorBuilder(0).build(null));
            if (subkey != null) {
                PGPSignatureSubpacketGenerator signing = new PGPSignatureSubpacketGenerator();
                signing.setKeyFlags(false, KeyFlags.SIGN_DATA);
                generator.addSubKey(subkey, signing.generate(), null,
                        new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_GENERAL,
                                HashAlgorithmTags.SHA256));
            }
            return generator;
        }
    }

    private static OpenPgpClaim lowLevelSignature(BcKeyStore store, String fingerprint,
            Path artifact, int hashAlgorithm, Instant creationTime) throws Exception {
        PGPSecretKey key = store.findSecretKey(fingerprint).getSecretKey();
        return lowLevelSignature(key.getPublicKey(), key.extractPrivateKey(null), artifact,
                hashAlgorithm, creationTime);
    }

    /**
     * Signs an artifact with the given key, choosing the hash and the
     * signed creation time, and parses the result as a claim.
     */
    private static OpenPgpClaim lowLevelSignature(PGPPublicKey publicKey, PGPPrivateKey privateKey,
            Path artifact, int hashAlgorithm, Instant creationTime) throws Exception {
        PGPSignatureGenerator generator = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(publicKey.getAlgorithm(), hashAlgorithm), publicKey);
        generator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
        PGPSignatureSubpacketGenerator hashed = new PGPSignatureSubpacketGenerator();
        hashed.setSignatureCreationTime(true, Date.from(creationTime));
        hashed.setIssuerFingerprint(false, publicKey);
        generator.setHashedSubpackets(hashed.generate());
        generator.update(Files.readAllBytes(artifact));
        Path signature = artifact.resolveSibling(artifact.getFileName() + ".asc");
        try (OutputStream out = new ArmoredOutputStream(Files.newOutputStream(signature))) {
            generator.generate().encode(out);
        }
        return (OpenPgpClaim) new OpenPgpSignatureFormat()
                .parse(Evidence.read(signature, Evidence.SOURCE_SIDECAR)).get(0);
    }

    @Nested
    class OwnSigningKey {

        @TempDir
        Path dir;

        @Test
        void aRunnerSigningFromATskVerifiesItsOwnSignatureOverEmptyStores() throws Exception {
            String fp = generate("signer");
            BcRunner runner = new BcRunner(emptyStore(), null, exportTsk("signer", fp));

            VerifyResult result = runner.verify(artifact(), signWith(runner));

            assertThat(result.isVerified()).isTrue();
            assertThat(((OpenPgpVerifyResult) result).primaryFingerprint()).isEqualTo(fp);
        }

        @Test
        void anotherKeyIsStillNotFound() throws Exception {
            BcRunner runner = new BcRunner(emptyStore(), null,
                    exportTsk("signer", generate("signer")));
            signWith(runner);
            String otherFp = generate("other");
            BcRunner other = new BcRunner(store("other"), otherFp, null);

            VerifyResult result = runner.verify(artifact(), signWith(other));

            assertThat(result.isIndeterminate(IndeterminateReason.KEY_UNAVAILABLE)).isTrue();
        }

        private OpenPgpClaim signWith(BcRunner signer) throws IOException {
            Path content = Files.writeString(artifact(), "test content");
            Path signature = dir.resolve("artifact.txt.asc");
            signer.sign(content, signature);
            return (OpenPgpClaim) new OpenPgpSignatureFormat()
                    .parse(Evidence.read(signature, Evidence.SOURCE_SIDECAR)).get(0);
        }

        private String generate(String name) {
            return new BcRunner(store(name), null, null)
                    .generateKey("Test <" + name + "@example.com>", "ed25519", null);
        }

        private Path exportTsk(String name, String fp) throws IOException {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (ArmoredOutputStream armored = new ArmoredOutputStream(out)) {
                store(name).findSecretKey(fp).encode(armored);
            }
            return Files.write(dir.resolve(name + ".tsk"), out.toByteArray());
        }

        private BcKeyStore emptyStore() {
            return store("empty");
        }

        private BcKeyStore store(String name) {
            return new BcKeyStore(null, dir.resolve(name + "/cert-d"),
                    dir.resolve(name + "/bc-private"));
        }

        private Path artifact() {
            return dir.resolve("artifact.txt");
        }
    }

    private BcRunner createSigningRunner(Path tempDir) {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"),
                tempDir.resolve("bc-private"));
        String fingerprint = new BcRunner(store, null, null)
                .generateKey("Test <test@example.com>", "ed25519", null);
        return new BcRunner(store, fingerprint, null);
    }

    private BcRunner createVerifyOnly(Path tempDir) {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        return new BcRunner(store, null, null);
    }

    @Test
    void nameReturnsBc() {
        BcRunner runner = createVerifyOnly(Path.of(System.getProperty("java.io.tmpdir")));
        assertThat(runner.name()).isEqualTo("bc");
    }

    @Test
    void isAvailableAlwaysTrue() {
        BcRunner runner = createVerifyOnly(Path.of(System.getProperty("java.io.tmpdir")));
        assertThat(runner.isAvailable()).isTrue();
    }

    @Test
    void canSignFalseWhenNoFingerprint() {
        BcRunner runner = createVerifyOnly(Path.of(System.getProperty("java.io.tmpdir")));
        assertThat(runner.canSign()).isFalse();
    }

    @Test
    void supportedCredentialTypesBothV4AndV6() {
        BcRunner runner = createVerifyOnly(Path.of(System.getProperty("java.io.tmpdir")));
        assertThat(runner.supportedCredentialTypes()).isEqualTo(Set.of("pgp4", "pgp6"));
    }

    @Test
    void canVerifyAcceptsAnyOpenPgpClaim() {
        BcRunner runner = createVerifyOnly(Path.of(System.getProperty("java.io.tmpdir")));
        assertThat(runner.canVerify(new OpenPgpClaim("block", 4, "FP", 27, null))).isTrue();
        assertThat(runner.canVerify(new OpenPgpClaim("block", 6, "FP", 27, null))).isTrue();
    }

    @Test
    void canVerifyRejectsSigstoreClaim() {
        BcRunner runner = createVerifyOnly(Path.of(System.getProperty("java.io.tmpdir")));
        assertThat(runner.canVerify(new SigstoreClaim("{}", null))).isFalse();
    }

    @Test
    void extractCredentialsV4ProducesOpenpgp4(@TempDir Path tempDir) {
        BcRunner runner = createVerifyOnly(tempDir);
        OpenPgpVerifyResult result = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, "User <user@example.com>", "Ed25519",
                4, "AABBCCDD", "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD");
        var creds = runner.extractCredentials(result);
        assertThat(creds).containsExactly(
                new KeyCredential("pgp4", "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD"));
    }

    @Test
    void extractCredentialsV6ProducesOpenpgp6(@TempDir Path tempDir) {
        BcRunner runner = createVerifyOnly(tempDir);
        OpenPgpVerifyResult result = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, "User <user@example.com>", "Ed25519",
                6, null, "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD");
        var creds = runner.extractCredentials(result);
        assertThat(creds).hasSize(1);
        assertThat(creds.get(0).type()).isEqualTo("pgp6");
    }

    @Test
    void extractCredentialsFailReturnsEmpty(@TempDir Path tempDir) {
        BcRunner runner = createVerifyOnly(tempDir);
        OpenPgpVerifyResult result = new OpenPgpVerifyResult(ClaimOutcome.FAILED, null, null, null, 4, null, null);
        assertThat(runner.extractCredentials(result).isEmpty()).isTrue();
    }

    @Test
    void signAndVerifyRoundTripEd25519(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        BcRunner runner = new BcRunner(store, null, null);

        String fingerprint = runner.generateKey("Test <test@example.com>", "ed25519", null);
        BcRunner signer = new BcRunner(store, fingerprint, null);

        Path artifact = tempDir.resolve("artifact.txt");
        Files.writeString(artifact, "test content");
        Path sigFile = tempDir.resolve("artifact.txt.asc");

        SignResult signResult = signer.sign(artifact, sigFile);
        assertThat(signResult.algorithm()).isNotNull();

        String armored = Files.readString(sigFile);
        OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);
        OpenPgpClaim claim = new OpenPgpClaim(
                armored, info.version(), info.issuerFingerprint(), info.algorithmId(), null);

        VerifyResult result = signer.verify(artifact, claim);
        assertThat(result.isVerified()).isTrue();
    }

    @Test
    void verifyFallsBackToKeyIdWhenFingerprintMissing(@TempDir Path tempDir) throws Exception {
        // Use ECDSA P-256 which produces v4 keys — the real scenario where
        // Issuer Fingerprint subpackets (type 33) are often absent
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        BcRunner runner = new BcRunner(store, null, null);

        String fingerprint = runner.generateKey("Test <test@example.com>", "nistp256", null);
        BcRunner signer = new BcRunner(store, fingerprint, null);

        Path artifact = tempDir.resolve("artifact.txt");
        Files.writeString(artifact, "test content");
        Path sigFile = tempDir.resolve("artifact.txt.asc");
        signer.sign(artifact, sigFile);

        String armored = Files.readString(sigFile);
        OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);

        // Create a claim with null fingerprint, simulating a v4 signature
        // without Issuer Fingerprint subpacket (type 33)
        OpenPgpClaim claimNoFp = new OpenPgpClaim(
                armored, info.version(), null, info.algorithmId(), null);

        // BC should extract the key ID from the signature bytes and find the key
        VerifyResult result = runner.verify(artifact, claimNoFp);
        assertThat(result.isVerified()).isTrue();

        // a 64-bit key ID proves nothing, so what is proven is the verifying key by its full
        // fingerprint, and the primary key it belongs to
        assertThat(runner.extractCredentials(result)).contains(KeyCredential.openPgp(fingerprint));
        assertThat(((OpenPgpVerifyResult) result).keySource().kind())
                .isEqualTo(TrustRootRef.KIND_OPENPGP_CERT_D);
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
        String fp = signerRunner.generateKey("Signer <signer@example.com>", "nistp256", null);
        BcRunner signer = new BcRunner(signerStore, fp, null);

        Path artifact = tempDir.resolve("artifact.txt");
        Files.writeString(artifact, "test content");
        Path sigFile = tempDir.resolve("artifact.txt.asc");
        signer.sign(artifact, sigFile);

        String armored = Files.readString(sigFile);
        OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);

        // Verify with null fingerprint against the empty store
        OpenPgpClaim claimNoFp = new OpenPgpClaim(
                armored, info.version(), null, info.algorithmId(), null);

        VerifyResult result = runner.verify(artifact, claimNoFp);
        assertThat(result.isIndeterminate(IndeterminateReason.KEY_UNAVAILABLE)).isTrue();
        assertThat(((OpenPgpVerifyResult) result).fingerprint()).isNotNull();
    }

    /**
     * Verifies that ephemeral key caching (via {@link BcKeyStore#addFetched})
     * allows subsequent verification to succeed, while no key file is written to
     * the cert-d directory on disk.
     *
     * <p>
     * This simulates the {@code importToKeyring=false} (default) flow: the key is
     * fetched for the current session only and discarded when the JVM exits.
     */
    @Test
    void ephemeralKeyCacheVerifiesWithoutPersisting(@TempDir Path tempDir) throws Exception {
        // Signer store: generate key and sign
        BcKeyStore signerStore = new BcKeyStore(null, tempDir.resolve("signer-cd"), tempDir.resolve("signer-bp"));
        BcRunner signerRunner = new BcRunner(signerStore, null, null);
        String fp = signerRunner.generateKey("Eph <eph@example.com>", "nistp256", null);
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
        // (fetchKey would call fetchKeyFromHkp which needs a real keyserver)
        var pubRing = signerStore.findPublicKey(fp).ring();
        verifierStore.addFetched(pubRing, "hkps://keys.example.org");

        String armored = Files.readString(sigFile);
        OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);
        OpenPgpClaim claim = new OpenPgpClaim(
                armored, info.version(), info.issuerFingerprint(), info.algorithmId(), null);

        VerifyResult result = verifier.verify(artifact, claim);
        assertThat(result.isVerified()).isTrue();
        assertThat(Files.exists(verifierCertD)).as("cert-d should not exist — key was ephemeral").isFalse();
    }

    @Test
    void verifyNoKeyReturnsNoKeyVerdict(@TempDir Path tempDir) throws Exception {
        BcRunner runner = createVerifyOnly(tempDir);
        OpenPgpClaim claim = new OpenPgpClaim(
                "-----BEGIN PGP SIGNATURE-----\nfake\n-----END PGP SIGNATURE-----\n",
                4, "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF", 27, null);

        VerifyResult result = runner.verify(tempDir.resolve("nonexistent"), claim);
        assertThat(result.isIndeterminate(IndeterminateReason.KEY_UNAVAILABLE)).isTrue();
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

        String fingerprint = runner.generateKey("Test <test@example.com>", "ed25519", null);
        PGPSecretKeyRing ring = store.findSecretKey(fingerprint);
        assertThat(ring).isNotNull();

        for (var keys = ring.getSecretKeys(); keys.hasNext();) {
            PGPSecretKey sk = keys.next();
            assertThat(sk.getKeyEncryptionAlgorithm()).as("Secret key should be encrypted")
                    .isNotEqualTo(SymmetricKeyAlgorithmTags.NULL);
        }
    }

    @Test
    void signAndVerifyWithEncryptedKey(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        PassphraseProvider provider = fixedPassphrase(TEST_PASSPHRASE);
        BcRunner runner = new BcRunner(store, null, null, provider);

        String fingerprint = runner.generateKey("Test <test@example.com>", "ed25519", null);
        BcRunner signer = new BcRunner(store, fingerprint, null, provider);

        Path artifact = tempDir.resolve("artifact.txt");
        Files.writeString(artifact, "encrypted key content");
        Path sigFile = tempDir.resolve("artifact.txt.asc");

        SignResult signResult = signer.sign(artifact, sigFile);
        assertThat(signResult.algorithm()).isNotNull();

        String armored = Files.readString(sigFile);
        OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);
        OpenPgpClaim claim = new OpenPgpClaim(
                armored, info.version(), info.issuerFingerprint(), info.algorithmId(), null);

        VerifyResult result = signer.verify(artifact, claim);
        assertThat(result.isVerified()).isTrue();
    }

    @Test
    void signWithEncryptedKeyNoProviderThrows(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        BcRunner generator = new BcRunner(store, null, null, fixedPassphrase(TEST_PASSPHRASE));
        String fingerprint = generator.generateKey("Test <test@example.com>", "ed25519", null);

        // signer has no passphrase provider
        BcRunner signer = new BcRunner(store, fingerprint, null);

        Path artifact = tempDir.resolve("artifact.txt");
        Files.writeString(artifact, "content");
        Path sigFile = tempDir.resolve("artifact.txt.asc");

        assertThatThrownBy(() -> signer.sign(artifact, sigFile))
                .isInstanceOf(ToolExecutionException.class)
                .hasMessageContaining("passphrase");
    }

    @Test
    void signWithWrongPassphraseThrows(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        BcRunner generator = new BcRunner(store, null, null, fixedPassphrase(TEST_PASSPHRASE));
        String fingerprint = generator.generateKey("Test <test@example.com>", "ed25519", null);

        BcRunner signer = new BcRunner(store, fingerprint, null,
                fixedPassphrase("wrong-passphrase".toCharArray()));

        Path artifact = tempDir.resolve("artifact.txt");
        Files.writeString(artifact, "content");
        Path sigFile = tempDir.resolve("artifact.txt.asc");

        assertThatThrownBy(() -> signer.sign(artifact, sigFile))
                .isInstanceOf(ToolExecutionException.class);
    }

    @Test
    void signWithNullPassphraseFromProviderThrows(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        BcRunner generator = new BcRunner(store, null, null, fixedPassphrase(TEST_PASSPHRASE));
        String fingerprint = generator.generateKey("Test <test@example.com>", "ed25519", null);

        BcRunner signer = new BcRunner(store, fingerprint, null, fp -> null);

        Path artifact = tempDir.resolve("artifact.txt");
        Files.writeString(artifact, "content");
        Path sigFile = tempDir.resolve("artifact.txt.asc");

        assertThatThrownBy(() -> signer.sign(artifact, sigFile))
                .isInstanceOf(ToolExecutionException.class)
                .hasMessageContaining("passphrase");
    }

    @Test
    void generateKeyNullPassphraseFromProviderStoresUnencrypted(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        BcRunner runner = new BcRunner(store, null, null, fp -> null);

        String fingerprint = runner.generateKey("Test <test@example.com>", "ed25519", null);
        PGPSecretKeyRing ring = store.findSecretKey(fingerprint);
        assertThat(ring).isNotNull();

        PGPSecretKey primary = ring.getSecretKey();
        assertThat(primary.getKeyEncryptionAlgorithm()).isEqualTo(SymmetricKeyAlgorithmTags.NULL);
    }

    @Test
    void generateKeyEmptyPassphraseStoresUnencrypted(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        BcRunner runner = new BcRunner(store, null, null, fp -> new char[0]);

        String fingerprint = runner.generateKey("Test <test@example.com>", "ed25519", null);
        PGPSecretKeyRing ring = store.findSecretKey(fingerprint);

        PGPSecretKey primary = ring.getSecretKey();
        assertThat(primary.getKeyEncryptionAlgorithm()).isEqualTo(SymmetricKeyAlgorithmTags.NULL);
    }

    @Test
    void signAndVerifyEncryptedKeyRsa(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        PassphraseProvider provider = fixedPassphrase(TEST_PASSPHRASE);
        BcRunner runner = new BcRunner(store, null, null, provider);

        String fingerprint = runner.generateKey("Test <test@example.com>", "rsa4096", null);
        BcRunner signer = new BcRunner(store, fingerprint, null, provider);

        Path artifact = tempDir.resolve("artifact.txt");
        Files.writeString(artifact, "rsa encrypted key");
        Path sigFile = tempDir.resolve("artifact.txt.asc");
        signer.sign(artifact, sigFile);

        String armored = Files.readString(sigFile);
        OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);
        OpenPgpClaim claim = new OpenPgpClaim(
                armored, info.version(), info.issuerFingerprint(), info.algorithmId(), null);

        assertThat(signer.verify(artifact, claim).isVerified()).isTrue();
    }

    @Test
    void signAndVerifyEncryptedKeyEcdsaV4(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        PassphraseProvider provider = fixedPassphrase(TEST_PASSPHRASE);
        BcRunner runner = new BcRunner(store, null, null, provider);

        String fingerprint = runner.generateKey("Test <test@example.com>", "nistp256", null);
        BcRunner signer = new BcRunner(store, fingerprint, null, provider);

        Path artifact = tempDir.resolve("artifact.txt");
        Files.writeString(artifact, "ecdsa v4 encrypted key");
        Path sigFile = tempDir.resolve("artifact.txt.asc");
        signer.sign(artifact, sigFile);

        String armored = Files.readString(sigFile);
        OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);
        OpenPgpClaim claim = new OpenPgpClaim(
                armored, info.version(), info.issuerFingerprint(), info.algorithmId(), null);

        assertThat(signer.verify(artifact, claim).isVerified()).isTrue();
    }

    @Test
    void builderPassphraseProviderThreadsToBcRunner(@TempDir Path tempDir) throws Exception {
        PassphraseProvider provider = fixedPassphrase(TEST_PASSPHRASE);

        String certD = tempDir.resolve("cert-d").toString();
        String bcPrivate = tempDir.resolve("bc-private").toString();

        // Generate an encrypted key via direct BcRunner
        BcKeyStore store = new BcKeyStore(null, Path.of(certD), Path.of(bcPrivate));
        BcRunner generator = new BcRunner(store, null, null, provider);
        String fingerprint = generator.generateKey("Test <test@example.com>", "ed25519", null);

        // Sign via Sigmund builder with bcPassphraseProvider — point to same key store
        try (Sigmund sigmund = Sigmund.builder()
                .bcPassphraseProvider(provider)
                .addSigningTool("bc", Map.of(
                        "signing-fingerprint", fingerprint,
                        "cert-d-home", certD,
                        "bc-private-home", bcPrivate))
                .build()) {

            Path artifact = tempDir.resolve("artifact.txt");
            Files.writeString(artifact, "builder test");

            SigningOutput output = sigmund.signer().sign(artifact, tempDir);
            assertThat(output.files().isEmpty()).isFalse();
        }
    }
}
