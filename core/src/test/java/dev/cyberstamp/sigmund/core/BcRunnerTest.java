package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.UserIDPacket;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.RevocationReasonTags;
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
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

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

        private String typeOf(BcKeyStore store, String fingerprint) {
            try (BcRunner runner = new BcRunner(store, fingerprint, null)) {
                return runner.signingInfo().get(0).credentialType();
            }
        }

        @Test
        void aNamedKeyMissingFromTheStoreIsTypedFromItsFingerprint(@TempDir Path dir) {
            String v4 = "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12";
            String v6 = "B".repeat(64);
            try (BcRunner runner = new BcRunner(store(dir), List.of(v4, v6), null, null, null, null,
                    BcRunner.DEFAULT_CIPHER_SUITE)) {

                List<SigningInfo> infos = runner.signingInfo();

                assertThat(infos).extracting(SigningInfo::fingerprint).containsExactly(v4, v6);
                assertThat(infos).extracting(SigningInfo::credentialType)
                        .containsExactly(Credential.TYPE_PGP4, Credential.TYPE_PGP6);
            }
        }

        @Test
        void anUnparseableTskFileGivesOneEntryOfUnknownType(@TempDir Path dir) throws IOException {
            Path tsk = Files.writeString(dir.resolve("broken.tsk"), "not a key");

            List<SigningInfo> infos;
            try (BcRunner runner = new BcRunner(store(dir), null, tsk)) {
                infos = runner.signingInfo();
            }

            assertThat(infos).hasSize(1);
            assertThat(infos.get(0).fingerprint()).isEqualTo("broken.tsk");
            assertThat(infos.get(0).credentialType()).isNull();
        }

        @Test
        void withoutACredentialTypeTheKeyIsV4(@TempDir Path dir) {
            BcKeyStore store = store(dir);

            String fingerprint = BcTestKeys.generate(store, "A <a@example.com>", "ed25519", null);

            assertThat(fingerprint).hasSize(40);
            assertThat(typeOf(store, fingerprint)).isEqualTo(Credential.TYPE_PGP4);
        }

        @Test
        void aV4Ed25519KeyUsesTheLegacyEncodingGnuPgReads(@TempDir Path dir) {
            BcKeyStore store = store(dir);
            try (BcRunner runner = new BcRunner(store, null, null)) {

                String fingerprint = runner.generateKey("A <a@example.com>", "ed25519", Credential.TYPE_PGP4);

                PGPPublicKeyRing ring = store.findPublicKey(fingerprint).ring();
                ring.getPublicKeys().forEachRemaining(key -> assertThat(key.getAlgorithm())
                        .isEqualTo(PublicKeyAlgorithmTags.EDDSA_LEGACY));
            }
        }

        /**
         * A keyserver may serve the user's own key with a user ID put first that the key's own
         * certificate does not carry; the description shows the user ID of the key itself.
         */
        @Test
        void theOwnKeyIsDescribedByItsOwnUserIdNotOneAFetchedCopyPutFirst(@TempDir Path dir) throws Exception {
            BcKeyStore store = store(dir);
            String fingerprint = BcTestKeys.generate(store, "Own <own@example.org>", "ed25519", null);
            BcTestKeys.addFetched(store, Map.of("hkps://keyserver.example.org",
                    withUserIdFirst(store, fingerprint, "Added <added@example.org>")));
            assertThat(store.findPublicKey(fingerprint).ring().getPublicKey().getUserIDs().next())
                    .isEqualTo("Added <added@example.org>");

            try (BcRunner runner = new BcRunner(store, fingerprint, null)) {
                assertThat(runner.signingInfo().get(0).userId()).isEqualTo("Own <own@example.org>");
            }
        }

        private PGPPublicKeyRing withUserIdFirst(BcKeyStore store, String fingerprint, String added) throws Exception {
            PGPPublicKeyRing ring = store.findPublicKey(fingerprint).ring();
            PGPPublicKey primary = ring.getPublicKey();
            String own = primary.getUserIDs().next();
            List<PGPSignature> ownSignatures = new ArrayList<>();
            primary.getSignaturesForID(own).forEachRemaining(ownSignatures::add);
            PGPSecretKey secret = store.findSecretKey(fingerprint).getSecretKey();
            PGPSignatureGenerator generator = new PGPSignatureGenerator(
                    new BcPGPContentSignerBuilder(primary.getAlgorithm(), HashAlgorithmTags.SHA256), primary);
            generator.init(PGPSignature.POSITIVE_CERTIFICATION, secret.extractPrivateKey(null));
            PGPPublicKey reordered = PGPPublicKey.addCertification(PGPPublicKey.removeCertification(primary, own),
                    added, generator.generateCertification(added, primary));
            for (PGPSignature signature : ownSignatures) {
                reordered = PGPPublicKey.addCertification(reordered, own, signature);
            }
            return PGPPublicKeyRing.insertPublicKey(ring, reordered);
        }

        @Test
        void pgp6GivesAV6Key(@TempDir Path dir) {
            BcKeyStore store = store(dir);

            String fingerprint = BcTestKeys.generate(store, "A <a@example.com>", "ed25519", Credential.TYPE_PGP6);

            assertThat(fingerprint).hasSize(64);
            assertThat(typeOf(store, fingerprint)).isEqualTo(Credential.TYPE_PGP6);
        }

        @Test
        void anEcdsaKeyCannotBeV6(@TempDir Path dir) {
            assertThatThrownBy(() -> BcTestKeys.generate(store(dir), "A <a@example.com>", "nistp256", Credential.TYPE_PGP6))
                    .isInstanceOf(ToolExecutionException.class)
                    .hasMessageContaining("nistp256 produces v4 keys only");
        }

        @Test
        void anEd448KeyIsV6Only(@TempDir Path dir) {
            assertThatThrownBy(() -> BcTestKeys.generate(store(dir), "A <a@example.com>", "ed448", null))
                    .isInstanceOf(ToolExecutionException.class)
                    .hasMessageContaining("ed448 produces pgp6 keys only");
        }

        @Test
        void anUnknownCredentialTypeIsRejected(@TempDir Path dir) {
            assertThatThrownBy(() -> BcTestKeys.generate(store(dir), "A <a@example.com>", "ed25519", "sigstore"))
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
                SigningTests.signWithOnlyKey(signer, artifact, signature);

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

        /**
         * A block that holds no signature, checked against a key the store holds, names no signer:
         * nothing in it was made by that key.
         */
        @Test
        void aBlockHoldingNoSignatureIsMalformedAndNamesNoSigner(@TempDir Path tempDir) throws Exception {
            BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
            String fingerprint = BcTestKeys.generate(store, "Signer <signer@example.org>", "ed25519", null);
            String notASignature = AscCombiner.armor(store.findPublicKey(fingerprint).ring().getEncoded());
            Path artifact = Files.writeString(tempDir.resolve("artifact.txt"), "content");

            try (BcRunner runner = new BcRunner(store, null, null)) {
                VerifyResult result = runner.verify(artifact, new OpenPgpClaim(notASignature, 4, fingerprint, 22, null));

                assertThat(result.isIndeterminate(IndeterminateReason.EVIDENCE_MALFORMED)).isTrue();
                assertThat(result.signerDisplayName()).isNull();
            }
        }

        /**
         * A signature packet cut short, which Bouncy Castle breaks on while checking it against a
         * key the store holds, names no signer either.
         */
        @Test
        void aBlockBouncyCastleBreaksOnNamesNoSigner(@TempDir Path tempDir) throws Exception {
            BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
            String fingerprint = BcTestKeys.generate(store, "Signer <signer@example.org>", "ed25519", null);
            Path artifact = Files.writeString(tempDir.resolve("artifact.txt"), "content");

            try (BcRunner runner = new BcRunner(store, null, null)) {
                String truncatedSignature = AscCombiner.armor(new byte[] { (byte) 0xC2, 0x10, 0x04 });
                VerifyResult result = runner.verify(artifact,
                        new OpenPgpClaim(truncatedSignature, 4, fingerprint, 22, null));

                assertThat(result.isIndeterminate(IndeterminateReason.TOOL_UNAVAILABLE))
                        .as(result.outcome() + " " + result.reason()).isTrue();
                assertThat(result.signerDisplayName()).isNull();
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
            BcTestKeys.addFetched(store, Map.of("hkps://keys.example.org", certificate));
            Path artifact = Files.writeString(tempDir.resolve("artifact.txt"), "content");
            OpenPgpClaim claim = lowLevelSignature(subkey.getPublicKey(), subkey.getPrivateKey(),
                    artifact, HashAlgorithmTags.SHA256, Instant.now());

            try (BcRunner bcRunner = new BcRunner(store, null, null)) {
                VerifyResult result = bcRunner.verify(artifact, claim);

                assertThat(result.isIndeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM))
                        .as(result.outcome() + " " + result.reason()).isTrue();
            }
        }

        @Test
        void aRevokedKeyFailsNamingTheKeyserversThatServedTheRevocation(@TempDir Path tempDir)
                throws Exception {
            PGPKeyPair primary = rsaKeyPair();
            PGPPublicKey revokedKey = PGPPublicKey.addCertification(
                    keyRing(primary, null, HashAlgorithmTags.SHA256).generatePublicKeyRing().getPublicKey(),
                    revocation(primary));
            PGPPublicKeyRing certificate = new PGPPublicKeyRing(List.of(revokedKey));
            BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"),
                    tempDir.resolve("bc-private"));
            BcTestKeys.addFetched(store, Map.of("hkps://keys.example.org", certificate));
            Path artifact = Files.writeString(tempDir.resolve("artifact.txt"), "content");
            OpenPgpClaim claim = lowLevelSignature(primary.getPublicKey(), primary.getPrivateKey(),
                    artifact, HashAlgorithmTags.SHA256, Instant.now());

            try (BcRunner bcRunner = new BcRunner(store, null, null)) {
                VerifyResult result = bcRunner.verify(artifact, claim);

                assertThat(result.isFailed()).as(result.outcome() + " " + result.reason()).isTrue();
                assertThat(result.detail()).startsWith("key revoked as compromised on ")
                        .endsWith("; revocation served by hkps://keys.example.org");
            }
        }

        @Test
        void aForgedRevocationNextToARealOneNeverSuppliesTheDetail(@TempDir Path tempDir) throws Exception {
            Instant now = Instant.now();
            PGPKeyPair primary = rsaKeyPair();
            PGPKeyPair forger = rsaKeyPair();
            PGPPublicKey base = keyRing(primary, null, HashAlgorithmTags.SHA256).generatePublicKeyRing()
                    .getPublicKey();
            PGPPublicKey revokedKey = PGPPublicKey.addCertification(
                    PGPPublicKey.addCertification(base, revocation(forger, primary, now.minusSeconds(900),
                            RevocationReasonTags.KEY_SUPERSEDED)),
                    revocation(primary, primary, now.minusSeconds(1800),
                            RevocationReasonTags.KEY_COMPROMISED));
            BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"),
                    tempDir.resolve("bc-private"));
            BcTestKeys.addFetched(store, Map.of("hkps://keys.example.org", new PGPPublicKeyRing(List.of(revokedKey))));
            Path artifact = Files.writeString(tempDir.resolve("artifact.txt"), "content");
            OpenPgpClaim claim = lowLevelSignature(primary.getPublicKey(), primary.getPrivateKey(),
                    artifact, HashAlgorithmTags.SHA256, now);

            try (BcRunner bcRunner = new BcRunner(store, null, null)) {
                VerifyResult result = bcRunner.verify(artifact, claim);

                assertThat(result.isFailed()).as(result.outcome() + " " + result.reason()).isTrue();
                assertThat(result.detail()).startsWith("key revoked as compromised on "
                        + now.minusSeconds(1800).atZone(ZoneOffset.UTC).toLocalDate());
            }
        }

        @ParameterizedTest(name = "reason {0}")
        @CsvSource({ "1, superseded", "3, retired", "50, no reason given" })
        void aRevocationIsNamedByItsReason(int reason, String named, @TempDir Path tempDir) throws Exception {
            PGPKeyPair primary = rsaKeyPair();
            BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
            BcTestKeys.addFetched(store, Map.of("hkps://keys.example.org", revokedCertificate(primary, reason)));

            VerifyResult result = verifySignedNow(tempDir, store, primary);

            assertThat(result.isFailed()).as(result.outcome() + " " + result.reason()).isTrue();
            assertThat(result.detail()).startsWith("key revoked as " + named + " on ");
        }

        @Test
        void aRevocationServedBySeveralKeyserversNamesEach(@TempDir Path tempDir) throws Exception {
            PGPKeyPair primary = rsaKeyPair();
            PGPPublicKeyRing certificate = revokedCertificate(primary, RevocationReasonTags.KEY_COMPROMISED);
            BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
            Map<String, PGPPublicKeyRing> copies = new LinkedHashMap<>();
            copies.put("hkps://one.example.org", certificate);
            copies.put("hkps://two.example.org", certificate);
            BcTestKeys.addFetched(store, copies);

            VerifyResult result = verifySignedNow(tempDir, store, primary);

            assertThat(result.detail())
                    .endsWith("; revocation served by hkps://one.example.org, hkps://two.example.org");
        }

        @Test
        void aRevocationFromALocalStoreNamesNoKeyserver(@TempDir Path tempDir) throws Exception {
            PGPKeyPair primary = rsaKeyPair();
            BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
            store.storeCert(revokedCertificate(primary, RevocationReasonTags.KEY_COMPROMISED));

            VerifyResult result = verifySignedNow(tempDir, store, primary);

            assertThat(result.isFailed()).as(result.outcome() + " " + result.reason()).isTrue();
            assertThat(result.detail()).startsWith("key revoked as compromised on ").doesNotContain("served by");
        }

        /**
         * A revocation the key's holder made but placed where its type does not belong — a subkey
         * revocation (0x28) on the primary key, a key revocation (0x20) on a subkey — revokes
         * nothing: GnuPG and Sequoia ignore it. Each is made over the data its place is checked
         * against — the primary key alone, or the primary key and the subkey — so only its type
         * is out of place. The binding view drops it: besides its own type check, Bouncy Castle's
         * {@code verifyCertification} refuses a signature whose type does not fit the keys it is
         * checked over, and Bouncy Castle's certificate does not read either as a revocation.
         */
        @ParameterizedTest(name = "on the primary key: {0}")
        @ValueSource(booleans = { true, false })
        void aRevocationOfTheWrongTypeForItsKeyIsDropped(boolean onPrimary, @TempDir Path tempDir) throws Exception {
            PGPKeyPair primary = rsaKeyPair();
            PGPKeyPair subkey = rsaKeyPair();
            PGPPublicKeyRing ring = keyRing(primary, subkey, HashAlgorithmTags.SHA256).generatePublicKeyRing();
            PGPSignatureGenerator generator = new PGPSignatureGenerator(
                    new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA256),
                    primary.getPublicKey());
            generator.init(onPrimary ? PGPSignature.SUBKEY_REVOCATION : PGPSignature.KEY_REVOCATION,
                    primary.getPrivateKey());
            PGPSignatureSubpacketGenerator hashed = new PGPSignatureSubpacketGenerator();
            hashed.setSignatureCreationTime(true, Date.from(Instant.now().minusSeconds(1800)));
            hashed.setIssuerFingerprint(false, primary.getPublicKey());
            hashed.setRevocationReason(false, RevocationReasonTags.KEY_COMPROMISED, "revoked");
            generator.setHashedSubpackets(hashed.generate());
            PGPPublicKey subkeyInRing = ring.getPublicKey(subkey.getKeyID());
            PGPSignature revocation = onPrimary ? generator.generateCertification(primary.getPublicKey())
                    : generator.generateCertification(primary.getPublicKey(), subkeyInRing);
            PGPPublicKeyRing misplaced = withSignatureAfter(ring, onPrimary ? ring.getPublicKey() : subkeyInRing,
                    revocation);
            BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
            store.storeCert(misplaced);

            VerifyResult result = verifySignedNow(tempDir, store, subkey);

            assertThat(result.isVerified()).as(result.outcome() + " " + result.detail()).isTrue();
        }

        /**
         * The certificate with a signature placed right after a key's packet, written as packets
         * because Bouncy Castle will not add a revocation to a key of the wrong kind.
         */
        private static PGPPublicKeyRing withSignatureAfter(PGPPublicKeyRing ring, PGPPublicKey key,
                PGPSignature signature) throws Exception {
            ByteArrayOutputStream keyPacket = new ByteArrayOutputStream();
            try (BCPGOutputStream out = new BCPGOutputStream(keyPacket)) {
                out.writePacket(key.getPublicKeyPacket());
            }
            byte[] encoded = ring.getEncoded();
            byte[] packet = keyPacket.toByteArray();
            int end = indexOf(encoded, packet) + packet.length;
            ByteArrayOutputStream spliced = new ByteArrayOutputStream();
            spliced.write(encoded, 0, end);
            spliced.write(signature.getEncoded());
            spliced.write(encoded, end, encoded.length - end);
            return new PGPPublicKeyRing(spliced.toByteArray(), new JcaKeyFingerprintCalculator());
        }

        private static int indexOf(byte[] bytes, byte[] wanted) {
            for (int i = 0; i + wanted.length <= bytes.length; i++) {
                if (Arrays.equals(bytes, i, i + wanted.length, wanted, 0, wanted.length)) {
                    return i;
                }
            }
            throw new IllegalArgumentException("packet not found");
        }

        private static PGPPublicKeyRing revokedCertificate(PGPKeyPair primary, int reason) throws Exception {
            PGPPublicKey revokedKey = PGPPublicKey.addCertification(
                    keyRing(primary, null, HashAlgorithmTags.SHA256).generatePublicKeyRing().getPublicKey(),
                    revocation(primary, primary, Instant.now().minusSeconds(1800), reason));
            return new PGPPublicKeyRing(List.of(revokedKey));
        }

        private static VerifyResult verifySignedNow(Path tempDir, BcKeyStore store, PGPKeyPair signer)
                throws Exception {
            Path artifact = Files.writeString(tempDir.resolve("artifact.txt"), "content");
            OpenPgpClaim claim = lowLevelSignature(signer.getPublicKey(), signer.getPrivateKey(),
                    artifact, HashAlgorithmTags.SHA256, Instant.now());
            try (BcRunner bcRunner = new BcRunner(store, null, null)) {
                return bcRunner.verify(artifact, claim);
            }
        }

        private static PGPSignature revocation(PGPKeyPair primary) throws Exception {
            return revocation(primary, primary, Instant.now().minusSeconds(1),
                    RevocationReasonTags.KEY_COMPROMISED);
        }

        private static PGPSignature revocation(PGPKeyPair signer, PGPKeyPair subject, Instant at, int reason)
                throws Exception {
            PGPSignatureGenerator generator = new PGPSignatureGenerator(
                    new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_GENERAL,
                            HashAlgorithmTags.SHA256),
                    signer.getPublicKey());
            generator.init(PGPSignature.KEY_REVOCATION, signer.getPrivateKey());
            PGPSignatureSubpacketGenerator hashed = new PGPSignatureSubpacketGenerator();
            hashed.setSignatureCreationTime(true, Date.from(at));
            hashed.setIssuerFingerprint(false, subject.getPublicKey());
            hashed.setRevocationReason(false, (byte) reason, "revoked");
            generator.setHashedSubpackets(hashed.generate());
            return generator.generateCertification(subject.getPublicKey());
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

    @Nested
    class DisplayedUserId {

        private static final String DIRECTORY = "hkps://keys.openpgp.org";

        @Test
        void anUnboundUserIdIsNeverShown(@TempDir Path tempDir) throws Exception {
            PGPKeyPair primary = rsaKeyPair();
            PGPPublicKeyRing certificate = certificate(primary,
                    userId("Intruder <intruder@example.org>", null),
                    userId("Signer <signer@example.org>", certify(primary, "Signer <signer@example.org>", false)));

            assertThat(displayedFor(tempDir, primary, Map.of(DIRECTORY, certificate)))
                    .isEqualTo("Signer <signer@example.org>");
        }

        @Test
        void aRevokedUserIdIsNeverShown(@TempDir Path tempDir) throws Exception {
            PGPKeyPair primary = rsaKeyPair();
            byte[] revoked = bytes("Old <old@example.org>");
            PGPPublicKeyRing certificate = certificate(primary,
                    userId("Old <old@example.org>", certify(primary, "Old <old@example.org>", false),
                            revokeCertification(primary, revoked)),
                    userId("Signer <signer@example.org>", certify(primary, "Signer <signer@example.org>", false)));

            assertThat(displayedFor(tempDir, primary, Map.of(DIRECTORY, certificate)))
                    .isEqualTo("Signer <signer@example.org>");
        }

        @Test
        void aDirectoryServedUserIdIsPreferredOverThePrimary(@TempDir Path tempDir) throws Exception {
            PGPKeyPair primary = rsaKeyPair();
            PGPPublicKeyRing directoryCopy = certificate(primary,
                    userId("Verified <verified@example.org>", certify(primary, "Verified <verified@example.org>", false)));
            PGPPublicKeyRing otherCopy = certificate(primary,
                    userId("Verified <verified@example.org>", certify(primary, "Verified <verified@example.org>", false)),
                    userId("Primary <primary@example.org>", certify(primary, "Primary <primary@example.org>", true)));
            Map<String, PGPPublicKeyRing> copies = new LinkedHashMap<>();
            copies.put("hkps://keyserver.example.org", otherCopy);
            copies.put(DIRECTORY, directoryCopy);

            assertThat(displayedFor(tempDir, primary, copies)).isEqualTo("Verified <verified@example.org>");
        }

        @Test
        void aLookupByKeyIdPrefersTheDirectoryServedUserIdAsAFingerprintLookupDoes(@TempDir Path tempDir)
                throws Exception {
            PGPKeyPair primary = rsaKeyPair();
            PGPPublicKeyRing directoryCopy = certificate(primary,
                    userId("Verified <verified@example.org>", certify(primary, "Verified <verified@example.org>", false)));
            PGPPublicKeyRing otherCopy = certificate(primary,
                    userId("Verified <verified@example.org>", certify(primary, "Verified <verified@example.org>", false)),
                    userId("Primary <primary@example.org>", certify(primary, "Primary <primary@example.org>", true)));
            Map<String, PGPPublicKeyRing> copies = new LinkedHashMap<>();
            copies.put("hkps://keyserver.example.org", otherCopy);
            copies.put(DIRECTORY, directoryCopy);
            BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
            BcTestKeys.addFetched(store, copies);
            String fingerprint = KeyRingFiles.hex(primary.getPublicKey().getFingerprint());

            try (BcRunner runner = new BcRunner(store, null, null)) {
                assertThat(runner.lookupKeyUserId(fingerprint)).isEqualTo("Verified <verified@example.org>");
                assertThat(runner.lookupKeyUserId(fingerprint.substring(fingerprint.length() - 16)))
                        .isEqualTo("Verified <verified@example.org>");
            }
        }

        @Test
        void thePrimaryIsShownForAKeyFromALocalStore(@TempDir Path tempDir) throws Exception {
            PGPKeyPair primary = rsaKeyPair();
            PGPPublicKeyRing certificate = certificate(primary,
                    userId("First <first@example.org>", certify(primary, "First <first@example.org>", false)),
                    userId("Primary <primary@example.org>", certify(primary, "Primary <primary@example.org>", true)));
            BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
            store.storeCert(certificate);

            assertThat(displayed(tempDir, store, primary)).isEqualTo("Primary <primary@example.org>");
        }

        private static String displayedFor(Path tempDir, PGPKeyPair primary,
                Map<String, PGPPublicKeyRing> copies) throws Exception {
            BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
            BcTestKeys.addFetched(store, copies);
            return displayed(tempDir, store, primary);
        }

        private static String displayed(Path tempDir, BcKeyStore store, PGPKeyPair primary) throws Exception {
            Path artifact = Files.writeString(tempDir.resolve("artifact.txt"), "content");
            OpenPgpClaim claim = lowLevelSignature(primary.getPublicKey(), primary.getPrivateKey(),
                    artifact, HashAlgorithmTags.SHA256, Instant.now());
            try (BcRunner runner = new BcRunner(store, null, null)) {
                VerifyResult result = runner.verify(artifact, claim);
                assertThat(result.isVerified()).as(result.outcome() + " " + result.reason()).isTrue();
                return result.signerDisplayName();
            }
        }

        private record UserIdEntry(byte[] id, List<PGPSignature> signatures) {
        }

        private static UserIdEntry userId(String id, PGPSignature certification, PGPSignature... more) {
            return userId(bytes(id), certification, more);
        }

        private static UserIdEntry userId(byte[] id, PGPSignature certification, PGPSignature... more) {
            List<PGPSignature> signatures = new ArrayList<>();
            if (certification != null) {
                signatures.add(certification);
            }
            signatures.addAll(List.of(more));
            return new UserIdEntry(id, signatures);
        }

        private static byte[] bytes(String id) {
            return id.getBytes(StandardCharsets.UTF_8);
        }

        private static PGPPublicKeyRing certificate(PGPKeyPair primary, UserIdEntry... entries) throws Exception {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            BCPGOutputStream out = new BCPGOutputStream(bytes);
            out.writePacket(primary.getPublicKey().getPublicKeyPacket());
            for (UserIdEntry entry : entries) {
                out.writePacket(new UserIDPacket(entry.id()));
                for (PGPSignature signature : entry.signatures()) {
                    signature.encode(out);
                }
            }
            out.close();
            return new PGPPublicKeyRing(bytes.toByteArray(), new JcaKeyFingerprintCalculator());
        }

        private static PGPSignature certify(PGPKeyPair primary, String id, boolean primaryUserId) throws Exception {
            return certify(primary, bytes(id), primaryUserId);
        }

        private static PGPSignature certify(PGPKeyPair primary, byte[] id, boolean primaryUserId) throws Exception {
            PGPSignatureSubpacketGenerator hashed = new PGPSignatureSubpacketGenerator();
            hashed.setSignatureCreationTime(true, Date.from(Instant.now().minusSeconds(3000)));
            hashed.setIssuerFingerprint(false, primary.getPublicKey());
            hashed.setKeyFlags(false, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA);
            if (primaryUserId) {
                hashed.setPrimaryUserID(true, true);
            }
            return userIdSignature(primary, PGPSignature.POSITIVE_CERTIFICATION, id, hashed);
        }

        private static PGPSignature revokeCertification(PGPKeyPair primary, byte[] id) throws Exception {
            PGPSignatureSubpacketGenerator hashed = new PGPSignatureSubpacketGenerator();
            hashed.setSignatureCreationTime(true, Date.from(Instant.now().minusSeconds(2000)));
            hashed.setIssuerFingerprint(false, primary.getPublicKey());
            hashed.setRevocationReason(false, RevocationReasonTags.USER_NO_LONGER_VALID, "retired");
            return userIdSignature(primary, PGPSignature.CERTIFICATION_REVOCATION, id, hashed);
        }

        private static PGPSignature userIdSignature(PGPKeyPair primary, int type, byte[] id,
                PGPSignatureSubpacketGenerator hashed) throws Exception {
            PGPSignatureGenerator generator = new PGPSignatureGenerator(
                    new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA256),
                    primary.getPublicKey());
            generator.init(type, primary.getPrivateKey());
            generator.setHashedSubpackets(hashed.generate());
            generator.update(certifiedKey(primary.getPublicKey()));
            generator.update(userIdHeader(id));
            generator.update(id);
            return generator.generate();
        }

        private static byte[] certifiedKey(PGPPublicKey key) throws Exception {
            byte[] body = key.getPublicKeyPacket().getEncodedContents();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(0x99);
            out.write(body.length >> 8);
            out.write(body.length);
            out.write(body);
            return out.toByteArray();
        }

        private static byte[] userIdHeader(byte[] id) {
            return new byte[] { (byte) 0xB4, (byte) (id.length >> 24), (byte) (id.length >> 16),
                    (byte) (id.length >> 8), (byte) id.length };
        }

        private static PGPKeyPair rsaKeyPair() throws Exception {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", new BouncyCastleProvider());
            generator.initialize(2048, new SecureRandom());
            return new JcaPGPKeyPair(PublicKeyPacket.VERSION_4, PublicKeyAlgorithmTags.RSA_GENERAL,
                    generator.generateKeyPair(), Date.from(Instant.now().minusSeconds(3600)));
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
            try (BcRunner runner = new BcRunner(emptyStore(), null, exportTsk("signer", fp))) {

                VerifyResult result = runner.verify(artifact(), signWith(runner));

                assertThat(result.isVerified()).isTrue();
                assertThat(((OpenPgpVerifyResult) result).primaryFingerprint()).isEqualTo(fp);
            }
        }

        @Test
        void anotherKeyIsStillNotFound() throws Exception {
            try (BcRunner runner = new BcRunner(emptyStore(), null,
                    exportTsk("signer", generate("signer")))) {
                signWith(runner);
                String otherFp = generate("other");
                try (BcRunner other = new BcRunner(store("other"), otherFp, null)) {

                    VerifyResult result = runner.verify(artifact(), signWith(other));

                    assertThat(result.isIndeterminate(IndeterminateReason.KEY_UNAVAILABLE)).isTrue();
                }
            }
        }

        private OpenPgpClaim signWith(BcRunner signer) throws IOException {
            Path content = Files.writeString(artifact(), "test content");
            Path signature = dir.resolve("artifact.txt.asc");
            SigningTests.signWithOnlyKey(signer, content, signature);
            return (OpenPgpClaim) new OpenPgpSignatureFormat()
                    .parse(Evidence.read(signature, Evidence.SOURCE_SIDECAR)).get(0);
        }

        private String generate(String name) {
            return BcTestKeys.generate(store(name), "Test <" + name + "@example.com>", "ed25519", null);
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

    /**
     * One reason, {@code KEY_UNAVAILABLE}, covers keys an operator resolves differently; the
     * detail says which, so a report can tell a key nobody publishes from one served without
     * the self-signature that binds it.
     */
    @Nested
    class UnavailableKeyDetail {

        @TempDir
        Path dir;

        @Test
        void aKeyNoStoreHasWithFetchingOffSaysSo() throws Exception {
            Signed signed = sign();
            try (BcRunner verifier = new BcRunner(emptyStore(), null, null)) {

                OpenPgpVerifyResult result = (OpenPgpVerifyResult) verifier.verify(signed.artifact(), signed.claim());

                assertThat(result.isIndeterminate(IndeterminateReason.KEY_UNAVAILABLE)).isTrue();
                assertThat(result.detail()).isEqualTo("no local key store has it, and key fetching is off");
            }
        }

        @Test
        void aSignatureNamingOnlyAKeyIdSaysItIsNotLookedUp() throws Exception {
            Signed signed = sign();
            OpenPgpClaim keyIdOnly = new OpenPgpClaim(signed.claim().armoredBlock(),
                    signed.claim().packetVersion(), null, signed.claim().algorithmId(), null);
            try (BcRunner verifier = new BcRunner(emptyStore(), null, null)) {

                OpenPgpVerifyResult result = (OpenPgpVerifyResult) verifier.verify(signed.artifact(), keyIdOnly);

                assertThat(result.detail())
                        .isEqualTo("the signature names only a key ID, which is not looked up on keyservers");
            }
        }

        @Test
        void aCopyWithoutSelfSignaturesNamesWhereItCameFrom() throws Exception {
            Signed signed = sign();
            BcKeyStore store = emptyStore();
            BcTestKeys.addFetched(store, Map.of("hkps://keys.example.org",
                    withoutSelfSignatures(signed.store().findPublicKey(signed.fingerprint()).ring())));
            try (BcRunner verifier = new BcRunner(store, null, null)) {

                OpenPgpVerifyResult result = (OpenPgpVerifyResult) verifier.verify(signed.artifact(), signed.claim());

                assertThat(result.isIndeterminate(IndeterminateReason.KEY_UNAVAILABLE)).isTrue();
                assertThat(result.detail())
                        .isEqualTo("the copy from hkps://keys.example.org carries no self-signature binding the key");
            }
        }

        private record Signed(BcKeyStore store, String fingerprint, Path artifact, OpenPgpClaim claim) {
        }

        private Signed sign() throws IOException {
            BcKeyStore store = new BcKeyStore(null, dir.resolve("signer-cert-d"), dir.resolve("signer-bc"));
            String fingerprint = BcTestKeys.generate(store, "Signer <signer@example.com>",
                    "ed25519", null);
            Path artifact = Files.writeString(dir.resolve("artifact.txt"), "content");
            Path signature = dir.resolve("artifact.txt.asc");
            try (BcRunner signer = new BcRunner(store, fingerprint, null)) {
                SigningTests.signWithOnlyKey(signer, artifact, signature);
            }
            OpenPgpClaim claim = (OpenPgpClaim) new OpenPgpSignatureFormat()
                    .parse(Evidence.read(signature, Evidence.SOURCE_SIDECAR)).get(0);
            return new Signed(store, fingerprint, artifact, claim);
        }

        private BcKeyStore emptyStore() {
            return new BcKeyStore(null, dir.resolve("verifier-cert-d"), dir.resolve("verifier-bc"));
        }

        /**
         * The certificate with no self-signature on its primary key: its user IDs removed, as
         * keys.openpgp.org serves a key whose owner never verified an address, and its direct-key
         * signature too, which keys generated before RFC 9580 lack.
         */
        private PGPPublicKeyRing withoutSelfSignatures(PGPPublicKeyRing ring) {
            List<PGPPublicKey> keys = new ArrayList<>();
            ring.getPublicKeys().forEachRemaining(keys::add);
            PGPPublicKey primary = keys.get(0);
            Iterator<byte[]> ids = primary.getRawUserIDs();
            while (ids.hasNext()) {
                primary = PGPPublicKey.removeCertification(primary, ids.next());
            }
            Iterator<PGPSignature> directKey = primary.getSignaturesOfType(PGPSignature.DIRECT_KEY);
            while (directKey.hasNext()) {
                primary = PGPPublicKey.removeCertification(primary, directKey.next());
            }
            keys.set(0, primary);
            return new PGPPublicKeyRing(keys);
        }
    }

    /**
     * A secret key leaves the store armored, as an environment variable such as
     * {@code SIGMUND_BC_SIGNING_KEY} or a {@code tsk-file} takes it, and signs again from there.
     */
    @Nested
    class SecretKeyExport {

        @TempDir
        Path dir;

        @Test
        void anExportedSecretKeySignsFromATskFile() throws Exception {
            BcKeyStore store = new BcKeyStore(null, dir.resolve("cert-d"), dir.resolve("bc-private"));
            String fingerprint = BcTestKeys.generate(store, "CI <ci@example.com>", "ed25519", null);

            String armored;
            try (BcRunner exporter = new BcRunner(store, null, null)) {
                armored = exporter.exportSecretKey(fingerprint);
            }

            assertThat(armored).startsWith("-----BEGIN PGP PRIVATE KEY BLOCK-----");
            Path tsk = Files.writeString(dir.resolve("key.asc"), armored);
            BcKeyStore empty = new BcKeyStore(null, dir.resolve("empty-cert-d"), dir.resolve("empty-bc"));
            try (BcRunner signer = new BcRunner(empty, null, tsk)) {
                assertThat(signer.signingInfo()).extracting(SigningInfo::fingerprint).containsExactly(fingerprint);
                Path artifact = Files.writeString(dir.resolve("artifact.txt"), "content");
                SigningTests.signWithOnlyKey(signer, artifact, dir.resolve("artifact.txt.asc"));
                assertThat(dir.resolve("artifact.txt.asc")).exists();
            }
        }

        @Test
        void aKeyWithoutASecretInTheStoreIsAnError() {
            BcKeyStore store = new BcKeyStore(null, dir.resolve("cert-d"), dir.resolve("bc-private"));

            try (BcRunner exporter = new BcRunner(store, null, null)) {
                assertThatThrownBy(() -> exporter.exportSecretKey("0123456789ABCDEF0123456789ABCDEF01234567"))
                        .isInstanceOf(ToolExecutionException.class)
                        .hasMessageContaining("0123456789ABCDEF0123456789ABCDEF01234567");
            }
        }
    }

    @Nested
    class MultipleKeys {

        @TempDir
        Path dir;

        @Test
        void eachKeySignsWithItself() throws Exception {
            BcKeyStore store = store();
            String fp1 = generate(store, "one");
            String fp2 = generate(store, "two");
            try (BcRunner runner = runner(store, fp1, fp2)) {

                List<SigningInfo> keys = runner.signingInfo();

                assertThat(keys).extracting(SigningInfo::fingerprint).containsExactly(fp1, fp2);
                for (SigningInfo key : keys) {
                    assertThat(provenBy(runner, key)).contains(KeyCredential.openPgp(key.fingerprint()));
                }
            }
        }

        @Test
        void aKeyOutsideTheListIsRejected() throws Exception {
            BcKeyStore store = store();
            String fp1 = generate(store, "one");
            String outside = generate(store, "outside");
            try (BcRunner runner = runner(store, fp1)) {
                Path artifact = Files.writeString(dir.resolve("artifact.txt"), "content");

                assertThatThrownBy(() -> runner.sign(artifact, dir.resolve("artifact.txt.asc"),
                        new SigningInfo("bc", outside, null, null, "pgp4")))
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("bc")
                        .hasMessageContaining(outside);
            }
        }

        private List<Credential> provenBy(BcRunner runner, SigningInfo key) throws IOException {
            Path artifact = Files.writeString(dir.resolve("artifact.txt"), "content");
            Path signature = dir.resolve("artifact-" + key.fingerprint() + ".asc");
            runner.sign(artifact, signature, key);
            Claim claim = new OpenPgpSignatureFormat()
                    .parse(Evidence.read(signature, Evidence.SOURCE_SIDECAR)).get(0);
            return runner.extractCredentials(runner.verify(artifact, claim));
        }

        private BcRunner runner(BcKeyStore store, String... fingerprints) {
            return new BcRunner(store, List.of(fingerprints), null, null, null, null,
                    BcRunner.DEFAULT_CIPHER_SUITE);
        }

        private String generate(BcKeyStore store, String name) {
            return BcTestKeys.generate(store, "Test <" + name + "@example.com>", "ed25519", null);
        }

        private BcKeyStore store() {
            return new BcKeyStore(null, dir.resolve("cert-d"), dir.resolve("bc-private"));
        }
    }

    private BcRunner createSigningRunner(Path tempDir) {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"),
                tempDir.resolve("bc-private"));
        String fingerprint = BcTestKeys.generate(store, "Test <test@example.com>", "ed25519", null);
        return new BcRunner(store, fingerprint, null);
    }

    private BcRunner createVerifyOnly(Path tempDir) {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        return new BcRunner(store, null, null);
    }

    @Test
    void nameReturnsBc() {
        try (BcRunner runner = createVerifyOnly(Path.of(System.getProperty("java.io.tmpdir")))) {
            assertThat(runner.name()).isEqualTo("bc");
        }
    }

    @Test
    void isAvailableAlwaysTrue() {
        try (BcRunner runner = createVerifyOnly(Path.of(System.getProperty("java.io.tmpdir")))) {
            assertThat(runner.isAvailable()).isTrue();
        }
    }

    @Test
    void canSignFalseWhenNoFingerprint() {
        try (BcRunner runner = createVerifyOnly(Path.of(System.getProperty("java.io.tmpdir")))) {
            assertThat(runner.canSign()).isFalse();
        }
    }

    @Test
    void supportedCredentialTypesBothV4AndV6() {
        try (BcRunner runner = createVerifyOnly(Path.of(System.getProperty("java.io.tmpdir")))) {
            assertThat(runner.supportedCredentialTypes()).isEqualTo(Set.of("pgp4", "pgp6"));
        }
    }

    @Test
    void canVerifyAcceptsClassicSignaturesOfEitherVersion() {
        try (BcRunner runner = createVerifyOnly(Path.of(System.getProperty("java.io.tmpdir")))) {
            assertThat(runner.canVerify(new OpenPgpClaim("block", 4, "FP", 27, null))).isTrue();
            assertThat(runner.canVerify(new OpenPgpClaim("block", 6, "FP", 27, null))).isTrue();
        }
    }

    @Test
    void canVerifyDeclinesPostQuantumSignatures() {
        try (BcRunner runner = createVerifyOnly(Path.of(System.getProperty("java.io.tmpdir")))) {
            for (int algorithmId = 30; algorithmId <= 36; algorithmId++) {
                assertThat(runner.canVerify(new OpenPgpClaim("block", 6, "FP", algorithmId, null)))
                        .as("algorithm %d", algorithmId).isFalse();
            }
        }
    }

    @Test
    void canVerifyRejectsSigstoreClaim() {
        try (BcRunner runner = createVerifyOnly(Path.of(System.getProperty("java.io.tmpdir")))) {
            assertThat(runner.canVerify(new SigstoreClaim("{}", null))).isFalse();
        }
    }

    @Test
    void extractCredentialsV4ProducesOpenpgp4(@TempDir Path tempDir) {
        try (BcRunner runner = createVerifyOnly(tempDir)) {
            OpenPgpVerifyResult result = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, "User <user@example.com>",
                    "Ed25519",
                    4, "AABBCCDD", "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD");
            var creds = runner.extractCredentials(result);
            assertThat(creds).containsExactly(
                    new KeyCredential("pgp4", "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD"));
        }
    }

    @Test
    void extractCredentialsV6ProducesOpenpgp6(@TempDir Path tempDir) {
        try (BcRunner runner = createVerifyOnly(tempDir)) {
            OpenPgpVerifyResult result = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, "User <user@example.com>",
                    "Ed25519",
                    6, null, "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD");
            var creds = runner.extractCredentials(result);
            assertThat(creds).hasSize(1);
            assertThat(creds.get(0).type()).isEqualTo("pgp6");
        }
    }

    @Test
    void extractCredentialsFailReturnsEmpty(@TempDir Path tempDir) {
        try (BcRunner runner = createVerifyOnly(tempDir)) {
            OpenPgpVerifyResult result = new OpenPgpVerifyResult(ClaimOutcome.FAILED, null, null, null, 4, null, null);
            assertThat(runner.extractCredentials(result).isEmpty()).isTrue();
        }
    }

    @Test
    void signAndVerifyRoundTripEd25519(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        try (BcRunner runner = new BcRunner(store, null, null)) {

            String fingerprint = runner.generateKey("Test <test@example.com>", "ed25519", null);
            try (BcRunner signer = new BcRunner(store, fingerprint, null)) {

                Path artifact = tempDir.resolve("artifact.txt");
                Files.writeString(artifact, "test content");
                Path sigFile = tempDir.resolve("artifact.txt.asc");

                SignResult signResult = SigningTests.signWithOnlyKey(signer, artifact, sigFile);
                assertThat(signResult.algorithm()).isNotNull();

                String armored = Files.readString(sigFile);
                OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);
                OpenPgpClaim claim = new OpenPgpClaim(
                        armored, info.version(), info.issuerFingerprint(), info.algorithmId(), null);

                VerifyResult result = signer.verify(artifact, claim);
                assertThat(result.isVerified()).isTrue();
            }
        }
    }

    @Test
    void verifyFallsBackToKeyIdWhenFingerprintMissing(@TempDir Path tempDir) throws Exception {
        // Use ECDSA P-256 which produces v4 keys — the real scenario where
        // Issuer Fingerprint subpackets (type 33) are often absent
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        try (BcRunner runner = new BcRunner(store, null, null)) {

            String fingerprint = runner.generateKey("Test <test@example.com>", "nistp256", null);
            try (BcRunner signer = new BcRunner(store, fingerprint, null)) {

                Path artifact = tempDir.resolve("artifact.txt");
                Files.writeString(artifact, "test content");
                Path sigFile = tempDir.resolve("artifact.txt.asc");
                SigningTests.signWithOnlyKey(signer, artifact, sigFile);

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
        }
    }

    @Test
    void verifyNullFingerprintNoKeyReturnsNoKey(@TempDir Path tempDir) throws Exception {
        // Use an empty key store — no keys available
        BcKeyStore emptyStore = new BcKeyStore(null, tempDir.resolve("empty-cert-d"),
                tempDir.resolve("empty-bc-private"));
        try (BcRunner runner = new BcRunner(emptyStore, null, null)) {

            // Generate a key in a separate store just to produce a valid signature
            BcKeyStore signerStore = new BcKeyStore(null, tempDir.resolve("signer-cert-d"),
                    tempDir.resolve("signer-bc-private"));
            try (BcRunner signerRunner = new BcRunner(signerStore, null, null)) {
                String fp = signerRunner.generateKey("Signer <signer@example.com>", "nistp256", null);
                try (BcRunner signer = new BcRunner(signerStore, fp, null)) {

                    Path artifact = tempDir.resolve("artifact.txt");
                    Files.writeString(artifact, "test content");
                    Path sigFile = tempDir.resolve("artifact.txt.asc");
                    SigningTests.signWithOnlyKey(signer, artifact, sigFile);

                    String armored = Files.readString(sigFile);
                    OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);

                    // Verify with null fingerprint against the empty store
                    OpenPgpClaim claimNoFp = new OpenPgpClaim(
                            armored, info.version(), null, info.algorithmId(), null);

                    VerifyResult result = runner.verify(artifact, claimNoFp);
                    assertThat(result.isIndeterminate(IndeterminateReason.KEY_UNAVAILABLE)).isTrue();
                    assertThat(((OpenPgpVerifyResult) result).fingerprint()).isNotNull();
                }
            }
        }
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
        try (BcRunner signerRunner = new BcRunner(signerStore, null, null)) {
            String fp = signerRunner.generateKey("Eph <eph@example.com>", "nistp256", null);
            try (BcRunner signer = new BcRunner(signerStore, fp, null)) {

                Path artifact = tempDir.resolve("artifact.txt");
                Files.writeString(artifact, "ephemeral test");
                Path sigFile = tempDir.resolve("artifact.txt.asc");
                SigningTests.signWithOnlyKey(signer, artifact, sigFile);

                // Verifier store: empty, isolated from signer
                Path verifierCertD = tempDir.resolve("verifier-cd");
                BcKeyStore verifierStore = new BcKeyStore(null, verifierCertD, tempDir.resolve("verifier-bp"));
                try (BcRunner verifier = new BcRunner(verifierStore, null, null)) {

                    // Export the key, then simulate ephemeral fetch by calling cacheEphemeral directly
                    // (fetchKey would call fetchKeyFromHkp which needs a real keyserver)
                    var pubRing = signerStore.findPublicKey(fp).ring();
                    BcTestKeys.addFetched(verifierStore, Map.of("hkps://keys.example.org", pubRing));

                    String armored = Files.readString(sigFile);
                    OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);
                    OpenPgpClaim claim = new OpenPgpClaim(
                            armored, info.version(), info.issuerFingerprint(), info.algorithmId(), null);

                    VerifyResult result = verifier.verify(artifact, claim);
                    assertThat(result.isVerified()).isTrue();
                    assertThat(Files.exists(verifierCertD)).as("cert-d should not exist — key was ephemeral").isFalse();
                }
            }
        }
    }

    @Test
    void verifyNoKeyReturnsNoKeyVerdict(@TempDir Path tempDir) throws Exception {
        try (BcRunner runner = createVerifyOnly(tempDir)) {
            OpenPgpClaim claim = new OpenPgpClaim(
                    "-----BEGIN PGP SIGNATURE-----\nfake\n-----END PGP SIGNATURE-----\n",
                    4, "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF", 27, null);

            VerifyResult result = runner.verify(tempDir.resolve("nonexistent"), claim);
            assertThat(result.isIndeterminate(IndeterminateReason.KEY_UNAVAILABLE)).isTrue();
        }
    }

    // --- Passphrase-protected key tests ---

    private static final char[] TEST_PASSPHRASE = "test-secret".toCharArray();

    private static PassphraseProvider fixedPassphrase(char[] passphrase) {
        return fp -> passphrase.clone();
    }

    @Test
    void generateKeyWithPassphraseStoresEncrypted(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        try (BcRunner runner = new BcRunner(store, null, null, fixedPassphrase(TEST_PASSPHRASE))) {

            String fingerprint = runner.generateKey("Test <test@example.com>", "ed25519", null);
            PGPSecretKeyRing ring = store.findSecretKey(fingerprint);
            assertThat(ring).isNotNull();

            for (var keys = ring.getSecretKeys(); keys.hasNext();) {
                PGPSecretKey sk = keys.next();
                assertThat(sk.getKeyEncryptionAlgorithm()).as("Secret key should be encrypted")
                        .isNotEqualTo(SymmetricKeyAlgorithmTags.NULL);
            }
        }
    }

    @Test
    void signAndVerifyWithEncryptedKey(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        PassphraseProvider provider = fixedPassphrase(TEST_PASSPHRASE);
        try (BcRunner runner = new BcRunner(store, null, null, provider)) {

            String fingerprint = runner.generateKey("Test <test@example.com>", "ed25519", null);
            try (BcRunner signer = new BcRunner(store, fingerprint, null, provider)) {

                Path artifact = tempDir.resolve("artifact.txt");
                Files.writeString(artifact, "encrypted key content");
                Path sigFile = tempDir.resolve("artifact.txt.asc");

                SignResult signResult = SigningTests.signWithOnlyKey(signer, artifact, sigFile);
                assertThat(signResult.algorithm()).isNotNull();

                String armored = Files.readString(sigFile);
                OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);
                OpenPgpClaim claim = new OpenPgpClaim(
                        armored, info.version(), info.issuerFingerprint(), info.algorithmId(), null);

                VerifyResult result = signer.verify(artifact, claim);
                assertThat(result.isVerified()).isTrue();
            }
        }
    }

    @Test
    void signWithEncryptedKeyNoProviderThrows(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        try (BcRunner generator = new BcRunner(store, null, null, fixedPassphrase(TEST_PASSPHRASE))) {
            String fingerprint = generator.generateKey("Test <test@example.com>", "ed25519", null);

            // signer has no passphrase provider
            try (BcRunner signer = new BcRunner(store, fingerprint, null)) {

                Path artifact = tempDir.resolve("artifact.txt");
                Files.writeString(artifact, "content");
                Path sigFile = tempDir.resolve("artifact.txt.asc");

                assertThatThrownBy(() -> SigningTests.signWithOnlyKey(signer, artifact, sigFile))
                        .isInstanceOf(ToolExecutionException.class)
                        .hasMessageContaining("passphrase");
            }
        }
    }

    @Test
    void signWithWrongPassphraseThrows(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        try (BcRunner generator = new BcRunner(store, null, null, fixedPassphrase(TEST_PASSPHRASE))) {
            String fingerprint = generator.generateKey("Test <test@example.com>", "ed25519", null);

            try (BcRunner signer = new BcRunner(store, fingerprint, null,
                    fixedPassphrase("wrong-passphrase".toCharArray()))) {

                Path artifact = tempDir.resolve("artifact.txt");
                Files.writeString(artifact, "content");
                Path sigFile = tempDir.resolve("artifact.txt.asc");

                assertThatThrownBy(() -> SigningTests.signWithOnlyKey(signer, artifact, sigFile))
                        .isInstanceOf(ToolExecutionException.class);
            }
        }
    }

    @Test
    void signWithNullPassphraseFromProviderThrows(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        try (BcRunner generator = new BcRunner(store, null, null, fixedPassphrase(TEST_PASSPHRASE))) {
            String fingerprint = generator.generateKey("Test <test@example.com>", "ed25519", null);

            try (BcRunner signer = new BcRunner(store, fingerprint, null, fp -> null)) {

                Path artifact = tempDir.resolve("artifact.txt");
                Files.writeString(artifact, "content");
                Path sigFile = tempDir.resolve("artifact.txt.asc");

                assertThatThrownBy(() -> SigningTests.signWithOnlyKey(signer, artifact, sigFile))
                        .isInstanceOf(ToolExecutionException.class)
                        .hasMessageContaining("passphrase");
            }
        }
    }

    @Test
    void generateKeyNullPassphraseFromProviderStoresUnencrypted(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        try (BcRunner runner = new BcRunner(store, null, null, fp -> null)) {

            String fingerprint = runner.generateKey("Test <test@example.com>", "ed25519", null);
            PGPSecretKeyRing ring = store.findSecretKey(fingerprint);
            assertThat(ring).isNotNull();

            PGPSecretKey primary = ring.getSecretKey();
            assertThat(primary.getKeyEncryptionAlgorithm()).isEqualTo(SymmetricKeyAlgorithmTags.NULL);
        }
    }

    @Test
    void generateKeyEmptyPassphraseStoresUnencrypted(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        try (BcRunner runner = new BcRunner(store, null, null, fp -> new char[0])) {

            String fingerprint = runner.generateKey("Test <test@example.com>", "ed25519", null);
            PGPSecretKeyRing ring = store.findSecretKey(fingerprint);

            PGPSecretKey primary = ring.getSecretKey();
            assertThat(primary.getKeyEncryptionAlgorithm()).isEqualTo(SymmetricKeyAlgorithmTags.NULL);
        }
    }

    @Test
    void signAndVerifyEncryptedKeyRsa(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        PassphraseProvider provider = fixedPassphrase(TEST_PASSPHRASE);
        try (BcRunner runner = new BcRunner(store, null, null, provider)) {

            String fingerprint = runner.generateKey("Test <test@example.com>", "rsa4096", null);
            try (BcRunner signer = new BcRunner(store, fingerprint, null, provider)) {

                Path artifact = tempDir.resolve("artifact.txt");
                Files.writeString(artifact, "rsa encrypted key");
                Path sigFile = tempDir.resolve("artifact.txt.asc");
                SigningTests.signWithOnlyKey(signer, artifact, sigFile);

                String armored = Files.readString(sigFile);
                OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);
                OpenPgpClaim claim = new OpenPgpClaim(
                        armored, info.version(), info.issuerFingerprint(), info.algorithmId(), null);

                assertThat(signer.verify(artifact, claim).isVerified()).isTrue();
            }
        }
    }

    @Test
    void signAndVerifyEncryptedKeyEcdsaV4(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        PassphraseProvider provider = fixedPassphrase(TEST_PASSPHRASE);
        try (BcRunner runner = new BcRunner(store, null, null, provider)) {

            String fingerprint = runner.generateKey("Test <test@example.com>", "nistp256", null);
            try (BcRunner signer = new BcRunner(store, fingerprint, null, provider)) {

                Path artifact = tempDir.resolve("artifact.txt");
                Files.writeString(artifact, "ecdsa v4 encrypted key");
                Path sigFile = tempDir.resolve("artifact.txt.asc");
                SigningTests.signWithOnlyKey(signer, artifact, sigFile);

                String armored = Files.readString(sigFile);
                OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);
                OpenPgpClaim claim = new OpenPgpClaim(
                        armored, info.version(), info.issuerFingerprint(), info.algorithmId(), null);

                assertThat(signer.verify(artifact, claim).isVerified()).isTrue();
            }
        }
    }

    @Test
    void builderPassphraseProviderThreadsToBcRunner(@TempDir Path tempDir) throws Exception {
        PassphraseProvider provider = fixedPassphrase(TEST_PASSPHRASE);

        String certD = tempDir.resolve("cert-d").toString();
        String bcPrivate = tempDir.resolve("bc-private").toString();

        // Generate an encrypted key via direct BcRunner
        BcKeyStore store = new BcKeyStore(null, Path.of(certD), Path.of(bcPrivate));
        try (BcRunner generator = new BcRunner(store, null, null, provider)) {
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
}
