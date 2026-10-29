package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SqRunnerTest {

    @Test
    void primaryFingerprintIsReadFromTheCertificate(@TempDir Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc"));
        String primary = new BcRunner(store, null, null).generateKey("A <a@example.org>", "ed25519", null);
        Path certFile = tempDir.resolve("cert.pgp");
        Files.write(certFile, store.findPublicKey(primary).ring().getEncoded());
        String subkey = "1111111111111111111111111111111111111111";

        assertThat(SqRunner.primaryFingerprintOf(certFile, subkey)).isEqualTo(primary.toUpperCase());
        assertThat(SqRunner.primaryFingerprintOf(certFile, primary)).isNull();
        assertThat(SqRunner.primaryFingerprintOf(null, subkey)).isNull();
    }

    @Test
    void parseCertInfoRsaCert() {
        String output = """
                OpenPGP Certificate.

                      Fingerprint: 41A2197725BD63EB00D071D46A7F5DB1C68BDB81
                  Public-key algo: RSA
                  Public-key size: 4096 bits
                    Creation time: 2022-11-22 21:54:22 UTC
                        Key flags: certification, signing

                           Subkey: 25C3B7C9C0DF627E052F126F84EFABB1BAFB7050
                  Public-key algo: RSA
                  Public-key size: 4096 bits
                    Creation time: 2022-11-22 21:54:22 UTC
                        Key flags: transport encryption, data-at-rest encryption

                           UserID: Alexey Loubyansky <olubyans@redhat.com>
                """;
        SqRunner.CertInfo info = SqRunner.parseCertInfo(output, null);
        assertThat(info).isNotNull();
        assertThat(info.algorithm()).isEqualTo("RSA");
        assertThat(info.userId()).isEqualTo("Alexey Loubyansky <olubyans@redhat.com>");
        assertThat(info.certFile()).isNull();
    }

    @Test
    void parseCertInfoPqcCertWithSubkeys() {
        String output = """
                OpenPGP Certificate.

                      Fingerprint: 3EE8B170C692FEFEFF2033DDD872C037A75FFE8BD8748005D0285222E76EDB53
                  Public-key algo: ML-DSA-65+Ed25519
                    Creation time: 2026-05-04 21:09:50 UTC
                        Key flags: certification

                           Subkey: D62AAB339E45E5EA2FD036872B01D46A517A299115599CCADD4C50A956F8E707
                  Public-key algo: ML-DSA-65+Ed25519
                    Creation time: 2026-05-04 21:09:50 UTC
                        Key flags: signing

                           UserID: Alexey Loubyansky <olubyans@redhat.com>
                """;
        java.nio.file.Path certFile = java.nio.file.Path.of("/some/cert.pgp");
        SqRunner.CertInfo info = SqRunner.parseCertInfo(output, certFile);
        assertThat(info).isNotNull();
        assertThat(info.algorithm()).isEqualTo("ML-DSA-65+Ed25519");
        assertThat(info.userId()).isEqualTo("Alexey Loubyansky <olubyans@redhat.com>");
        assertThat(info.certFile()).isEqualTo(certFile);
    }

    @Test
    void parseCertInfoNoUserID() {
        String output = """
                OpenPGP Certificate.

                      Fingerprint: ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890
                  Public-key algo: ML-DSA-87+Ed448
                    Creation time: 2025-01-15 10:00:00 UTC
                """;
        SqRunner.CertInfo info = SqRunner.parseCertInfo(output, null);
        assertThat(info).isNotNull();
        assertThat(info.algorithm()).isEqualTo("ML-DSA-87+Ed448");
        assertThat(info.userId()).isNull();
    }

    @Test
    void parseCertInfoNullInput() {
        assertThat(SqRunner.parseCertInfo(null, null)).isNull();
    }

    @Test
    void parseCertInfoEmptyInput() {
        assertThat(SqRunner.parseCertInfo("", null)).isNull();
    }

    @Test
    void parseCertInfoNoMatchingFields() {
        assertThat(SqRunner.parseCertInfo("some random output\n", null)).isNull();
    }

    @Nested
    class Routing {

        @Test
        void verifiesRfc9580SignatureVersions(@TempDir Path tempDir) {
            SqRunner sq = new SqRunner(tempDir);

            assertThat(sq.canVerify(new OpenPgpClaim("block", 4, null, 1, null))).isTrue();
            assertThat(sq.canVerify(new OpenPgpClaim("block", 6, null, 27, null))).isTrue();
        }

        @Test
        void doesNotClaimLibrePgpV5Signatures(@TempDir Path tempDir) {
            assertThat(new SqRunner(tempDir).canVerify(new OpenPgpClaim("block", 5, null, 22, null)))
                    .isFalse();
        }

        @Test
        void doesNotClaimSigstoreBundles(@TempDir Path tempDir) {
            assertThat(new SqRunner(tempDir).canVerify(new SigstoreClaim("{}", null))).isFalse();
        }
    }

    @Nested
    class ParseSignerSelfOutputTests {

        @Test
        void validV6Fingerprint() {
            String output = "sign.signer-self.0 = \"ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890\"\n";
            assertThat(SqRunner.parseSignerSelfOutput(output))
                    .isEqualTo("ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890");
        }

        @Test
        void validV4Fingerprint() {
            String output = "sign.signer-self.0 = \"41A2197725BD63EB00D071D46A7F5DB1C68BDB81\"\n";
            assertThat(SqRunner.parseSignerSelfOutput(output))
                    .isEqualTo("41A2197725BD63EB00D071D46A7F5DB1C68BDB81");
        }

        @Test
        void lowercaseFingerprintNormalized() {
            String output = "sign.signer-self.0 = \"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890\"\n";
            assertThat(SqRunner.parseSignerSelfOutput(output))
                    .isEqualTo("ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890");
        }

        @Test
        void placeholderTextRejected() {
            String output = "sign.signer-self.0 = \"fingerprint of your key\"\n";
            assertThat(SqRunner.parseSignerSelfOutput(output)).isNull();
        }

        @Test
        void emptyValueRejected() {
            String output = "sign.signer-self.0 = \"\"\n";
            assertThat(SqRunner.parseSignerSelfOutput(output)).isNull();
        }

        @Test
        void nullInput() {
            assertThat(SqRunner.parseSignerSelfOutput(null)).isNull();
        }

        @Test
        void emptyInput() {
            assertThat(SqRunner.parseSignerSelfOutput("")).isNull();
        }

        @Test
        void noEqualsSign() {
            assertThat(SqRunner.parseSignerSelfOutput("some random output")).isNull();
        }

        @Test
        void tooShortHexRejected() {
            String output = "sign.signer-self.0 = \"ABCDEF1234\"\n";
            assertThat(SqRunner.parseSignerSelfOutput(output)).isNull();
        }

        @Test
        void nonHexRejected() {
            String output = "sign.signer-self.0 = \"GHIJKL1234567890ABCDEF1234567890ABCDEF1234\"\n";
            assertThat(SqRunner.parseSignerSelfOutput(output)).isNull();
        }
    }

    @Nested
    class SignerSelfCanSignTests {

        @TempDir
        Path tempDir;

        @Test
        void canSignWithDefaultSignerFingerprint() {
            String fp = "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890";
            SqRunner sq = new SqRunner("sq", tempDir, null, fp);
            assertThat(sq.canSign()).isTrue();
        }

        @Test
        void cannotSignWithNullDefaultSigner() {
            SqRunner sq = new SqRunner("sq", tempDir, null, null);
            assertThat(sq.canSign()).isFalse();
        }

        @Test
        void explicitFingerprintTakesPrecedence() {
            String explicit = "1111111111111111111111111111111111111111111111111111111111111111";
            String defaultFp = "2222222222222222222222222222222222222222222222222222222222222222";
            SqRunner sq = new SqRunner("sq", tempDir, explicit, defaultFp);
            assertThat(sq.canSign()).isTrue();
            List<SigningInfo> info = sq.signingInfo();
            assertThat(info.size()).isEqualTo(1);
            assertThat(info.get(0).fingerprint()).isEqualTo(explicit);
        }
    }

    @Nested
    class ParseCertStorePathTests {

        @Test
        void normalOutput() {
            String output = """
                     - home directory
                       - /home/user
                       - This holds the configuration file.

                     - certificate store
                       - /home/user/.local/share/pgp.cert.d
                       - This holds all the certificates.

                     - key store
                       - /home/user/.local/share/sequoia/keystore
                    """;
            assertThat(SqRunner.parseCertStorePath(output))
                    .isEqualTo(Path.of("/home/user/.local/share/pgp.cert.d"));
        }

        @Test
        void withSequoiaHome() {
            String output = """
                     - certificate store
                       - /tmp/sq-home/data/pgp.cert.d
                       - This holds all the certificates.
                    """;
            assertThat(SqRunner.parseCertStorePath(output))
                    .isEqualTo(Path.of("/tmp/sq-home/data/pgp.cert.d"));
        }

        @Test
        void trailingWhitespace() {
            String output = " - certificate store  \n   - /some/path/pgp.cert.d   \n";
            assertThat(SqRunner.parseCertStorePath(output))
                    .isEqualTo(Path.of("/some/path/pgp.cert.d"));
        }

        @Test
        void missingCertificateStoreSection() {
            String output = """
                     - home directory
                       - /home/user

                     - key store
                       - /home/user/.local/share/sequoia/keystore
                    """;
            assertThat(SqRunner.parseCertStorePath(output)).isNull();
        }

        @Test
        void nullInput() {
            assertThat(SqRunner.parseCertStorePath(null)).isNull();
        }

        @Test
        void emptyInput() {
            assertThat(SqRunner.parseCertStorePath("")).isNull();
        }
    }

    @Nested
    class FindCertFileTests {

        @TempDir
        Path tempDir;

        @Test
        void directPathExistsReturnsIt() throws IOException {
            String fingerprint = "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890";
            Path certDir = tempDir.resolve("data").resolve("pgp.cert.d").resolve("ab");
            Files.createDirectories(certDir);
            Path certFile = certDir.resolve(
                    "cdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
            Files.writeString(certFile, "fake cert data");

            SqRunner sq = new SqRunner(tempDir);
            Path result = sq.findCertFile(fingerprint);
            assertThat(result).isNotNull();
            assertThat(result).isEqualTo(certFile);
        }

        @Test
        void directPathMissingReturnsNull() {
            String fingerprint = "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890";
            SqRunner sq = new SqRunner(tempDir);
            Path result = sq.findCertFile(fingerprint);
            assertThat(result).isNull();
        }

        @Test
        void nullFingerprintReturnsNull() {
            SqRunner sq = new SqRunner(tempDir);
            assertThat(sq.findCertFile(null)).isNull();
        }

        @Test
        void emptyFingerprintReturnsNull() {
            SqRunner sq = new SqRunner(tempDir);
            assertThat(sq.findCertFile("")).isNull();
        }
    }

    @Nested
    class TrustRootReporting {

        @Test
        void namesTheIsolatedStoreWhenOneIsConfigured(@TempDir Path home) {
            TrustRootRef root = new SqRunner(home).trustRoot();

            assertThat(root.kind()).isEqualTo(TrustRootRef.KIND_OPENPGP_CERT_D);
            assertThat(root.identifier()).isEqualTo(home.toString());
        }

        /** No SEQUOIA_HOME is the ordinary case: sq reads the user's own cert store. */
        @Test
        void namesSqsDefaultStoreWhenNoHomeIsConfigured() {
            TrustRootRef root = new SqRunner((Path) null).trustRoot();

            assertThat(root.kind()).isEqualTo(TrustRootRef.KIND_OPENPGP_CERT_D);
            assertThat(root.identifier()).isEqualTo("sq default store");
        }
    }

    @Nested
    class CryptoPolicy {

        @Test
        void sqRunsUnderSigmundsPolicyRatherThanTheHosts() throws Exception {
            Map<String, String> env = SqRunner.envFor(null);

            assertThat(env).doesNotContainKey("SEQUOIA_HOME");
            assertThat(Files.readString(Path.of(env.get("SEQUOIA_CRYPTO_POLICY"))))
                    .isEqualTo(sequoiaPolicyResource())
                    .contains("[hash_algorithms]", "[asymmetric_algorithms]");
        }

        private String sequoiaPolicyResource() throws IOException {
            try (InputStream policy = VerificationAlgorithms.class
                    .getResourceAsStream(VerificationAlgorithms.SEQUOIA_POLICY_RESOURCE)) {
                assertThat(policy).isNotNull();
                return new String(policy.readAllBytes(), StandardCharsets.UTF_8);
            }
        }

        @Test
        void anIsolatedHomeKeepsThePolicy(@TempDir Path home) {
            Map<String, String> env = SqRunner.envFor(home);

            assertThat(env).containsEntry("SEQUOIA_HOME", home.toString())
                    .containsKey("SEQUOIA_CRYPTO_POLICY");
        }
    }

    /**
     * The verdict read from {@code sq verify}'s report, using the texts sq 1.4 prints — including
     * the no-break space it puts between a count and its noun; the agreement tests run the same
     * cases against the installed sq.
     */
    @Nested
    class VerdictFromReport {

        private static final String NOT_AUTHENTICATED = "  Error: Verification failed: could not authenticate any signatures\n";

        @Test
        void anAuthenticatedSignatureVerifies() {
            assertThat(SqRunner.verdict(0, "1\u00A0authenticated signature.\n"))
                    .isEqualTo(ToolVerdict.verified());
        }

        @Test
        void aManipulatedMessageFails() {
            String stderr = "Error verifying signature made by ABCD:\n"
                    + "  Error: Message has been manipulated\n"
                    + "0\u00A0authenticated signatures, 1\u00A0bad signature.\n" + NOT_AUTHENTICATED;

            assertThat(SqRunner.verdict(1, stderr))
                    .isEqualTo(ToolVerdict.failed());
        }

        @Test
        void aRevokedKeyFails() {
            String stderr = "Signing key on ABCD is bad:\n"
                    + "  Error: Invalid key: \"certificate is revoked\"\n"
                    + "0\u00A0authenticated signatures, 1\u00A0bad key.\n" + NOT_AUTHENTICATED;

            assertThat(SqRunner.verdict(1, stderr))
                    .isEqualTo(ToolVerdict.failed());
        }

        @Test
        void anExpiredKeyFails() {
            String stderr = "Signing key on ABCD is bad:\n"
                    + "  Error: The primary key is not live\n"
                    + "because: Expired on 2026-10-07T19:00:00Z\n"
                    + "0\u00A0authenticated signatures, 1\u00A0bad key.\n" + NOT_AUTHENTICATED;

            assertThat(SqRunner.verdict(1, stderr))
                    .isEqualTo(ToolVerdict.failed());
        }

        @Test
        void anUnboundKeyIsNotAvailable() {
            String stderr = "Signing key on ABCD is not bound:\n"
                    + "  Error: No binding signature at time 2026-10-16T19:23:52Z\n"
                    + "0\u00A0authenticated signatures, 1\u00A0bad key.\n" + NOT_AUTHENTICATED;

            assertThat(SqRunner.verdict(1, stderr)).isEqualTo(
                    ToolVerdict.indeterminate(IndeterminateReason.KEY_UNAVAILABLE));
        }

        @Test
        void aKeyThePolicyRejectsIsAnUnsupportedAlgorithm() {
            String stderr = "Signing key on ABCD is not bound:\n"
                    + "  Error: No binding signature at time 2026-10-16T19:23:52Z\n"
                    + "because: Policy rejected non-revocation signature (PositiveCertification)"
                    + " requiring second pre-image resistance\n"
                    + "because: SHA1 is not considered secure\n"
                    + "0\u00A0authenticated signatures, 1\u00A0bad key.\n" + NOT_AUTHENTICATED;

            assertThat(SqRunner.verdict(1, stderr))
                    .isEqualTo(ToolVerdict.indeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM));
        }

        @Test
        void aReportWithoutAVerdictIsTheToolsFailure() {
            assertThat(SqRunner.verdict(2, "error: unexpected argument '--signer-file'\n"))
                    .isEqualTo(ToolVerdict.indeterminate(IndeterminateReason.TOOL_UNAVAILABLE));
        }
    }
}
