package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SqRunnerTest {

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

            assertThat(root.kind()).isEqualTo(TrustRootRef.KIND_OPENPGP_KEYRING);
            assertThat(root.identifier()).isEqualTo(home.toString());
        }

        /** No SEQUOIA_HOME is the ordinary case: sq reads the user's own cert store. */
        @Test
        void namesSqsDefaultStoreWhenNoHomeIsConfigured() {
            TrustRootRef root = new SqRunner((Path) null).trustRoot();

            assertThat(root.kind()).isEqualTo(TrustRootRef.KIND_OPENPGP_KEYRING);
            assertThat(root.identifier()).isEqualTo("sq default store");
        }
    }
}
