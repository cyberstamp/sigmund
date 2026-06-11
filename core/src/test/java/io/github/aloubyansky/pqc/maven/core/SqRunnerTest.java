package io.github.aloubyansky.pqc.maven.core;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class SqRunnerTest {

    @Test
    void parseCertInfo_rsaCert() {
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
        assertNotNull(info);
        assertEquals("RSA", info.algorithm());
        assertEquals("Alexey Loubyansky <olubyans@redhat.com>", info.userId());
        assertNull(info.certFile());
    }

    @Test
    void parseCertInfo_pqcCertWithSubkeys() {
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
        assertNotNull(info);
        assertEquals("ML-DSA-65+Ed25519", info.algorithm());
        assertEquals("Alexey Loubyansky <olubyans@redhat.com>", info.userId());
        assertEquals(certFile, info.certFile());
    }

    @Test
    void parseCertInfo_noUserID() {
        String output = """
                OpenPGP Certificate.

                      Fingerprint: ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890
                  Public-key algo: ML-DSA-87+Ed448
                    Creation time: 2025-01-15 10:00:00 UTC
                """;
        SqRunner.CertInfo info = SqRunner.parseCertInfo(output, null);
        assertNotNull(info);
        assertEquals("ML-DSA-87+Ed448", info.algorithm());
        assertNull(info.userId());
    }

    @Test
    void parseCertInfo_nullInput() {
        assertNull(SqRunner.parseCertInfo(null, null));
    }

    @Test
    void parseCertInfo_emptyInput() {
        assertNull(SqRunner.parseCertInfo("", null));
    }

    @Test
    void parseCertInfo_noMatchingFields() {
        assertNull(SqRunner.parseCertInfo("some random output\n", null));
    }
}
