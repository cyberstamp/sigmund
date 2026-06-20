package io.github.aloubyansky.sigmund.core;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class GpgRunnerTest {

    @Test
    void extractGpgKeyId_fromStderr() {
        String stderr = """
                gpg: Signature made Mon 12 May 2025 10:00:00 AM EDT
                gpg:                using RSA key 4AEE18F83AFDEB23
                gpg: Good signature from "User <user@example.com>" [ultimate]
                """;
        assertEquals("4AEE18F83AFDEB23", GpgRunner.extractGpgKeyId(stderr));
    }

    @Test
    void extractGpgKeyId_longForm() {
        String stderr = """
                gpg: Signature made Mon 12 May 2025 10:00:00 AM EDT
                gpg:                using RSA key ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234
                gpg: Good signature from "User <user@example.com>" [ultimate]
                """;
        assertEquals("ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234", GpgRunner.extractGpgKeyId(stderr));
    }

    @Test
    void extractGpgKeyId_notFound() {
        assertNull(GpgRunner.extractGpgKeyId("gpg: some other output\n"));
    }

    @Test
    void extractGpgKeyId_nullInput() {
        assertNull(GpgRunner.extractGpgKeyId(null));
    }

    // --- extractSignerUserId ---

    @Test
    void extractSignerUserId_fromStderr() {
        String stderr = """
                gpg: Signature made Mon 12 May 2025 10:00:00 AM EDT
                gpg:                using RSA key 4AEE18F83AFDEB23
                gpg: Good signature from "User Name <user@example.com>" [ultimate]
                """;
        assertEquals("User Name <user@example.com>", GpgRunner.extractSignerUserId(stderr));
    }

    @Test
    void extractSignerUserId_noGoodSignature() {
        String stderr = """
                gpg: Signature made Mon 12 May 2025 10:00:00 AM EDT
                gpg:                using RSA key 4AEE18F83AFDEB23
                gpg: Can't check signature: No public key
                """;
        assertNull(GpgRunner.extractSignerUserId(stderr));
    }

    @Test
    void extractSignerUserId_nullInput() {
        assertNull(GpgRunner.extractSignerUserId(null));
    }

    // --- extractAlgorithm ---

    @Test
    void extractAlgorithm_rsa() {
        String stderr = """
                gpg: Signature made Mon 12 May 2025 10:00:00 AM EDT
                gpg:                using RSA key 4AEE18F83AFDEB23
                gpg: Good signature from "User <user@example.com>" [ultimate]
                """;
        assertEquals("RSA", GpgRunner.extractAlgorithm(stderr));
    }

    @Test
    void extractAlgorithm_eddsa() {
        String stderr = """
                gpg: Signature made Mon 12 May 2025 10:00:00 AM EDT
                gpg:                using EDDSA key ABCD1234ABCD1234
                gpg: Good signature from "User <user@example.com>" [ultimate]
                """;
        assertEquals("EDDSA", GpgRunner.extractAlgorithm(stderr));
    }

    @Test
    void extractAlgorithm_nullInput() {
        assertNull(GpgRunner.extractAlgorithm(null));
    }

    @Test
    void extractAlgorithm_notFound() {
        assertNull(GpgRunner.extractAlgorithm("gpg: some other output\n"));
    }
}
