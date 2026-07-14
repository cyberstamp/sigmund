package io.github.cyberstamp.sigmund.core;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class GpgRunnerTest {

    @Test
    void extractGpgKeyIdFromStderr() {
        String stderr = """
                gpg: Signature made Mon 12 May 2025 10:00:00 AM EDT
                gpg:                using RSA key 4AEE18F83AFDEB23
                gpg: Good signature from "User <user@example.com>" [ultimate]
                """;
        assertEquals("4AEE18F83AFDEB23", GpgRunner.extractGpgKeyId(stderr));
    }

    @Test
    void extractGpgKeyIdLongForm() {
        String stderr = """
                gpg: Signature made Mon 12 May 2025 10:00:00 AM EDT
                gpg:                using RSA key ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234
                gpg: Good signature from "User <user@example.com>" [ultimate]
                """;
        assertEquals("ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234", GpgRunner.extractGpgKeyId(stderr));
    }

    @Test
    void extractGpgKeyIdNotFound() {
        assertNull(GpgRunner.extractGpgKeyId("gpg: some other output\n"));
    }

    @Test
    void extractGpgKeyIdNullInput() {
        assertNull(GpgRunner.extractGpgKeyId(null));
    }

    // --- extractSignerUserId ---

    @Test
    void extractSignerUserIdFromStderr() {
        String stderr = """
                gpg: Signature made Mon 12 May 2025 10:00:00 AM EDT
                gpg:                using RSA key 4AEE18F83AFDEB23
                gpg: Good signature from "User Name <user@example.com>" [ultimate]
                """;
        assertEquals("User Name <user@example.com>", GpgRunner.extractSignerUserId(stderr));
    }

    @Test
    void extractSignerUserIdNoGoodSignature() {
        String stderr = """
                gpg: Signature made Mon 12 May 2025 10:00:00 AM EDT
                gpg:                using RSA key 4AEE18F83AFDEB23
                gpg: Can't check signature: No public key
                """;
        assertNull(GpgRunner.extractSignerUserId(stderr));
    }

    @Test
    void extractSignerUserIdNullInput() {
        assertNull(GpgRunner.extractSignerUserId(null));
    }

    // --- extractAlgorithm ---

    @Test
    void extractAlgorithmRsa() {
        String stderr = """
                gpg: Signature made Mon 12 May 2025 10:00:00 AM EDT
                gpg:                using RSA key 4AEE18F83AFDEB23
                gpg: Good signature from "User <user@example.com>" [ultimate]
                """;
        assertEquals("RSA", GpgRunner.extractAlgorithm(stderr));
    }

    @Test
    void extractAlgorithmEddsa() {
        String stderr = """
                gpg: Signature made Mon 12 May 2025 10:00:00 AM EDT
                gpg:                using EDDSA key ABCD1234ABCD1234
                gpg: Good signature from "User <user@example.com>" [ultimate]
                """;
        assertEquals("EDDSA", GpgRunner.extractAlgorithm(stderr));
    }

    @Test
    void extractAlgorithmNullInput() {
        assertNull(GpgRunner.extractAlgorithm(null));
    }

    @Test
    void extractAlgorithmNotFound() {
        assertNull(GpgRunner.extractAlgorithm("gpg: some other output\n"));
    }
}
