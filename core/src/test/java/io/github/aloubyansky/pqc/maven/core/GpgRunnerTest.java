package io.github.aloubyansky.pqc.maven.core;

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
}
