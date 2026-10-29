package dev.cyberstamp.sigmund.cli;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.junit.jupiter.api.Test;

/**
 * The CLI's dependency management is the Quarkus BOM's, not the sigstore module's, so it can
 * resolve a different version of a library sigstore-java depends on. sigstore-java's generated
 * Protobuf classes refuse to load on a Protobuf runtime older than the one they were generated
 * with, which fails every command that builds the tools, {@code keygen} included.
 */
class SigstoreClasspathTest {

    @Test
    void sigstoreProtobufClassesLoadOnTheCliClasspath() {
        assertDoesNotThrow(() -> Class.forName("dev.sigstore.proto.trustroot.v1.TrustedRoot"));
    }
}
