package io.github.aloubyansky.pqc.maven.plugin;

import static org.junit.jupiter.api.Assertions.*;

import io.github.aloubyansky.pqc.maven.core.GpgRunner;
import io.github.aloubyansky.pqc.maven.core.HybridVerifier;
import io.github.aloubyansky.pqc.maven.core.VerificationResult;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class VerifyDependenciesMojoTest {

    @TempDir
    Path tempDir;

    @Test
    void allPass_noFailure() {
        List<VerifyDependenciesMojo.ArtifactVerification> results = List.of(
                new VerifyDependenciesMojo.ArtifactVerification(
                        "com.example", "lib", "1.0", "jar",
                        VerificationResult.PASS, "0xABCD",
                        VerificationResult.PASS, false));
        String failure = VerifyDependenciesMojo.evaluatePolicy(results, "warn", true);
        assertNull(failure);
    }

    @Test
    void gpgFail_alwaysFails() {
        List<VerifyDependenciesMojo.ArtifactVerification> results = List.of(
                new VerifyDependenciesMojo.ArtifactVerification(
                        "com.example", "lib", "1.0", "jar",
                        VerificationResult.FAIL, null,
                        VerificationResult.NOT_PRESENT, false));
        String failure = VerifyDependenciesMojo.evaluatePolicy(results, "warn", true);
        assertNotNull(failure);
        assertTrue(failure.contains("failed"));
    }

    @Test
    void pqcFail_alwaysFails() {
        List<VerifyDependenciesMojo.ArtifactVerification> results = List.of(
                new VerifyDependenciesMojo.ArtifactVerification(
                        "com.example", "lib", "1.0", "jar",
                        VerificationResult.PASS, "0xABCD",
                        VerificationResult.FAIL, false));
        String failure = VerifyDependenciesMojo.evaluatePolicy(results, "warn", true);
        assertNotNull(failure);
    }

    @Test
    void pqcUnchecked_failIfPqcUncheckedTrue() {
        List<VerifyDependenciesMojo.ArtifactVerification> results = List.of(
                new VerifyDependenciesMojo.ArtifactVerification(
                        "com.example", "lib", "1.0", "jar",
                        VerificationResult.PASS, "0xABCD",
                        VerificationResult.PASS, true));
        String failure = VerifyDependenciesMojo.evaluatePolicy(results, "warn", true);
        assertNotNull(failure);
    }

    @Test
    void pqcUnchecked_okWhenFailIfPqcUncheckedFalse() {
        List<VerifyDependenciesMojo.ArtifactVerification> results = List.of(
                new VerifyDependenciesMojo.ArtifactVerification(
                        "com.example", "lib", "1.0", "jar",
                        VerificationResult.PASS, "0xABCD",
                        VerificationResult.PASS, true));
        String failure = VerifyDependenciesMojo.evaluatePolicy(results, "warn", false);
        assertNull(failure);
    }

    @Test
    void skipped_passes() {
        List<VerifyDependenciesMojo.ArtifactVerification> results = List.of(
                new VerifyDependenciesMojo.ArtifactVerification(
                        "com.example", "lib", "1.0", "jar",
                        VerificationResult.SKIPPED, null,
                        VerificationResult.SKIPPED, false));
        String failure = VerifyDependenciesMojo.evaluatePolicy(results, "warn", true);
        assertNull(failure);
    }

    @Test
    void unmappedPolicy_fail() {
        List<VerifyDependenciesMojo.ArtifactVerification> results = List.of(
                new VerifyDependenciesMojo.ArtifactVerification(
                        "com.example", "lib", "1.0", "jar",
                        null, null,
                        null, false));
        String failure = VerifyDependenciesMojo.evaluatePolicy(results, "fail", true);
        assertNotNull(failure);
    }

    @Test
    void unmappedPolicy_warn_noFailure() {
        List<VerifyDependenciesMojo.ArtifactVerification> results = List.of(
                new VerifyDependenciesMojo.ArtifactVerification(
                        "com.example", "lib", "1.0", "jar",
                        null, null,
                        null, false));
        String failure = VerifyDependenciesMojo.evaluatePolicy(results, "warn", true);
        assertNull(failure);
    }

    @Test
    void gpgNotPresent_failsWithNoSignatureMessage() {
        List<VerifyDependenciesMojo.ArtifactVerification> results = List.of(
                new VerifyDependenciesMojo.ArtifactVerification(
                        "com.example", "lib", "1.0", "jar",
                        VerificationResult.NOT_PRESENT, null,
                        VerificationResult.NOT_PRESENT, false));
        String failure = VerifyDependenciesMojo.evaluatePolicy(results, "warn", true);
        assertNotNull(failure);
        assertTrue(failure.contains("no signature file found"));
    }

    // --- verifyArtifact tests ---

    @Test
    void verifyArtifact_unmapped() throws IOException {
        KeysMap map = parseKeysMap("");
        VerifyDependenciesMojo mojo = createMojo(null);
        Artifact artifact = createArtifact("com.example", "unknown", "1.0");

        VerifyDependenciesMojo.ArtifactVerification result = mojo.verifyArtifact(artifact, map, dummyVerifier());
        assertNull(result.gpgResult());
        assertNull(result.pqcResult());
    }

    @Test
    void verifyArtifact_noSig() throws IOException {
        KeysMap map = parseKeysMap("com.example:lib = noSig");
        VerifyDependenciesMojo mojo = createMojo(null);
        Artifact artifact = createArtifact("com.example", "lib", "1.0");

        VerifyDependenciesMojo.ArtifactVerification result = mojo.verifyArtifact(artifact, map, dummyVerifier());
        assertEquals(VerificationResult.SKIPPED, result.gpgResult());
        assertEquals(VerificationResult.SKIPPED, result.pqcResult());
    }

    @Test
    void verifyArtifact_noAscFile() throws IOException {
        KeysMap map = parseKeysMap("com.example:lib = 0xABCD1234ABCD1234");
        VerifyDependenciesMojo mojo = createMojo(null);
        Artifact artifact = createArtifact("com.example", "lib", "1.0");

        VerifyDependenciesMojo.ArtifactVerification result = mojo.verifyArtifact(artifact, map, dummyVerifier());
        assertEquals(VerificationResult.NOT_PRESENT, result.gpgResult());
        assertEquals(VerificationResult.NOT_PRESENT, result.pqcResult());
    }

    private VerifyDependenciesMojo createMojo(Path ascFile) {
        return new VerifyDependenciesMojo() {
            @Override
            Path downloadSignature(Artifact artifact) {
                return ascFile;
            }
        };
    }

    private Artifact createArtifact(String groupId, String artifactId, String version) {
        return new DefaultArtifact(
                groupId, artifactId, version, "compile", "jar", "", new DefaultArtifactHandler("jar"));
    }

    private HybridVerifier dummyVerifier() {
        return new HybridVerifier(new GpgRunner(), null);
    }

    private KeysMap parseKeysMap(String content) throws IOException {
        Path file = tempDir.resolve("keys.map");
        Files.writeString(file, content);
        return KeysMap.parse(file);
    }

    // --- fingerprintsMatch tests ---

    @Test
    void fingerprintsMatch_fullMatch() {
        assertTrue(VerifyDependenciesMojo.fingerprintsMatch(
                "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234",
                "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234"));
    }

    @Test
    void fingerprintsMatch_longKeyIdMatchesFullFingerprint() {
        assertTrue(VerifyDependenciesMojo.fingerprintsMatch(
                "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234",
                "ABCD1234ABCD1234ABCD1234"));
    }

    @Test
    void fingerprintsMatch_shortIdRejected() {
        assertFalse(VerifyDependenciesMojo.fingerprintsMatch(
                "1234", "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234"));
    }

    @Test
    void fingerprintsMatch_mismatch() {
        assertFalse(VerifyDependenciesMojo.fingerprintsMatch(
                "AAAA1234AAAA1234AAAA1234AAAA1234AAAA1234",
                "BBBB1234BBBB1234BBBB1234BBBB1234BBBB1234"));
    }

    @Test
    void fingerprintsMatch_caseInsensitive() {
        assertTrue(VerifyDependenciesMojo.fingerprintsMatch(
                "abcd1234abcd1234abcd1234abcd1234abcd1234",
                "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234"));
    }
}
