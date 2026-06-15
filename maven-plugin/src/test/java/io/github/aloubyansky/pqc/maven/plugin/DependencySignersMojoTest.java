package io.github.aloubyansky.pqc.maven.plugin;

import static org.junit.jupiter.api.Assertions.*;

import io.github.aloubyansky.pqc.maven.core.SignatureInfo;
import io.github.aloubyansky.pqc.maven.core.VerificationResult;
import java.util.List;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.junit.jupiter.api.Test;

class DependencySignersMojoTest {

    @Test
    void inspectSignatures_noAscFile() {
        DependencySignersMojo mojo = createMojo(null);
        Artifact artifact = createArtifact("com.example", "lib", "1.0");

        List<DependencySignersMojo.SignedArtifact> results = mojo.inspectSignatures(artifact,
                new io.github.aloubyansky.pqc.maven.core.GpgRunner(), null);
        assertEquals(1, results.size());
        assertEquals(VerificationResult.NOT_PRESENT, results.get(0).signatureInfo().result());
        assertNull(results.get(0).signatureInfo().keyId());
        assertNull(results.get(0).repoId());
    }

    @Test
    void artifactSigner_v4WithSigner() {
        DependencySignersMojo.SignedArtifact signer = new DependencySignersMojo.SignedArtifact(
                "com.example:lib:1.0", "central",
                new SignatureInfo(4, "ABCD1234", "RSA", "User <user@example.com>", VerificationResult.PASS));
        assertEquals("com.example:lib:1.0", signer.coordinates());
        assertEquals("central", signer.repoId());
        assertEquals(4, signer.signatureInfo().version());
        assertEquals("ABCD1234", signer.signatureInfo().keyId());
        assertEquals("User <user@example.com>", signer.signatureInfo().signerUserId());
    }

    @Test
    void artifactSigner_v6Detected() {
        DependencySignersMojo.SignedArtifact signer = new DependencySignersMojo.SignedArtifact(
                "com.example:lib:1.0", "central",
                new SignatureInfo(6, null, null, null, VerificationResult.SKIPPED));
        assertEquals(6, signer.signatureInfo().version());
        assertNull(signer.signatureInfo().keyId());
        assertEquals(VerificationResult.SKIPPED, signer.signatureInfo().result());
    }

    @Test
    void artifactSigner_noSignature() {
        DependencySignersMojo.SignedArtifact signer = new DependencySignersMojo.SignedArtifact(
                "com.example:lib:1.0", null,
                new SignatureInfo(-1, null, null, null, VerificationResult.NOT_PRESENT));
        assertNull(signer.repoId());
        assertEquals(-1, signer.signatureInfo().version());
    }

    // --- formatCoordinates tests ---

    @Test
    void formatCoordinates_simpleJar() {
        Artifact artifact = createArtifact("com.example", "lib", "1.0");
        assertEquals("com.example:lib:1.0", DependencySignersMojo.formatCoordinates(artifact));
    }

    @Test
    void formatCoordinates_withClassifier() {
        Artifact artifact = new DefaultArtifact(
                "com.example", "lib", "1.0", "compile", "jar", "sources", new DefaultArtifactHandler("jar"));
        assertEquals("com.example:lib:jar:sources:1.0", DependencySignersMojo.formatCoordinates(artifact));
    }

    @Test
    void formatCoordinates_nonJarType() {
        Artifact artifact = new DefaultArtifact(
                "com.example", "lib", "1.0", "compile", "pom", "", new DefaultArtifactHandler("pom"));
        assertEquals("com.example:lib:pom:1.0", DependencySignersMojo.formatCoordinates(artifact));
    }

    @Test
    void formatCoordinates_nonJarTypeWithClassifier() {
        Artifact artifact = new DefaultArtifact(
                "com.example", "lib", "1.0", "compile", "zip", "dist", new DefaultArtifactHandler("zip"));
        assertEquals("com.example:lib:zip:dist:1.0", DependencySignersMojo.formatCoordinates(artifact));
    }

    @Test
    void fetchMissingSignerInfo_reverifiesAfterKeyFetch() throws Exception {
        DependencySignersMojo mojo = createMojo(null);
        setField(mojo, "keyservers", "hkps://keyserver.ubuntu.com");

        // Create temp files to act as artifact and signature
        java.nio.file.Path artifactFile = java.nio.file.Files.createTempFile("artifact", ".jar");
        java.nio.file.Path signatureFile = java.nio.file.Files.createTempFile("artifact", ".jar.asc");
        try {
            // Simulate a dependency whose key was not in the keyring at verify time
            var results = new java.util.ArrayList<>(List.of(
                    new DependencySignersMojo.SignedArtifact(
                            "com.example:lib:1.0", "central",
                            new SignatureInfo(4, "ABCD1234ABCD1234", "RSA", null, VerificationResult.NO_KEY),
                            artifactFile, signatureFile)));

            // Stub GpgRunner: receiveKey succeeds, verify returns PASS with signer info
            var gpg = new io.github.aloubyansky.pqc.maven.core.GpgRunner() {
                @Override
                public boolean receiveKey(String keyId, String keyserver) {
                    return true;
                }

                @Override
                public VerifyResult verify(java.nio.file.Path artifact, java.nio.file.Path signature) {
                    return new VerifyResult(VerificationResult.PASS,
                            "ABCD1234ABCD1234", "RSA", "Test User <test@example.com>");
                }
            };

            mojo.fetchMissingSignerInfo(results, gpg);

            assertEquals(1, results.size());
            SignatureInfo updated = results.get(0).signatureInfo();
            assertEquals("Test User <test@example.com>", updated.signerUserId());
            assertEquals(VerificationResult.PASS, updated.result(),
                    "Result should be PASS after re-verification with fetched key");
        } finally {
            java.nio.file.Files.deleteIfExists(artifactFile);
            java.nio.file.Files.deleteIfExists(signatureFile);
        }
    }

    private DependencySignersMojo createMojo(DependencySignersMojo.ResolvedSignature resolved) {
        return new DependencySignersMojo() {
            @Override
            ResolvedSignature downloadSignatureWithRepo(Artifact artifact) {
                return resolved;
            }
        };
    }

    private static void setField(Object target, String fieldName, Object value) {
        try {
            Class<?> clazz = target.getClass();
            while (clazz != null) {
                try {
                    java.lang.reflect.Field field = clazz.getDeclaredField(fieldName);
                    field.setAccessible(true);
                    field.set(target, value);
                    return;
                } catch (NoSuchFieldException e) {
                    clazz = clazz.getSuperclass();
                }
            }
            throw new NoSuchFieldException(fieldName);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private Artifact createArtifact(String groupId, String artifactId, String version) {
        return new DefaultArtifact(
                groupId, artifactId, version, "compile", "jar", "", new DefaultArtifactHandler("jar"));
    }
}
