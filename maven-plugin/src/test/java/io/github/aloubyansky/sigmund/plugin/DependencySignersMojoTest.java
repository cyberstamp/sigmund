package io.github.aloubyansky.sigmund.plugin;

import static org.junit.jupiter.api.Assertions.*;

import io.github.aloubyansky.sigmund.core.OpenPgpVerifyResult;
import io.github.aloubyansky.sigmund.core.UnverifiedResult;
import io.github.aloubyansky.sigmund.core.Verdict;
import io.github.aloubyansky.sigmund.core.VerifyResult;
import io.github.aloubyansky.sigmund.plugin.SignatureInspector.SignedArtifact;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class DependencySignersMojoTest {

    @Test
    void signedArtifact_v4WithSigner() {
        VerifyResult vr = new OpenPgpVerifyResult(Verdict.PASS,
                "User <user@example.com>", "RSA", 4, "ABCD1234", "ABCD1234");
        SignedArtifact signer = new SignedArtifact(
                "com.example:lib:1.0", "central", vr, null, null);
        assertEquals("com.example:lib:1.0", signer.coordinates());
        assertEquals("central", signer.repoId());
        assertInstanceOf(OpenPgpVerifyResult.class, signer.verifyResult());
        OpenPgpVerifyResult opvr = (OpenPgpVerifyResult) signer.verifyResult();
        assertEquals(4, opvr.version());
        assertEquals("ABCD1234", opvr.preferredKeyId());
        assertEquals("User <user@example.com>", opvr.signerDisplayName());
    }

    @Test
    void signedArtifact_v6Detected() {
        VerifyResult vr = new OpenPgpVerifyResult(Verdict.SKIPPED,
                null, null, 6, null, null);
        SignedArtifact signer = new SignedArtifact(
                "com.example:lib:1.0", "central", vr, null, null);
        OpenPgpVerifyResult opvr = (OpenPgpVerifyResult) signer.verifyResult();
        assertEquals(6, opvr.version());
        assertNull(opvr.preferredKeyId());
        assertEquals(Verdict.SKIPPED, signer.verdict());
    }

    @Test
    void signedArtifact_noSignature() {
        SignedArtifact signer = new SignedArtifact(
                "com.example:lib:1.0", null, Verdict.SKIPPED);
        assertNull(signer.repoId());
        assertInstanceOf(UnverifiedResult.class, signer.verifyResult());
        assertEquals(Verdict.SKIPPED, signer.verdict());
    }

    // --- ArtifactCoords.toString tests ---

    @Test
    void artifactCoords_simpleJar() {
        ArtifactCoords coords = createArtifact("com.example", "lib", "1.0");
        assertEquals("com.example:lib:1.0", coords.toString());
    }

    @Test
    void artifactCoords_withClassifier() {
        ArtifactCoords coords = new ArtifactCoords(
                "com.example", "lib", "sources", "jar", "1.0");
        assertEquals("com.example:lib:jar:sources:1.0", coords.toString());
    }

    @Test
    void artifactCoords_nonJarType() {
        ArtifactCoords coords = new ArtifactCoords(
                "com.example", "lib", "", "pom", "1.0");
        assertEquals("com.example:lib:pom:1.0", coords.toString());
    }

    @Test
    void artifactCoords_nonJarTypeWithClassifier() {
        ArtifactCoords coords = new ArtifactCoords(
                "com.example", "lib", "dist", "zip", "1.0");
        assertEquals("com.example:lib:zip:dist:1.0", coords.toString());
    }

    @Nested
    class GenerateSignerIdTests {

        private final DependencySignersMojo mojo = new DependencySignersMojo();

        @Test
        void normalUidProducesKebabCaseId() {
            assertEquals("john-smith",
                    mojo.generateSignerId("John Smith <john@example.com>", 1));
        }

        @Test
        void uidWithoutEmailBrackets() {
            assertEquals("jane-doe", mojo.generateSignerId("Jane Doe", 1));
        }

        @Test
        void emptyNameFallsBackToCounter() {
            assertEquals("signer-1", mojo.generateSignerId(" <user@example.com>", 1));
        }

        @Test
        void specialCharsOnlyFallsBackToCounter() {
            assertEquals("signer-2", mojo.generateSignerId("... <user@example.com>", 2));
        }

        @Test
        void nullUidFallsBackToCounter() {
            assertEquals("signer-3", mojo.generateSignerId(null, 3));
        }

        @Test
        void collisionProducesUniqueSuffix() {
            VerifyResult vr1 = new OpenPgpVerifyResult(Verdict.PASS,
                    "John Smith <john@a.com>", "RSA", 4, "KEY1", "KEY1");
            VerifyResult vr2 = new OpenPgpVerifyResult(Verdict.PASS,
                    "John Smith <john@b.com>", "RSA", 4, "KEY2", "KEY2");

            Map<String, DependencySignersMojo.SignerInfo> existingSigners = new LinkedHashMap<>();
            var info1 = new DependencySignersMojo.SignerInfo(
                    mojo.resolveUniqueSignerId(vr1, 1, existingSigners, Set.of()), vr1);
            existingSigners.put("KEY1", info1);

            String id2 = mojo.resolveUniqueSignerId(vr2, 2, existingSigners, Set.of());
            assertEquals("john-smith", info1.id);
            assertEquals("john-smith-2", id2);
        }

        @Test
        void collisionWithReservedIds() {
            VerifyResult vr = new OpenPgpVerifyResult(Verdict.PASS,
                    "Alice <alice@example.com>", "RSA", 4, "KEY1", "KEY1");
            String id = mojo.resolveUniqueSignerId(vr, 1, new LinkedHashMap<>(), Set.of("alice"));
            assertEquals("alice-2", id);
        }
    }

    @Nested
    class SignerInfoTests {

        @Test
        void v4KeyClassifiedAsPgp4() {
            VerifyResult vr = new OpenPgpVerifyResult(Verdict.PASS,
                    "User <user@example.com>", "RSA", 4, null, "FP4");
            var info = new DependencySignersMojo.SignerInfo("test", vr);
            assertEquals("FP4", info.pgp4Key);
            assertNull(info.pgp6Key);
        }

        @Test
        void v6KeyClassifiedAsPgp6() {
            VerifyResult vr = new OpenPgpVerifyResult(Verdict.PASS,
                    "User <user@example.com>", "ML-DSA-87+Ed448", 6, null, "FP6");
            var info = new DependencySignersMojo.SignerInfo("test", vr);
            assertNull(info.pgp4Key);
            assertEquals("FP6", info.pgp6Key);
        }

        @Test
        void mergeAccumulatesBothKeys() {
            VerifyResult vr4 = new OpenPgpVerifyResult(Verdict.PASS,
                    "User <user@example.com>", "RSA", 4, null, "FP4");
            VerifyResult vr6 = new OpenPgpVerifyResult(Verdict.PASS,
                    null, "ML-DSA-87+Ed448", 6, null, "FP6");
            var info = new DependencySignersMojo.SignerInfo("test", vr4);
            info.merge(vr6);
            assertEquals("FP4", info.pgp4Key);
            assertEquals("FP6", info.pgp6Key);
            assertEquals("user@example.com", info.email);
        }
    }

    @Nested
    class SignedArtifactEdgeCases {

        @Test
        void unverifiedWithPassThrows() {
            assertThrows(IllegalArgumentException.class,
                    () -> new SignedArtifact("coords", null, Verdict.PASS));
        }

        @Test
        void unverifiedWithFail() {
            var sa = new SignedArtifact("coords", "repo", Verdict.FAIL);
            assertEquals(Verdict.FAIL, sa.verdict());
            assertInstanceOf(io.github.aloubyansky.sigmund.core.UnverifiedResult.class, sa.verifyResult());
        }
    }

    private ArtifactCoords createArtifact(String groupId, String artifactId, String version) {
        return new ArtifactCoords(groupId, artifactId, "", "jar", version);
    }
}
