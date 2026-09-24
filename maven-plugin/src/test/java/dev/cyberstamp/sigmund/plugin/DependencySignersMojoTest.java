package dev.cyberstamp.sigmund.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.cyberstamp.sigmund.core.ArtifactCoords;
import dev.cyberstamp.sigmund.core.ClaimOutcome;
import dev.cyberstamp.sigmund.core.IndeterminateReason;
import dev.cyberstamp.sigmund.core.OpenPgpVerifyResult;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.UnverifiedResult;
import dev.cyberstamp.sigmund.core.VerifyResult;
import dev.cyberstamp.sigmund.plugin.SignatureInspector.SignedArtifact;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DependencySignersMojoTest {

    private static final ArtifactCoords LIB_COORDS = ArtifactCoords.parse("com.example:lib:1.0");

    @Test
    void signedArtifactV4WithSigner() {
        VerifyResult vr = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null,
                "User <user@example.com>", "RSA", 4, "ABCD1234", "ABCD1234");
        SignedArtifact signer = new SignedArtifact(LIB_COORDS, "central", vr, null, null);
        assertThat(signer.coords()).isEqualTo(LIB_COORDS);
        assertThat(signer.repoId()).isEqualTo("central");
        assertThat(signer.verifyResult()).isInstanceOf(OpenPgpVerifyResult.class);
        OpenPgpVerifyResult opvr = (OpenPgpVerifyResult) signer.verifyResult();
        assertThat(opvr.version()).isEqualTo(4);
        assertThat(opvr.preferredKeyId()).isEqualTo("ABCD1234");
        assertThat(opvr.signerDisplayName()).isEqualTo("User <user@example.com>");
    }

    @Test
    void signedArtifactV6Detected() {
        VerifyResult vr = new OpenPgpVerifyResult(ClaimOutcome.INDETERMINATE, IndeterminateReason.UNSUPPORTED_ALGORITHM,
                null, null, 6, null, null);
        SignedArtifact signer = new SignedArtifact(LIB_COORDS, "central", vr, null, null);
        OpenPgpVerifyResult opvr = (OpenPgpVerifyResult) signer.verifyResult();
        assertThat(opvr.version()).isEqualTo(6);
        assertThat(opvr.preferredKeyId()).isNull();
        assertThat(signer.isIndeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM)).isTrue();
    }

    @Test
    void signedArtifactNoSignature() {
        SignedArtifact signer = SignedArtifact.noClaim(LIB_COORDS, null);
        assertThat(signer.repoId()).isNull();
        assertThat(signer.verifyResult()).isNull();
        assertThat(signer.hasClaim()).isFalse();
    }

    // --- ArtifactCoords.toString tests ---

    @Test
    void artifactCoordsSimpleJar() {
        ArtifactCoords coords = createArtifact("com.example", "lib", "1.0");
        assertThat(coords.toString()).isEqualTo("com.example:lib:1.0");
    }

    @Test
    void artifactCoordsWithClassifier() {
        ArtifactCoords coords = new ArtifactCoords(
                "com.example", "lib", "sources", "jar", "1.0");
        assertThat(coords.toString()).isEqualTo("com.example:lib:jar:sources:1.0");
    }

    @Test
    void artifactCoordsNonJarType() {
        ArtifactCoords coords = new ArtifactCoords(
                "com.example", "lib", "", "pom", "1.0");
        assertThat(coords.toString()).isEqualTo("com.example:lib:pom:1.0");
    }

    @Test
    void artifactCoordsNonJarTypeWithClassifier() {
        ArtifactCoords coords = new ArtifactCoords(
                "com.example", "lib", "dist", "zip", "1.0");
        assertThat(coords.toString()).isEqualTo("com.example:lib:zip:dist:1.0");
    }

    @Nested
    class GenerateSignerIdTests {

        private final DependencySignersMojo mojo = new DependencySignersMojo();

        @Test
        void normalUidProducesKebabCaseId() {
            assertThat(mojo.generateSignerId("John Smith <john@example.com>", 1))
                    .isEqualTo("john-smith");
        }

        @Test
        void uidWithoutEmailBrackets() {
            assertThat(mojo.generateSignerId("Jane Doe", 1)).isEqualTo("jane-doe");
        }

        @Test
        void emptyNameFallsBackToCounter() {
            assertThat(mojo.generateSignerId(" <user@example.com>", 1)).isEqualTo("signer-1");
        }

        @Test
        void specialCharsOnlyFallsBackToCounter() {
            assertThat(mojo.generateSignerId("... <user@example.com>", 2)).isEqualTo("signer-2");
        }

        @Test
        void nullUidFallsBackToCounter() {
            assertThat(mojo.generateSignerId(null, 3)).isEqualTo("signer-3");
        }

        @Test
        void collisionProducesUniqueSuffix() {
            VerifyResult vr1 = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null,
                    "John Smith <john@a.com>", "RSA", 4, "KEY1", "KEY1");
            VerifyResult vr2 = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null,
                    "John Smith <john@b.com>", "RSA", 4, "KEY2", "KEY2");

            Map<String, DependencySignersMojo.SignerInfo> existingSigners = new LinkedHashMap<>();
            var info1 = new DependencySignersMojo.SignerInfo(
                    mojo.resolveUniqueSignerId(vr1, 1, existingSigners, Set.of()), vr1);
            existingSigners.put("KEY1", info1);

            String id2 = mojo.resolveUniqueSignerId(vr2, 2, existingSigners, Set.of());
            assertThat(info1.id).isEqualTo("john-smith");
            assertThat(id2).isEqualTo("john-smith-2");
        }

        @Test
        void collisionWithReservedIds() {
            VerifyResult vr = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null,
                    "Alice <alice@example.com>", "RSA", 4, "KEY1", "KEY1");
            String id = mojo.resolveUniqueSignerId(vr, 1, new LinkedHashMap<>(), Set.of("alice"));
            assertThat(id).isEqualTo("alice-2");
        }
    }

    @Nested
    class SignerInfoTests {

        @Test
        void v4KeyClassifiedAsPgp4() {
            VerifyResult vr = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null,
                    "User <user@example.com>", "RSA", 4, null, "FP4");
            var info = new DependencySignersMojo.SignerInfo("test", vr);
            assertThat(info.pgp4Key).isEqualTo("FP4");
            assertThat(info.pgp6Key).isNull();
        }

        @Test
        void v6KeyClassifiedAsPgp6() {
            VerifyResult vr = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null,
                    "User <user@example.com>", "ML-DSA-87+Ed448", 6, null, "FP6");
            var info = new DependencySignersMojo.SignerInfo("test", vr);
            assertThat(info.pgp4Key).isNull();
            assertThat(info.pgp6Key).isEqualTo("FP6");
        }

        @Test
        void mergeAccumulatesBothKeys() {
            VerifyResult vr4 = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null,
                    "User <user@example.com>", "RSA", 4, null, "FP4");
            VerifyResult vr6 = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null,
                    null, "ML-DSA-87+Ed448", 6, null, "FP6");
            var info = new DependencySignersMojo.SignerInfo("test", vr4);
            info.merge(vr6);
            assertThat(info.pgp4Key).isEqualTo("FP4");
            assertThat(info.pgp6Key).isEqualTo("FP6");
            assertThat(info.email).isEqualTo("user@example.com");
        }
    }

    @Nested
    class SignedArtifactEdgeCases {

        @Test
        void unverifiedResultCannotClaimVerified() {
            assertThatThrownBy(() -> new UnverifiedResult(ClaimOutcome.VERIFIED, null))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void toolUnavailableIsIndeterminateNotFailed() {
            var sa = SignedArtifact.toolUnavailable(LIB_COORDS, "repo");
            assertThat(sa.isFailed()).isFalse();
            assertThat(sa.isIndeterminate(IndeterminateReason.TOOL_UNAVAILABLE)).isTrue();
            assertThat(sa.verifyResult()).isInstanceOf(UnverifiedResult.class);
        }
    }

    @Nested
    class ArtifactsWithNoClaim {

        /**
         * An artifact with no signature at all carries no verify result, which is a
         * different thing from a claim no installed tool supports.
         */
        private final SignedArtifact noClaim = SignedArtifact.noClaim(LIB_COORDS, "central");

        private final SignedArtifact signed = new SignedArtifact(
                ArtifactCoords.parse("com.example:other:1.0"), "central",
                new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, "User <user@example.com>",
                        "RSA", 4, "ABCD1234", "ABCD1234"),
                null, null);

        @Test
        void areListedAsUnsignedInTheReport() {
            RecordingLog log = new RecordingLog();
            DependencySignersMojo mojo = new DependencySignersMojo();
            mojo.setLog(log);

            mojo.logReport(List.of(noClaim, signed));

            assertThat(log.lines).contains("warn: UNSIGNED", "warn:   " + LIB_COORDS);
        }

        @Test
        void areRecordedAsSignatureOptionalInAGeneratedConfig(@TempDir Path dir) throws Exception {
            DependencySignersMojo mojo = new DependencySignersMojo();
            mojo.setLog(new RecordingLog());
            Path configFile = dir.resolve("sigmund.yaml");

            mojo.writeTrustConfigYaml(List.of(noClaim, signed), configFile.toFile());

            SigmundConfig config = SigmundConfig.parse(configFile);
            assertThat(config.trustPolicy().isUnsignedAllowed(LIB_COORDS)).isTrue();
        }
    }

    private ArtifactCoords createArtifact(String groupId, String artifactId, String version) {
        return new ArtifactCoords(groupId, artifactId, "", "jar", version);
    }
}
