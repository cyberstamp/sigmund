package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SigmundTest {

    @TempDir
    Path tempDir;

    @Nested
    class SignerCreation {

        @Test
        void signerReturnsAllSigningTools() throws IOException {
            var signing = mockTool("gpg", true, true, Set.of("pgp4"));
            var verifyOnly = mockTool("sq", true, false, Set.of("pgp6"));
            try (var sigmund = Sigmund.builder().addTool(signing).addTool(verifyOnly).build()) {

                Signer signer = sigmund.signer();
                Path artifact = createTempFile("test.jar");
                SigningOutput output = signer.sign(artifact, tempDir);

                assertThat(output.files().size()).isEqualTo(1);
                assertThat(output.files().get(0).toolName()).isEqualTo("gpg");
            }
        }

        @Test
        void signerExcludesUnconfiguredTools() throws IOException {
            var bc = mockTool("bc", true, true, Set.of("pgp4"));
            var gpg = mockTool("gpg", true, true, Set.of("pgp4"));
            var config = new SigmundConfig(null, null, null,
                    new SigningConfig(null, List.of("bc"), List.of(), Map.of()),
                    null, null);
            try (var sigmund = Sigmund.builder().config(config)
                    .addTool(bc).addTool(gpg).build()) {

                Signer signer = sigmund.signer();
                Path artifact = createTempFile("configured-only.jar");
                SigningOutput output = signer.sign(artifact, tempDir);

                assertThat(output.files().size()).isEqualTo(1);
                assertThat(output.files().get(0).toolName()).isEqualTo("bc");
            }
        }

        @Test
        void signerThrowsWhenConfiguredToolCannotSign() {
            var bc = mockTool("bc", true, false, Set.of("pgp4"));
            var config = new SigmundConfig(null, null, null,
                    new SigningConfig(null, List.of("bc"), List.of(), Map.of()),
                    null, null);
            try (var sigmund = Sigmund.builder().config(config)
                    .addTool(bc).build()) {

                assertThatThrownBy(sigmund::signer)
                        .isInstanceOf(SigmundException.class)
                        .hasMessageContaining("bc")
                        .hasMessageContaining("not signing-capable");
            }
        }

        @Test
        void signerWithCredentialTypes() {
            var v4Tool = mockTool("gpg", true, true, Set.of("pgp4"));
            var v6Tool = mockTool("sq", true, true, Set.of("pgp6"));
            var config = new SigmundConfig(null, null, null,
                    new SigningConfig(null, List.of(), List.of("pgp6"), Map.of()),
                    null, null);
            try (var sigmund = Sigmund.builder().config(config)
                    .addTool(v4Tool).addTool(v6Tool).build()) {

                Signer signer = sigmund.signer();
                Path artifact = createTempFile("test.jar");
                SigningOutput output = signer.sign(artifact, tempDir);

                assertThat(output.files().size()).isEqualTo(1);
                assertThat(output.files().get(0).toolName()).isEqualTo("sq");
            }
        }

        @Test
        void credentialTypesWrittenAsInTheDocsSelectTheirTools() throws IOException {
            var v4Tool = mockTool("gpg", true, true, Set.of("pgp4"));
            var v6Tool = mockTool("sq", true, true, Set.of("pgp6"));
            var config = SigmundConfigParser.parse("<test>",
                    new StringReader("signing: { credential-types: [pgp6] }"));
            try (var sigmund = Sigmund.builder().config(config)
                    .addTool(v4Tool).addTool(v6Tool).build()) {

                SigningOutput output = sigmund.signer().sign(createTempFile("documented.jar"), tempDir);

                assertThat(output.files()).extracting(SignedFile::toolName).containsExactly("sq");
            }
        }

        @Test
        void signerWithNamedProfile() {
            var v4Tool = mockTool("gpg", true, true, Set.of("pgp4"));
            var v6Tool = mockTool("sq", true, true, Set.of("pgp6"));
            var config = new SigmundConfig(null, null, null,
                    new SigningConfig(null, List.of(), List.of(),
                            Map.of("v6-only", List.of("pgp6"),
                                    "classical", List.of("pgp4"))),
                    null, null);
            try (var sigmund = Sigmund.builder().config(config)
                    .addTool(v4Tool).addTool(v6Tool).build()) {

                Signer v6Signer = sigmund.signer("v6-only");
                Path artifact = createTempFile("test.jar");
                SigningOutput output = v6Signer.sign(artifact, tempDir);

                assertThat(output.files().size()).isEqualTo(1);
                assertThat(output.files().get(0).toolName()).isEqualTo("sq");

                Signer classicalSigner = sigmund.signer("classical");
                SigningOutput classicalOutput = classicalSigner.sign(artifact, tempDir);

                assertThat(classicalOutput.files().size()).isEqualTo(1);
                assertThat(classicalOutput.files().get(0).toolName()).isEqualTo("gpg");
            }
        }

        @Test
        void aToolchainToolWithNoKeyOfTheRequestedTypesDoesNotSign() {
            var gpg = mockTool("gpg", true, true, Set.of("pgp4"));
            var sq = mockTool("sq", true, true, Set.of("pgp6"));
            var config = new SigmundConfig(null, null, null,
                    new SigningConfig(null, List.of("gpg", "sq"), List.of(), Map.of("pqc", List.of("pgp6"))),
                    null, null);
            try (var sigmund = Sigmund.builder().config(config).addTool(gpg).addTool(sq).build()) {

                SigningPlan plan = sigmund.signer("pqc").plan();

                assertThat(plan.keys()).extracting(SigningInfo::toolName).containsExactly("sq");
                assertThat(plan.problems()).isEmpty();
            }
        }

        @Test
        void aRequestedTypeNoToolchainToolHasFailsWhenSigningStarts() throws IOException {
            var gpg = mockTool("gpg", true, true, Set.of("pgp4"));
            var config = new SigmundConfig(null, null, null,
                    new SigningConfig(null, List.of("gpg"), List.of("pgp6"), Map.of()),
                    null, null);
            try (var sigmund = Sigmund.builder().config(config).addTool(gpg).build()) {

                Signer signer = sigmund.signer();

                Path artifact = createTempFile("mismatch.jar");
                assertThatThrownBy(() -> signer.sign(artifact, tempDir))
                        .isInstanceOf(SigmundException.class)
                        .hasMessage("no signing key for requested credential type pgp6; keys in the run: gpg pgp4");
            }
        }

        @Test
        void aToolchainToolNotInTheRunThrowsAtSignerCreation() {
            var config = new SigmundConfig(null, null, null,
                    new SigningConfig(null, List.of("gpg"), List.of(), Map.of()),
                    null, null);
            try (var sigmund = Sigmund.builder().config(config).verificationConfig(onlyTools("bc"))
                    .addTool(mockTool("bc", true, true, Set.of("pgp4"))).build()) {

                assertThatThrownBy(sigmund::signer)
                        .isInstanceOf(SigmundException.class)
                        .hasMessageContaining("gpg")
                        .hasMessageContaining("not available");
            }
        }

        @Test
        void signerWithUnknownProfileThrows() {
            var config = new SigmundConfig(null, null, null,
                    new SigningConfig(null, List.of(), List.of(),
                            Map.of("v6-only", List.of("pgp6"))),
                    null, null);
            try (var sigmund = Sigmund.builder().config(config)
                    .addTool(mockTool("gpg", true, true, Set.of("pgp4"))).build()) {

                assertThatThrownBy(() -> sigmund.signer("nonexistent"))
                        .isInstanceOf(SigmundException.class)
                        .hasMessageContaining("nonexistent");
            }
        }

        @Test
        void signerWithNoSigningConfigThrows() {
            try (var sigmund = Sigmund.builder()
                    .addTool(mockTool("gpg", true, true, Set.of("pgp4"))).build()) {

                assertThatThrownBy(() -> sigmund.signer("any-profile"))
                        .isInstanceOf(SigmundException.class);
            }
        }
    }

    @Nested
    class DirectVerification {

        @Test
        void verifyRoutesToCorrectFormatAndTool() throws IOException {
            Path artifact = createTempFile("test.jar");
            Path sigFile = createTempFile("test.jar.asc",
                    "-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----\n");

            var claim = new OpenPgpClaim("armored", 4, "FP", 1, null);
            var format = mockFormat("openpgp", ".asc", true, List.of(claim));
            var tool = mockVerifyingTool("gpg", format, true,
                    new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, "Alice", "RSA", 4, "KEY", "FP"));
            try (var sigmund = Sigmund.builder().addTool(tool).build()) {

                SignatureVerificationReport report = sigmund.verify(artifact, sigFile);

                assertThat(report.isPass()).isTrue();
                assertThat(report.files().size()).isEqualTo(1);
                assertThat(report.files().get(0).format()).isEqualTo("openpgp");
            }
        }

        @Test
        void verifyFallsThroughOnSkipped() throws IOException {
            Path artifact = createTempFile("fallthrough.jar");
            Path sigFile = createTempFile("fallthrough.jar.asc",
                    "-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----\n");

            var claim = new OpenPgpClaim("armored", 4, "FP", 1, null);
            var format = mockFormat("openpgp", ".asc", true, List.of(claim));
            var skippingTool = mockVerifyingTool("bc", format, true,
                    new OpenPgpVerifyResult(ClaimOutcome.INDETERMINATE, IndeterminateReason.UNSUPPORTED_ALGORITHM, null, null,
                            4, null, null));
            var passingTool = mockVerifyingTool("gpg", format, true,
                    new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, "Alice", "RSA", 4, "KEY", "FP"));
            try (var sigmund = Sigmund.builder().addTool(skippingTool).addTool(passingTool).build()) {

                SignatureVerificationReport report = sigmund.verify(artifact, sigFile);

                assertThat(report.isPass()).isTrue();
                assertThat(report.files().size()).isEqualTo(1);
                assertThat(report.files().get(0).results().size()).isEqualTo(1);
                assertThat(report.files().get(0).results().get(0).isVerified()).isTrue();
            }
        }

        @Test
        void verifyFallsThroughOnNoKey() throws IOException {
            Path artifact = createTempFile("nokey.jar");
            Path sigFile = createTempFile("nokey.jar.asc",
                    "-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----\n");

            var claim = new OpenPgpClaim("armored", 4, "FP", 1, null);
            var format = mockFormat("openpgp", ".asc", true, List.of(claim));
            var noKeyTool = mockVerifyingTool("bc", format, true,
                    new OpenPgpVerifyResult(ClaimOutcome.INDETERMINATE, IndeterminateReason.KEY_UNAVAILABLE, null, "RSA", 4,
                            "KEY", "FP"));
            var passingTool = mockVerifyingTool("gpg", format, true,
                    new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, "Alice", "RSA", 4, "KEY", "FP"));
            try (var sigmund = Sigmund.builder().addTool(noKeyTool).addTool(passingTool).build()) {

                SignatureVerificationReport report = sigmund.verify(artifact, sigFile);

                assertThat(report.isPass()).isTrue();
                assertThat(report.files().get(0).results().get(0).isVerified()).isTrue();
                assertThat(report.files().get(0).results().get(0).signerDisplayName()).isEqualTo("Alice");
            }
        }

        @Test
        void verifyFallsThroughOnFail() throws IOException {
            Path artifact = createTempFile("fail.jar");
            Path sigFile = createTempFile("fail.jar.asc",
                    "-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----\n");

            var claim = new OpenPgpClaim("armored", 4, "FP", 1, null);
            var format = mockFormat("openpgp", ".asc", true, List.of(claim));
            var failTool = mockVerifyingTool("bc", format, true,
                    new OpenPgpVerifyResult(ClaimOutcome.FAILED, null, null, "RSA", 4, "KEY", "FP"));
            var passingTool = mockVerifyingTool("gpg", format, true,
                    new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, "Alice", "RSA", 4, "KEY", "FP"));
            try (var sigmund = Sigmund.builder().addTool(failTool).addTool(passingTool).build()) {

                SignatureVerificationReport report = sigmund.verify(artifact, sigFile);

                assertThat(report.isPass()).isTrue();
                assertThat(report.files().get(0).results().get(0).isVerified()).isTrue();
            }
        }

        @Test
        void verifyKeepsBestNonPassResult() throws IOException {
            Path artifact = createTempFile("best.jar");
            Path sigFile = createTempFile("best.jar.asc",
                    "-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----\n");

            var claim = new OpenPgpClaim("armored", 4, "FP", 1, null);
            var format = mockFormat("openpgp", ".asc", true, List.of(claim));
            var noKeyTool = mockVerifyingTool("bc", format, true,
                    new OpenPgpVerifyResult(ClaimOutcome.INDETERMINATE, IndeterminateReason.KEY_UNAVAILABLE, null, null, 4,
                            "KEY", "FP"));
            var failTool = mockVerifyingTool("gpg", format, true,
                    new OpenPgpVerifyResult(ClaimOutcome.FAILED, null, null, "RSA", 4, "KEY", "FP"));
            try (var sigmund = Sigmund.builder().addTool(noKeyTool).addTool(failTool).build()) {

                SignatureVerificationReport report = sigmund.verify(artifact, sigFile);

                assertThat(report.files().get(0).results().get(0).isFailed()).isTrue();
            }
        }

        @Test
        void verifyAllToolsReturnNoKey() throws IOException {
            Path artifact = createTempFile("allnokey.jar");
            Path sigFile = createTempFile("allnokey.jar.asc",
                    "-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----\n");

            var claim = new OpenPgpClaim("armored", 4, "FP", 1, null);
            var format = mockFormat("openpgp", ".asc", true, List.of(claim));
            var tool1 = mockVerifyingTool("bc", format, true,
                    new OpenPgpVerifyResult(ClaimOutcome.INDETERMINATE, IndeterminateReason.KEY_UNAVAILABLE, null, null, 4,
                            "KEY", "FP"));
            var tool2 = mockVerifyingTool("gpg", format, true,
                    new OpenPgpVerifyResult(ClaimOutcome.INDETERMINATE, IndeterminateReason.KEY_UNAVAILABLE, null, null, 4,
                            "KEY", "FP"));
            try (var sigmund = Sigmund.builder().addTool(tool1).addTool(tool2).build()) {

                SignatureVerificationReport report = sigmund.verify(artifact, sigFile);

                assertThat(report.files().get(0).results().size()).isEqualTo(1);
                assertThat(report.files().get(0).results().get(0).isIndeterminate(IndeterminateReason.KEY_UNAVAILABLE))
                        .isTrue();
            }
        }

        @Test
        void verifyAllToolsSkipReturnsEmpty() throws IOException {
            Path artifact = createTempFile("allskip.jar");
            Path sigFile = createTempFile("allskip.jar.asc",
                    "-----BEGIN PGP SIGNATURE-----\ntest\n-----END PGP SIGNATURE-----\n");

            var claim = new OpenPgpClaim("armored", 4, "FP", 1, null);
            var format = mockFormat("openpgp", ".asc", true, List.of(claim));
            var tool1 = mockVerifyingTool("bc", format, true,
                    new OpenPgpVerifyResult(ClaimOutcome.INDETERMINATE, IndeterminateReason.UNSUPPORTED_ALGORITHM, null, null,
                            4, null, null));
            var tool2 = mockVerifyingTool("gpg", format, true,
                    new OpenPgpVerifyResult(ClaimOutcome.INDETERMINATE, IndeterminateReason.UNSUPPORTED_ALGORITHM, null, null,
                            4, null, null));
            // only the two tools above: an installed sq would otherwise join the toolchain
            VerificationConfig onlyTheseTools = new VerificationConfig(false, false, List.of(),
                    List.of("bc", "gpg"));
            try (var sigmund = Sigmund.builder().verificationConfig(onlyTheseTools)
                    .addTool(tool1).addTool(tool2).build()) {

                SignatureVerificationReport report = sigmund.verify(artifact, sigFile);

                assertThat(report.isLenientPass()).isFalse();
                assertThat(report.files().get(0).results().isEmpty()).isTrue();
            }
        }

        @Test
        void verifyWithUnknownFormatReturnsEmptyResults() throws IOException {
            Path artifact = createTempFile("test.jar");
            Path sigFile = createTempFile("test.jar.unknown", "not a signature");

            var format = mockFormat("openpgp", ".asc", false, List.of());
            var tool = mockVerifyingTool("gpg", format, false, null);
            try (var sigmund = Sigmund.builder().addTool(tool).build()) {

                SignatureVerificationReport report = sigmund.verify(artifact, sigFile);

                assertThat(report.isLenientPass()).isFalse();
            }
        }

        @Test
        void verifyAllAggregatesMultipleFiles() throws IOException {
            Path artifact = createTempFile("test.jar");
            Path sig1 = createTempFile("test.jar.asc", "sig1");
            Path sig2 = createTempFile("test2.jar.asc", "sig2");

            var claim = new OpenPgpClaim("armored", 4, "FP", 1, null);
            var format = mockFormat("openpgp", ".asc", true, List.of(claim));
            var tool = mockVerifyingTool("gpg", format, true,
                    new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, null, "RSA", 4, null, null));
            try (var sigmund = Sigmund.builder().addTool(tool).build()) {

                SignatureVerificationReport report = sigmund.verifyAll(artifact, List.of(sig1, sig2));

                assertThat(report.files().size()).isEqualTo(2);
                assertThat(report.isPass()).isTrue();
            }
        }
    }

    @Nested
    class SignatureExtensions {

        @Test
        void signatureFileExtensionsReturnsRegisteredFormats() {
            var tool = mockTool("gpg", true, false, Set.of("pgp4"));
            try (var sigmund = Sigmund.builder().addTool(tool).build()) {

                Set<String> extensions = sigmund.signatureFileExtensions();

                assertThat(extensions).isNotNull();
                assertThat(extensions.contains(".asc")).isTrue();
            }
        }

        @Test
        void signatureFileExtensionsFromMultipleFormats() {
            var openpgpFormat = mockFormat("openpgp", ".asc", true, List.of());
            var sigstoreFormat = mockFormat("sigstore", ".sigstore.json", false, List.of());
            var pgpTool = mockToolWithFormat("gpg", openpgpFormat, true, false, Set.of("pgp4"));
            var sigstoreTool = mockToolWithFormat("sigstore", sigstoreFormat, true, false, Set.of("sigstore"));
            try (var sigmund = Sigmund.builder().addTool(pgpTool).addTool(sigstoreTool).build()) {

                Set<String> extensions = sigmund.signatureFileExtensions();

                assertThat(extensions.size()).isEqualTo(2);
                assertThat(extensions.contains(".asc")).isTrue();
                assertThat(extensions.contains(".sigstore.json")).isTrue();
            }
        }

        @Test
        void signatureFileExtensionsIsImmutable() {
            var tool = mockTool("gpg", true, false, Set.of("pgp4"));
            try (var sigmund = Sigmund.builder().addTool(tool).build()) {

                assertThatThrownBy(() -> sigmund.signatureFileExtensions().add(".sig"))
                        .isInstanceOf(UnsupportedOperationException.class);
            }
        }
    }

    @Nested
    class ToolAccess {

        @Test
        void toolByName() {
            var gpg = mockTool("gpg", true, false, Set.of("pgp4"));
            var sq = mockTool("sq", true, false, Set.of("pgp6"));
            try (var sigmund = Sigmund.builder().addTool(gpg).addTool(sq).build()) {

                assertThat(sigmund.tool("gpg")).isNotNull();
                assertThat(sigmund.tool("gpg").name()).isEqualTo("gpg");
                assertThat(sigmund.tool("sigstore")).isNull();
            }
        }

        @Test
        void findToolByCapability() {
            var tool = new MockKeyGeneratorTool("sq");
            try (var sigmund = Sigmund.builder().addTool(tool)
                    .verificationConfig(onlyTools("sq")).build()) {

                assertThat(sigmund.findTool(KeyGenerator.class)).isNotNull();
                assertThat(sigmund.findTool(KeyImporter.class)).isNull();
            }
        }

        @Test
        void findToolByCapabilityAndName() {
            var sq = new MockKeyGeneratorTool("sq");
            var other = new MockKeyGeneratorTool("other");
            try (var sigmund = Sigmund.builder().addTool(sq).addTool(other).build()) {

                assertThat(sigmund.findTool(KeyGenerator.class, "sq")).isNotNull();
                assertThat(sigmund.findTool(KeyGenerator.class, "nonexistent")).isNull();
            }
        }

        @Test
        void toolsListIsUnmodifiable() {
            try (var sigmund = Sigmund.builder()
                    .addTool(mockTool("gpg", true, false, Set.of())).build()) {

                assertThatThrownBy(() -> sigmund.tools().add(null))
                        .isInstanceOf(UnsupportedOperationException.class);
            }
        }
    }

    @Nested
    class VerifierCreation {

        @Test
        void closingSigmundClosesTheDirectory() {
            var format = mockFormat("openpgp", ".asc", true, List.of());
            var tool = mockVerifyingTool("gpg", format, true,
                    OpenPgpVerifyResult.indeterminate(IndeterminateReason.KEY_UNAVAILABLE));
            boolean[] closed = { false };
            OpenPgpDirectory directory = new OpenPgpDirectory() {
                @Override
                public String name() {
                    return IssuerKind.KEYS_OPENPGP_ORG;
                }

                @Override
                public List<String> verifiedAddresses(String fingerprint) {
                    return List.of();
                }

                @Override
                public void close() {
                    closed[0] = true;
                }
            };

            Sigmund.builder().addTool(tool).openPgpDirectory(directory).build().close();

            assertThat(closed[0]).isTrue();
        }

        @Test
        void verifierAssessTrusted() {
            var claim = new OpenPgpClaim("armored", 4, null, 1, null);
            var result = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, "Alice <alice@example.com>", "RSA",
                    4, "4AEE18F83AFDEB23", "4AEE18F83AFDEB23000000000000000000000000");
            var format = mockFormat("openpgp", ".asc", true, List.of(claim));
            var tool = mockVerifyingTool("gpg", format, true, result);
            try (var sigmund = Sigmund.builder().addTool(tool).build()) {

                var policy = ruleForNamespace("alice",
                        new KeyCredential("pgp4", "4AEE18F83AFDEB23000000000000000000000000"));
                TrustVerifier verifier = sigmund.verifier(policy);

                Path artifact = createTempFile("test.jar");
                Path sigFile = createTempFile("test.jar.asc", "signature");
                ArtifactCoords artifactId = testArtifact("org.example", "lib", "1.0");

                ArtifactResult assessed = verifier.assess(artifactId, artifact, List.of(sigFile));
                assertThat(assessed.outcome()).isEqualTo(ArtifactOutcome.SATISFIED);
                assertThat(assessed.claims()).hasSize(1);
            }
        }

        @Test
        void verifierAssessUntrusted() {
            var claim = new OpenPgpClaim("armored", 4, null, 1, null);
            var result = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, "Bob <bob@example.com>", "RSA",
                    4, "0000000018F83AFD", "0000000018F83AFD000000000000000000000000");
            var format = mockFormat("openpgp", ".asc", true, List.of(claim));
            var tool = mockVerifyingTool("gpg", format, true, result);
            try (var sigmund = Sigmund.builder().addTool(tool).build()) {

                var policy = ruleForNamespace("alice",
                        new KeyCredential("pgp4", "4AEE18F83AFDEB23000000000000000000000000"));
                TrustVerifier verifier = sigmund.verifier(policy);

                Path artifact = createTempFile("test2.jar");
                Path sigFile = createTempFile("test2.jar.asc", "signature");
                ArtifactCoords artifactId = testArtifact("org.example", "lib", "1.0");

                ArtifactResult assessed = verifier.assess(artifactId, artifact, List.of(sigFile));
                assertThat(assessed.outcome()).isEqualTo(ArtifactOutcome.UNSATISFIED);
            }
        }

        @Test
        void verifierAssessNotConfigured() {
            try (var sigmund = Sigmund.builder()
                    .addTool(mockTool("gpg", true, false, Set.of("pgp4")))
                    .build()) {
                TrustVerifier verifier = sigmund.verifier(RulePolicy.EMPTY);

                Path artifact = createTempFile("test3.jar");
                ArtifactCoords artifactId = testArtifact("org.example", "lib", "1.0");

                ArtifactResult result = verifier.assess(artifactId, artifact, List.of());
                assertThat(result.outcome()).isEqualTo(ArtifactOutcome.NOT_CONFIGURED);
            }
        }
    }

    @Nested
    class BuilderBehavior {

        @Test
        void rejectsUnavailableExplicitTool() {
            var available = mockTool("gpg", true, false, Set.of("pgp4"));
            var unavailable = mockTool("sq", false, false, Set.of("pgp6"));
            assertThatThrownBy(() -> Sigmund.builder().addTool(available).addTool(unavailable).build())
                    .isInstanceOf(SigmundException.class)
                    .hasMessageContaining("sq")
                    .hasMessageContaining("not available");
        }

        @Test
        void anUnknownToolInAToolchainSetThroughTheApiIsError() {
            var tool = mockTool("gpg", true, false, Set.of("pgp4"));
            var verificationConfig = new VerificationConfig(false, false, List.of(),
                    List.of("nonexistent", "gpg"));

            assertThatThrownBy(() -> Sigmund.builder().addTool(tool)
                    .verificationConfig(verificationConfig).build())
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("verification.toolchain: unknown tool 'nonexistent'");
        }

        @Test
        void addToolReplacesExistingByName() {
            var tool1 = mockTool("gpg", true, false, Set.of("pgp4"));
            var tool2 = mockTool("gpg", true, true, Set.of("pgp4"));
            try (var sigmund = Sigmund.builder().addTool(tool1).addTool(tool2)
                    .verificationConfig(onlyTools("gpg")).build()) {

                assertThat(sigmund.tools().size()).isEqualTo(1);
                assertThat(sigmund.tools().get(0).canSign()).isTrue();
            }
        }
    }

    @Nested
    class BuiltinFactoryDiscovery {

        @Test
        void defaultBuildDiscoversBuiltinTools() {
            // Build with default config. The builder should discover the three
            // built-in factories (bc, gpg, sq) and register at least the tools
            // that are available on this system. BC (pure Java) is always available.
            try (var sigmund = Sigmund.builder().build()) {

                assertThat(sigmund.tool("bc"))
                        .as("bc tool should always be available (pure Java)").isNotNull();
            }
        }
    }

    /**
     * The addresses a directory vouches for a key, asked for outside verification — by an update
     * deciding whether a new key belongs to a signer named by address.
     */
    @Nested
    class DirectoryIdentities {

        private static final String KEY = "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12";

        private final List<String> asked = new ArrayList<>();

        private Sigmund withDirectory(List<String> addresses) {
            OpenPgpDirectory directory = new OpenPgpDirectory() {
                @Override
                public String name() {
                    return IssuerKind.KEYS_OPENPGP_ORG;
                }

                @Override
                public List<String> verifiedAddresses(String fingerprint) {
                    asked.add(fingerprint);
                    return addresses;
                }
            };
            return Sigmund.builder().addTool(mockTool("bc", true, false, Set.of("pgp4")))
                    .verificationConfig(onlyTools("bc")).openPgpDirectory(directory).build();
        }

        @Test
        void eachVerifiedAddressIsAnEmailIdentityFromTheDirectory() throws IOException {
            try (Sigmund sigmund = withDirectory(List.of("alice@example.com"))) {
                assertThat(sigmund.directoryIdentities(KeyCredential.openPgp(KEY), List.of("keys.openpgp.org")))
                        .containsExactly(IdentityCredential.email(IssuerKind.KEYS_OPENPGP_ORG, "alice@example.com"));
            }
        }

        @Test
        void anIssuerThatIsNotADirectoryIsNotAsked() throws IOException {
            try (Sigmund sigmund = withDirectory(List.of("alice@example.com"))) {
                assertThat(sigmund.directoryIdentities(KeyCredential.openPgp(KEY),
                        List.of("https://token.actions.githubusercontent.com"))).isEmpty();
            }
            assertThat(asked).isEmpty();
        }
    }

    /**
     * Tool names and settings are known to the tool factories, so they are checked when tools are
     * built: a misspelled tool or setting would otherwise configure nothing, and the tool would run
     * with its defaults.
     */
    @Nested
    class ToolNamesAndSettings {

        private Sigmund.Builder builderFor(String yaml) {
            return Sigmund.builder().config(SigmundConfigParser.parse("<test>", new StringReader(yaml)));
        }

        @Test
        void anUnknownToolIsErrorWithTheNearestName() {
            assertThatThrownBy(() -> builderFor("tools: { sqq: { home: /tmp/sq } }").build())
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("tools: unknown tool 'sqq' — did you mean 'sq'?");
        }

        @Test
        void anUnknownToolNamesTheToolsAvailable() {
            assertThatThrownBy(() -> builderFor("tools: { cosign: {} }").build())
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("tools: unknown tool 'cosign'")
                    .hasMessageContaining("tools available: bc, gpg, sq");
        }

        @Test
        void anUnknownSettingIsErrorWithTheNearestName() {
            assertThatThrownBy(() -> builderFor("tools: { bc: { gnupg-hom: /tmp/gnupg } }").build())
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("tools.bc: unknown setting 'gnupg-hom' — did you mean 'gnupg-home'?");
        }

        @Test
        void credentialsIsNotAToolSetting() {
            assertThatThrownBy(() -> builderFor("tools: { bc: { credentials: pgp4 } }").build())
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("tools.bc: unknown setting 'credentials'");
        }

        @Test
        void aSettingAnotherToolAcceptsIsStillUnknownHere() {
            assertThatThrownBy(() -> builderFor("tools: { sq: { gnupg-home: /tmp/gnupg } }").build())
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("tools.sq: unknown setting 'gnupg-home'");
        }

        @Test
        void anUnknownToolInTheVerificationToolchainIsError() {
            assertThatThrownBy(() -> builderFor("verification: { toolchain: [bcc] }").build())
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("verification.toolchain: unknown tool 'bcc' — did you mean 'bc'?");
        }

        @Test
        void anUnknownToolInTheSigningToolchainIsError() {
            assertThatThrownBy(() -> builderFor("signing: { toolchain: [gpgg] }").build())
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("signing.toolchain: unknown tool 'gpgg' — did you mean 'gpg'?");
        }

        @Test
        void aSigningFingerprintThatIsNotFullIsErrorEvenForAToolNoToolchainNames() {
            assertThatThrownBy(() -> builderFor("tools: { gpg: { signing-fingerprint: \"0xDEADBEEF\" } }").build())
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("tools.gpg.signing-fingerprint")
                    .hasMessageContaining("not a full fingerprint");
        }

        @Test
        void aListForASettingThatTakesOneValueIsError() {
            assertThatThrownBy(() -> builderFor("tools: { bc: { gnupg-home: [/a, /b] } }").build())
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("tools.bc.gnupg-home must be a single value, not a list");
        }

        @Test
        void aScalarHoldingSeveralValuesForAListSettingIsError() {
            assertThatThrownBy(() -> builderFor("tools: { sq: { signing-fingerprint: \"A,B\" } }").build())
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining(
                            "tools.sq.signing-fingerprint: 'A,B' holds more than one value; write them as a list");
        }

        @Test
        void addingAnUnknownSigningToolNamesTheNearestTool() {
            assertThatThrownBy(() -> Sigmund.builder().addSigningTool("bcc", Map.of()))
                    .isInstanceOf(SigmundException.class)
                    .hasMessageContaining("unknown tool 'bcc' — did you mean 'bc'?");
        }
    }

    @Nested
    class ExclusiveSignerEnforcement {

        @Test
        void exclusiveSignerRemovesOtherSigningTools() {
            var bc = mockTool("bc", true, true, Set.of("pgp4"));
            var gpg = mockTool("gpg", true, true, Set.of("pgp4"));
            var builder = Sigmund.builder().verificationConfig(onlyTools("bc", "gpg"));
            builder.addTool(bc);
            builder.addTool(gpg);

            builder.enforceExclusiveSigners(List.of(exclusiveFactory("bc")));

            try (var sigmund = builder.build()) {
                var signers = sigmund.tools().stream()
                        .filter(SignatureTool::canSign).toList();
                assertThat(signers.size()).isEqualTo(1);
                assertThat(signers.get(0).name()).isEqualTo("bc");
            }
        }

        @Test
        void exclusiveSignerKeepsVerifyOnlyTools() {
            var bc = mockTool("bc", true, true, Set.of("pgp4"));
            var gpgVerifyOnly = mockTool("gpg", true, false, Set.of("pgp4"));
            var builder = Sigmund.builder().verificationConfig(onlyTools("bc", "gpg"));
            builder.addTool(bc);
            builder.addTool(gpgVerifyOnly);

            builder.enforceExclusiveSigners(List.of(exclusiveFactory("bc")));

            try (var sigmund = builder.build()) {
                assertThat(sigmund.tools().size()).isEqualTo(2);
                assertThat(sigmund.tool("gpg")).isNotNull();
                assertThat(sigmund.tool("gpg").canSign()).isFalse();
            }
        }

        @Test
        void noOpWhenSigningToolsExplicitlyConfigured() {
            var bc = mockTool("bc", true, true, Set.of("pgp4"));
            var gpg = mockTool("gpg", true, true, Set.of("pgp4"));
            var config = new SigmundConfig(null, null, null,
                    new SigningConfig(null, List.of("gpg"), List.of(), Map.of()),
                    null, null);
            var builder = Sigmund.builder().config(config).verificationConfig(onlyTools("bc", "gpg"));
            builder.addTool(bc);
            builder.addTool(gpg);

            builder.enforceExclusiveSigners(List.of(exclusiveFactory("bc")));

            try (var sigmund = builder.build()) {
                var signers = sigmund.tools().stream()
                        .filter(SignatureTool::canSign).toList();
                assertThat(signers.size()).isEqualTo(2);
            }
        }

        @Test
        void clearsSigningConfigAfterEnforcement() throws IOException {
            var bc = mockTool("bc", true, true, Set.of("pgp4"));
            var gpg = mockTool("gpg", true, true, Set.of("pgp4"));
            var config = new SigmundConfig(null, null, null,
                    new SigningConfig(null, List.of(), List.of(), Map.of()),
                    null, null);
            var builder = Sigmund.builder().config(config).verificationConfig(onlyTools("bc", "gpg"));
            builder.addTool(bc);
            builder.addTool(gpg);

            builder.enforceExclusiveSigners(List.of(exclusiveFactory("bc")));

            try (var sigmund = builder.build()) {
                Signer signer = sigmund.signer();
                Path artifact = createTempFile("exclusive.jar");
                SigningOutput output = signer.sign(artifact, tempDir);
                assertThat(output.files().size()).isEqualTo(1);
                assertThat(output.files().get(0).toolName()).isEqualTo("bc");
            }
        }

        @Test
        void multipleExclusiveSignersThrows() {
            var builder = Sigmund.builder().verificationConfig(onlyTools("bc", "sq"));
            builder.addTool(mockTool("bc", true, true, Set.of("pgp4")));
            builder.addTool(mockTool("sq", true, true, Set.of("pgp6")));

            var factories = List.<SignatureToolFactory> of(
                    exclusiveFactory("bc"), exclusiveFactory("sq"));
            assertThatThrownBy(() -> builder.enforceExclusiveSigners(factories))
                    .isInstanceOf(SigmundException.class)
                    .hasMessageContaining("Multiple");
        }

        private SignatureToolFactory exclusiveFactory(String name) {
            var tool = mockTool(name, true, true, Set.of("pgp4"));
            return new SignatureToolFactory() {
                @Override
                public String toolName() {
                    return name;
                }

                @Override
                public Set<String> supportedCredentialTypes() {
                    return Set.of("pgp4");
                }

                @Override
                public Set<String> acceptedSettings() {
                    return Set.of();
                }

                @Override
                public SignatureTool createSigning(Map<String, String> settings, SignerIdentity expected) {
                    return tool;
                }

                @Override
                public SignatureTool createVerifyOnly(Map<String, String> settings) {
                    throw new UnsupportedOperationException();
                }

                @Override
                public boolean isDefaultExclusiveSigner() {
                    return true;
                }
            };
        }
    }

    /**
     * bc reads public keys from GnuPG's keyring; when {@code tools.gpg.home} places gpg's home,
     * bc reads the same one unless {@code tools.bc.gnupg-home} says otherwise. bc's own stores are
     * not gpg's and keep their defaults.
     */
    @Nested
    class SharedGnupgHome {

        private final List<Map<String, String>> received = new ArrayList<>();

        private final SignatureToolFactory bc = new SignatureToolFactory() {
            @Override
            public String toolName() {
                return "bc";
            }

            @Override
            public Set<String> supportedCredentialTypes() {
                return Set.of("pgp4");
            }

            @Override
            public Set<String> acceptedSettings() {
                return Set.of("gnupg-home", "cert-d-home", "bc-private-home");
            }

            @Override
            public SignatureTool createSigning(Map<String, String> settings, SignerIdentity expected) {
                received.add(settings);
                return mockTool("bc", true, true, Set.of("pgp4"));
            }

            @Override
            public SignatureTool createVerifyOnly(Map<String, String> settings) {
                received.add(settings);
                return mockTool("bc", true, false, Set.of("pgp4"));
            }
        };

        private Sigmund.Builder builderFor(String yaml) {
            return Sigmund.builder()
                    .config(SigmundConfigParser.parse("<test>", new StringReader(yaml)))
                    .factories(List.of(bc, new GpgToolFactory()));
        }

        private Map<String, String> signingSettings(String yaml) {
            Sigmund.Builder builder = builderFor(yaml);
            ToolConfig own = SigmundConfigParser.parse("<test>", new StringReader(yaml)).toolsConfig().get("bc");
            builder.addSigningTool("bc", own == null ? Map.of() : own.settings());
            return received.get(0);
        }

        @Test
        void bcReadsGpgsHomeWhenOnlyGpgsIsSet() {
            assertThat(signingSettings("tools: { gpg: { home: /keys/gnupg } }"))
                    .containsEntry("gnupg-home", "/keys/gnupg")
                    .doesNotContainKeys("cert-d-home", "bc-private-home");
        }

        @Test
        void bcsOwnGnupgHomeWins() {
            assertThat(signingSettings("tools: { gpg: { home: /keys/gnupg }, bc: { gnupg-home: /bc/gnupg } }"))
                    .containsEntry("gnupg-home", "/bc/gnupg");
        }

        @Test
        void withoutGpgsHomeBcKeepsItsDefault() {
            assertThat(signingSettings("tools: { gpg: { executable: gpg2 } }")).doesNotContainKey("gnupg-home");
        }

        @Test
        void verificationToolsReadTheSameHome() {
            builderFor("""
                    verification: { toolchain: [bc] }
                    tools: { gpg: { home: /keys/gnupg } }
                    """).build();

            assertThat(received).singleElement()
                    .satisfies(settings -> assertThat(settings).containsEntry("gnupg-home", "/keys/gnupg"));
        }
    }

    @Nested
    class AssertedSigner {

        private SignerIdentity receivedBy(String yaml) {
            var received = new ArrayList<SignerIdentity>();
            var factory = new SignatureToolFactory() {
                @Override
                public String toolName() {
                    return "recording";
                }

                @Override
                public Set<String> supportedCredentialTypes() {
                    return Set.of("pgp4");
                }

                @Override
                public Set<String> acceptedSettings() {
                    return Set.of();
                }

                @Override
                public SignatureTool createSigning(Map<String, String> settings, SignerIdentity expected) {
                    received.add(expected);
                    return mockTool("recording", true, true, Set.of("pgp4"));
                }

                @Override
                public SignatureTool createVerifyOnly(Map<String, String> settings) {
                    throw new UnsupportedOperationException();
                }
            };
            Sigmund.builder()
                    .config(SigmundConfigParser.parse("<test>", new StringReader(yaml)))
                    .factories(List.of(factory))
                    .addSigningTool("recording", Map.of());
            assertThat(received).hasSize(1);
            return received.get(0);
        }

        @Test
        void aConfiguredSignerReachesTheFactory() {
            SignerIdentity expected = receivedBy("""
                    issuers: [keys.openpgp.org]
                    signers:
                      alice:
                        email: alice@example.com
                    signing:
                      signer: alice
                    """);

            assertThat(expected.id()).isEqualTo("alice");
            assertThat(expected.credentials()).containsExactly(
                    IdentityCredential.email(IssuerKind.KEYS_OPENPGP_ORG, "alice@example.com"));
        }

        @Test
        void withoutASignerTheFactoryReceivesNull() {
            assertThat(receivedBy("""
                    signing:
                      toolchain: [recording]
                    """)).isNull();
        }
    }

    @Nested
    class AutoCloseableBehavior {

        @Test
        void closeCallsAutoCloseableTools() throws Exception {
            var closeable = new MockCloseableSignatureTool("closeable");
            var regular = mockTool("regular", true, false, Set.of("pgp4"));
            var sigmund = Sigmund.builder()
                    .addTool(closeable)
                    .addTool(regular)
                    .build();

            sigmund.close();

            assertThat(closeable.wasClosed()).isTrue();
        }

        @Test
        void closeSuppressesExceptionsFromTools() throws Exception {
            var throwingTool = new MockThrowingCloseTool("throwing");
            var normalTool = new MockCloseableSignatureTool("normal");
            var sigmund = Sigmund.builder()
                    .addTool(throwingTool)
                    .addTool(normalTool)
                    .build();

            // Should not throw
            sigmund.close();

            assertThat(normalTool.wasClosed()).isTrue();
        }
    }

    @Nested
    class BuilderCleanupOnFailure {

        @Test
        void closesToolsWhenBuildFails() {
            var closeable = new MockCloseableSignatureTool("closeable");
            var builder = Sigmund.builder().verificationConfig(onlyTools("closeable", "bad"));
            builder.addTool(closeable);

            // Add a tool that will cause build() to fail. We can achieve this
            // by adding a second tool with the same format but making the builder
            // fail after tools are added. The simplest way: configure a signing
            // toolchain referencing a non-existent tool, then call signer() on
            // the result. But we need build() itself to fail.
            // Instead, add a tool whose signatureFormat().parse() is broken in a
            // way that triggers the catch in build(). Actually the simplest way
            // is to add a tool with a null signatureFormat which will cause NPE.
            var badTool = new SignatureTool() {
                @Override
                public String name() {
                    return "bad";
                }

                @Override
                public boolean isAvailable() {
                    return true;
                }

                @Override
                public boolean canSign() {
                    return false;
                }

                @Override
                public SignatureFormat signatureFormat() {
                    return null; // causes NPE in build()
                }

                @Override
                public Set<String> supportedCredentialTypes() {
                    return Set.of();
                }

                @Override
                public boolean canVerify(Claim u) {
                    return false;
                }

                @Override
                public SignResult sign(Path a, Path o, SigningInfo key) {
                    throw new UnsupportedOperationException();
                }

                @Override
                public VerifyResult verify(Path a, Claim u) {
                    throw new UnsupportedOperationException();
                }

                @Override
                public List<Credential> extractCredentials(VerifyResult r) {
                    return List.of();
                }
            };
            builder.addTool(badTool);

            assertThatThrownBy(builder::build)
                    .isInstanceOf(RuntimeException.class);
            assertThat(closeable.wasClosed())
                    .as("AutoCloseable tool should be closed when build() fails").isTrue();
        }
    }

    @Nested
    class SignerInspectionOrchestration {

        @Test
        void inspectSignerUsesCapableTool() {
            var tool = mockInspectionTool("bc", true);
            try (var sigmund = Sigmund.builder().addTool(tool).build()) {

                var report = sigmund.inspectSigner(
                        new KeyCredential("pgp4", "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD"),
                        null);

                assertThat(report).isNotNull();
                assertThat(report.results().isEmpty()).isFalse();
                assertThat(report.results().stream().anyMatch(SignerSourceResult::found)).isTrue();
            }
        }

        @Test
        void inspectSignerFiltersToolByName() {
            var bc = mockInspectionTool("bc", true);
            var gpg = mockInspectionTool("gpg", false);
            try (var sigmund = Sigmund.builder().addTool(bc).addTool(gpg).build()) {

                var report = sigmund.inspectSigner(
                        new KeyCredential("pgp4", "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD"),
                        "gpg");

                assertThat(report).isNotNull();
                assertThat(report.results().stream().noneMatch(SignerSourceResult::found)).isTrue();
            }
        }

        @Test
        void inspectSignerReturnsEmptyWhenNoCapableTool() {
            var tool = mockTool("bc", true, false, Set.of("pgp4"));
            try (var sigmund = Sigmund.builder().addTool(tool).build()) {

                var report = sigmund.inspectSigner(
                        new KeyCredential("pgp4", "AABB000000000000000000000000000000000000"), null);

                assertThat(report).isNotNull();
                assertThat(report.results().isEmpty()).isTrue();
            }
        }

        @Test
        void inspectSignerCollectsFromAllCapableTools() {
            var bc = mockInspectionTool("bc", true);
            var sq = mockInspectionTool("sq", true);
            try (var sigmund = Sigmund.builder().addTool(bc).addTool(sq).build()) {

                var report = sigmund.inspectSigner(
                        new KeyCredential("pgp4", "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD"),
                        null);

                assertThat(report.results().size()).isEqualTo(2);
            }
        }
    }

    // --- Helpers ---

    /**
     * A toolchain of the tools a test adds itself, so that no other tool is discovered and built.
     */
    private static VerificationConfig onlyTools(String... names) {
        return new VerificationConfig(false, false, List.of(), List.of(names));
    }

    private Path createTempFile(String name) {
        return createTempFile(name, "content");
    }

    private Path createTempFile(String name, String content) {
        try {
            Path file = tempDir.resolve(name);
            Files.writeString(file, content);
            return file;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static SignatureTool mockTool(String name, boolean available, boolean canSign,
            Set<String> credentialTypes) {
        var format = mockFormat("openpgp", ".asc", true, List.of());
        return new SignatureTool() {
            @Override
            public String name() {
                return name;
            }

            @Override
            public boolean isAvailable() {
                return available;
            }

            @Override
            public boolean canSign() {
                return canSign;
            }

            @Override
            public List<SigningInfo> signingInfo() {
                return credentialTypes.stream().sorted()
                        .map(type -> new SigningInfo(name, null, null, null, type)).toList();
            }

            @Override
            public SignatureFormat signatureFormat() {
                return format;
            }

            @Override
            public Set<String> supportedCredentialTypes() {
                return credentialTypes;
            }

            @Override
            public boolean canVerify(Claim u) {
                return false;
            }

            @Override
            public SignResult sign(Path a, Path o, SigningInfo key) {
                try {
                    Files.writeString(o, "signature");
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                return new SignResult("RSA");
            }

            @Override
            public VerifyResult verify(Path a, Claim u) {
                return new OpenPgpVerifyResult(ClaimOutcome.INDETERMINATE, IndeterminateReason.UNSUPPORTED_ALGORITHM, null,
                        null, 4, null, null);
            }

            @Override
            public List<Credential> extractCredentials(VerifyResult r) {
                return List.of();
            }
        };
    }

    private static SignatureTool mockToolWithFormat(String name, SignatureFormat format,
            boolean available, boolean canSign, Set<String> credentialTypes) {
        return new SignatureTool() {
            @Override
            public String name() {
                return name;
            }

            @Override
            public boolean isAvailable() {
                return available;
            }

            @Override
            public boolean canSign() {
                return canSign;
            }

            @Override
            public SignatureFormat signatureFormat() {
                return format;
            }

            @Override
            public Set<String> supportedCredentialTypes() {
                return credentialTypes;
            }

            @Override
            public boolean canVerify(Claim u) {
                return false;
            }

            @Override
            public SignResult sign(Path a, Path o, SigningInfo key) {
                throw new UnsupportedOperationException();
            }

            @Override
            public VerifyResult verify(Path a, Claim u) {
                return new OpenPgpVerifyResult(ClaimOutcome.INDETERMINATE, IndeterminateReason.UNSUPPORTED_ALGORITHM, null,
                        null, 4, null, null);
            }

            @Override
            public List<Credential> extractCredentials(VerifyResult r) {
                return List.of();
            }
        };
    }

    private static SignatureTool mockVerifyingTool(String name, SignatureFormat format,
            boolean canVerify, VerifyResult result) {
        return new SignatureTool() {
            @Override
            public String name() {
                return name;
            }

            @Override
            public boolean isAvailable() {
                return true;
            }

            @Override
            public boolean canSign() {
                return false;
            }

            @Override
            public SignatureFormat signatureFormat() {
                return format;
            }

            @Override
            public Set<String> supportedCredentialTypes() {
                return Set.of("pgp4");
            }

            @Override
            public boolean canVerify(Claim u) {
                return canVerify;
            }

            @Override
            public SignResult sign(Path a, Path o, SigningInfo key) {
                throw new UnsupportedOperationException();
            }

            @Override
            public VerifyResult verify(Path a, Claim u) {
                return result;
            }

            @Override
            public List<Credential> extractCredentials(VerifyResult r) {
                if (r instanceof OpenPgpVerifyResult opvr && opvr.fingerprint() != null) {
                    return List.of(new KeyCredential(Credential.TYPE_PGP4, opvr.fingerprint()));
                }
                return List.of();
            }
        };
    }

    private static SignatureFormat mockFormat(String name, String ext, boolean canHandle,
            List<Claim> claims) {
        return new SignatureFormat() {
            @Override
            public String name() {
                return name;
            }

            @Override
            public String fileExtension() {
                return ext;
            }

            @Override
            public boolean canHandleByContent(Evidence e) {
                return canHandle;
            }

            @Override
            public List<Claim> parse(Evidence e) {
                return claims;
            }
        };
    }

    private static SignatureTool mockInspectionTool(String name, boolean found) {
        return new MockInspectionTool(name, found);
    }

    private static class MockInspectionTool implements SignatureTool, SignerInspection {
        private final String name;
        private final boolean found;

        MockInspectionTool(String name, boolean found) {
            this.name = name;
            this.found = found;
        }

        @Override
        public String name() {
            return name;
        }

        @Override
        public boolean isAvailable() {
            return true;
        }

        @Override
        public boolean canSign() {
            return false;
        }

        @Override
        public SignatureFormat signatureFormat() {
            return mockFormat("openpgp", ".asc", true, List.of());
        }

        @Override
        public Set<String> supportedCredentialTypes() {
            return Set.of("pgp4");
        }

        @Override
        public boolean canVerify(Claim u) {
            return false;
        }

        @Override
        public SignResult sign(Path a, Path o, SigningInfo key) {
            throw new UnsupportedOperationException();
        }

        @Override
        public VerifyResult verify(Path a, Claim u) {
            throw new UnsupportedOperationException();
        }

        @Override
        public List<Credential> extractCredentials(VerifyResult r) {
            return List.of();
        }

        @Override
        public boolean canInspect(Credential credential) {
            return credential instanceof KeyCredential;
        }

        @Override
        public List<SignerSourceResult> inspect(Credential credential) {
            if (!found) {
                return List.of(new SignerSourceResult("local", "mock", false, null));
            }
            var info = new SignerInspectionResult(
                    "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD",
                    4, "EdDSA", 256,
                    Instant.now(), null,
                    List.of("Mock User <mock@test.com>"), List.of());
            return List.of(new SignerSourceResult("local", "mock", true, info));
        }
    }

    private static class MockKeyGeneratorTool implements SignatureTool, KeyGenerator {
        private final String toolName;

        MockKeyGeneratorTool(String name) {
            this.toolName = name;
        }

        @Override
        public String name() {
            return toolName;
        }

        @Override
        public boolean isAvailable() {
            return true;
        }

        @Override
        public boolean canSign() {
            return false;
        }

        @Override
        public SignatureFormat signatureFormat() {
            return mockFormat("openpgp", ".asc", true, List.of());
        }

        @Override
        public Set<String> supportedCredentialTypes() {
            return Set.of("pgp6");
        }

        @Override
        public boolean canVerify(Claim u) {
            return false;
        }

        @Override
        public SignResult sign(Path a, Path o, SigningInfo key) {
            throw new UnsupportedOperationException();
        }

        @Override
        public VerifyResult verify(Path a, Claim u) {
            throw new UnsupportedOperationException();
        }

        @Override
        public List<Credential> extractCredentials(VerifyResult r) {
            return List.of();
        }

        @Override
        public String generateKey(String userId, String cipherSuite, String credentialType) {
            return "fingerprint";
        }
    }

    private static ArtifactCoords testArtifact(String ns, String name, String version) {
        return new ArtifactCoords(ns, name, "", "jar", version);
    }

    private static TrustPolicy ruleForNamespace(String signerId, Credential credential) {
        var signer = new SignerIdentity(signerId, List.of(credential));
        var spec = new TrustPolicySpec(
                List.of(new RuleSpec(List.of(ArtifactPattern.parse("org.example:*")),
                        List.of(Set.of(signerId)), Map.of(), "rules[0]", null)),
                ClaimSetMode.ANY_CLAIM, Map.of(), List.of(), true);
        return RulePolicy.compile(spec, new SignersConfig(Map.of(signerId, signer)));
    }

    /**
     * Mock tool that implements AutoCloseable to test close() behavior.
     */
    private static class MockCloseableSignatureTool implements SignatureTool, AutoCloseable {
        private final String toolName;
        private boolean closed;

        MockCloseableSignatureTool(String name) {
            this.toolName = name;
        }

        boolean wasClosed() {
            return closed;
        }

        @Override
        public void close() {
            this.closed = true;
        }

        @Override
        public String name() {
            return toolName;
        }

        @Override
        public boolean isAvailable() {
            return true;
        }

        @Override
        public boolean canSign() {
            return false;
        }

        @Override
        public SignatureFormat signatureFormat() {
            return mockFormat("openpgp", ".asc", true, List.of());
        }

        @Override
        public Set<String> supportedCredentialTypes() {
            return Set.of("pgp4");
        }

        @Override
        public boolean canVerify(Claim u) {
            return false;
        }

        @Override
        public SignResult sign(Path a, Path o, SigningInfo key) {
            throw new UnsupportedOperationException();
        }

        @Override
        public VerifyResult verify(Path a, Claim u) {
            return new OpenPgpVerifyResult(ClaimOutcome.INDETERMINATE, IndeterminateReason.UNSUPPORTED_ALGORITHM, null, null, 4,
                    null, null);
        }

        @Override
        public List<Credential> extractCredentials(VerifyResult r) {
            return List.of();
        }
    }

    /**
     * Mock tool that throws an exception when closed.
     */
    private static class MockThrowingCloseTool implements SignatureTool, AutoCloseable {
        private final String toolName;

        MockThrowingCloseTool(String name) {
            this.toolName = name;
        }

        @Override
        public void close() throws IOException {
            throw new IOException("Tool close failed");
        }

        @Override
        public String name() {
            return toolName;
        }

        @Override
        public boolean isAvailable() {
            return true;
        }

        @Override
        public boolean canSign() {
            return false;
        }

        @Override
        public SignatureFormat signatureFormat() {
            return mockFormat("openpgp", ".asc", true, List.of());
        }

        @Override
        public Set<String> supportedCredentialTypes() {
            return Set.of("pgp4");
        }

        @Override
        public boolean canVerify(Claim u) {
            return false;
        }

        @Override
        public SignResult sign(Path a, Path o, SigningInfo key) {
            throw new UnsupportedOperationException();
        }

        @Override
        public VerifyResult verify(Path a, Claim u) {
            return new OpenPgpVerifyResult(ClaimOutcome.INDETERMINATE, IndeterminateReason.UNSUPPORTED_ALGORITHM, null, null, 4,
                    null, null);
        }

        @Override
        public List<Credential> extractCredentials(VerifyResult r) {
            return List.of();
        }
    }
}
