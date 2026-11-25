package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TrustVerifierTest {

    private static final String FP = "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12";
    private static final SignerIdentity ALICE = new SignerIdentity("alice",
            List.of(new KeyCredential(Credential.TYPE_PGP4, FP)));
    private static final ArtifactCoords COORDS = new ArtifactCoords("org.example", "lib", "", "jar", "1.0");

    @TempDir
    static Path fixtures;

    /** Real files: the verifier digests the artifact and reads the evidence it verifies. */
    static Path artifact;
    static Path evidenceFile;

    @BeforeAll
    static void createFixtures() throws IOException {
        artifact = Files.writeString(fixtures.resolve("lib.jar"), "artifact bytes");
        evidenceFile = Files.writeString(fixtures.resolve("lib.jar.asc"), "evidence bytes");
    }

    private static ArtifactResult assess(TrustPolicy policy, List<Path> evidenceFiles,
            ClaimResult... claims) {
        EvidenceProvider provider = provider(claims);
        return new TrustVerifier(policy, List.of(provider),
                new ClaimIdentityResolver(policy, Map.of(), false))
                .assess(COORDS, artifact, evidenceFiles);
    }

    private static EvidenceProvider provider(ClaimResult... claims) {
        return new EvidenceProvider() {
            @Override
            public String name() {
                return "openpgp";
            }

            @Override
            public boolean isAvailable() {
                return true;
            }

            @Override
            public boolean canHandle(Evidence evidence) {
                return true;
            }

            @Override
            public List<ClaimResult> verify(Path artifactFile, Evidence evidence) {
                return List.of(claims);
            }
        };
    }

    private static ClaimResult claim(ClaimOutcome outcome, IndeterminateReason reason,
            List<Credential> proven) {
        return new ClaimResult("openpgp", outcome, reason, proven, "Alice <alice@example.com>",
                TrustRootRef.unknown(),
                new EvidenceRef(evidenceFile, DigestSet.sha256(FP.toLowerCase()),
                        Evidence.SOURCE_SIDECAR),
                null, ClaimTimeSource.SIGNER, Instant.EPOCH, "RSA", "bc");
    }

    private static ClaimResult verifiedBy(SignerIdentity signer) {
        return claim(ClaimOutcome.VERIFIED, null, signer.credentials());
    }

    private static TrustPolicy expecting(SignerIdentity signer, ClaimSetMode extraClaims) {
        var signers = new SignersConfig(Map.of(signer.id(), signer));
        var spec = new TrustPolicySpec(
                List.of(new RuleSpec(List.of(ArtifactPattern.parse(COORDS.namespace())),
                        List.of(Set.of(signer.id())), Map.of(), "rules[0]", null)),
                extraClaims, Map.of(), List.of(), true);
        return RulePolicy.compile(spec, signers);
    }

    @Nested
    class OutcomeAssignment {

        @Test
        void aClaimFromAnExpectedSignerSatisfiesThePolicy() {
            ArtifactResult result = assess(expecting(ALICE, ClaimSetMode.ALL_CLAIMS),
                    List.of(evidenceFile), verifiedBy(ALICE));

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.SATISFIED);
        }

        @Test
        void aClaimFromAnotherSignerIsUnsatisfied() {
            SignerIdentity mallory = new SignerIdentity("mallory",
                    List.of(new KeyCredential(Credential.TYPE_PGP4, "DEADBEEF00000000000000000000000000000000")));

            ArtifactResult result = assess(expecting(ALICE, ClaimSetMode.ALL_CLAIMS),
                    List.of(evidenceFile), verifiedBy(mallory));

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.UNSATISFIED);
        }

        @Test
        void aRuleMayAcceptSurplusSignersThatTheDefaultsReject() {
            SignerIdentity mallory = new SignerIdentity("mallory",
                    List.of(new KeyCredential(Credential.TYPE_PGP4, "DEADBEEF00000000000000000000000000000000")));
            var spec = new TrustPolicySpec(
                    List.of(new RuleSpec(List.of(ArtifactPattern.parse(COORDS.namespace())),
                            List.of(Set.of(ALICE.id())), Map.of(), "rules[0]", ClaimSetMode.ANY_CLAIM)),
                    ClaimSetMode.ALL_CLAIMS, Map.of(), List.of(), true);
            TrustPolicy policy = RulePolicy.compile(spec, new SignersConfig(Map.of(ALICE.id(), ALICE)));

            ArtifactResult result = assess(policy, List.of(evidenceFile), verifiedBy(ALICE),
                    verifiedBy(mallory));

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.SATISFIED);
        }

        @Test
        void aRuleWithoutItsOwnExtraClaimsFollowsTheDefaults() {
            SignerIdentity mallory = new SignerIdentity("mallory",
                    List.of(new KeyCredential(Credential.TYPE_PGP4, "DEADBEEF00000000000000000000000000000000")));

            ArtifactResult result = assess(expecting(ALICE, ClaimSetMode.ALL_CLAIMS),
                    List.of(evidenceFile), verifiedBy(ALICE), verifiedBy(mallory));

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.UNSATISFIED);
        }

        @Test
        void aFailedSignatureIsTheAttackSignal() {
            ArtifactResult result = assess(expecting(ALICE, ClaimSetMode.ALL_CLAIMS),
                    List.of(evidenceFile), claim(ClaimOutcome.FAILED, null, List.of()));

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.FAILED);
        }

        @Test
        void noEvidenceAtAllIsNoClaimRatherThanAFailure() {
            ArtifactResult result = assess(expecting(ALICE, ClaimSetMode.ALL_CLAIMS), List.of());

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.NO_CLAIM);
        }

        @Test
        void anArtifactNoRuleCoversIsNotConfigured() {
            ArtifactResult result = assess(RulePolicy.EMPTY, List.of(evidenceFile),
                    verifiedBy(ALICE));

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.NOT_CONFIGURED);
        }

        @Test
        void anUnsignedArtifactUnderARequiresLessCatchAllIsNoClaimAndTolerated() {
            var spec = new TrustPolicySpec(
                    List.of(new RuleSpec(List.of(ArtifactPattern.parse("*")), List.of(),
                            Map.of(ArtifactOutcome.NO_CLAIM, EnforcementAction.IGNORE), "rules[0]", null)),
                    ClaimSetMode.ALL_CLAIMS, Map.of(), List.of(), true);
            TrustPolicy policy = RulePolicy.compile(spec, SignersConfig.EMPTY);

            ArtifactResult result = assess(policy, List.of());

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.NO_CLAIM);
            assertThat(result.matchedRule()).isNotNull();
            assertThat(VerificationReport.of(List.of(result), policy).blocks()).isFalse();
        }

        /**
         * The same requires-less catch-all tolerates an <em>unsigned</em> straggler via
         * {@code on-no-claim: ignore}, but a <em>signed</em> straggler is a different case: under the
         * default {@code extra-claims: reject} a verified claim from a signer no clause named is an
         * unaccepted surplus claim, so the artifact rolls up to {@link ArtifactOutcome#UNSATISFIED},
         * which {@code on-no-claim} does not relax. This fails closed and blocks — intended, and
         * pinned here so the surprise is caught if it ever changes (ADR-007 Enforcement).
         */
        @Test
        void aSignedStragglerUnderARequiresLessCatchAllIsUnsatisfiedAndBlocks() {
            var spec = new TrustPolicySpec(
                    List.of(new RuleSpec(List.of(ArtifactPattern.parse("*")), List.of(),
                            Map.of(ArtifactOutcome.NO_CLAIM, EnforcementAction.IGNORE), "rules[0]", null)),
                    ClaimSetMode.ALL_CLAIMS, Map.of(), List.of(), true);
            TrustPolicy policy = RulePolicy.compile(spec, SignersConfig.EMPTY);

            ArtifactResult result = assess(policy, List.of(evidenceFile), verifiedBy(ALICE));

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.UNSATISFIED);
            assertThat(VerificationReport.of(List.of(result), policy).blocks()).isTrue();
        }

        @Test
        void anUnavailableKeyLeavesTheVerdictUndecided() {
            ArtifactResult result = assess(expecting(ALICE, ClaimSetMode.ALL_CLAIMS),
                    List.of(evidenceFile),
                    claim(ClaimOutcome.INDETERMINATE, IndeterminateReason.KEY_UNAVAILABLE,
                            List.of()));

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.INDETERMINATE);
            assertThat(result.reason()).isEqualTo(IndeterminateReason.KEY_UNAVAILABLE);
        }
    }

    @Nested
    class ExtraClaimsHandling {

        @Test
        void allClaimsRejectsEvidenceFromAnUnlistedSigner() {
            SignerIdentity stranger = new SignerIdentity("stranger",
                    List.of(new KeyCredential(Credential.TYPE_PGP4, "BEEF000000000000000000000000000000000000")));

            ArtifactResult result = assess(expecting(ALICE, ClaimSetMode.ALL_CLAIMS),
                    List.of(evidenceFile), verifiedBy(ALICE), verifiedBy(stranger));

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.UNSATISFIED);
        }

        @Test
        void anyClaimAcceptsOnTheStrengthOfTheOneItNeeded() {
            SignerIdentity stranger = new SignerIdentity("stranger",
                    List.of(new KeyCredential(Credential.TYPE_PGP4, "BEEF000000000000000000000000000000000000")));

            ArtifactResult result = assess(expecting(ALICE, ClaimSetMode.ANY_CLAIM),
                    List.of(evidenceFile), verifiedBy(ALICE), verifiedBy(stranger));

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.SATISFIED);
        }
    }

    @Nested
    class ResultContents {

        @Test
        void theSubjectIsIdentifiedByTheBytesThatWereVerified() throws IOException {
            ArtifactResult result = assess(expecting(ALICE, ClaimSetMode.ALL_CLAIMS),
                    List.of(evidenceFile), verifiedBy(ALICE));

            assertThat(result.subject().coords()).isEqualTo(COORDS);
            assertThat(result.subject().digests())
                    .isEqualTo(DigestSet.sha256(artifact));
        }

        @Test
        void everyClaimIsKeptIncludingOnesThatDidNotContribute() {
            ArtifactResult result = assess(expecting(ALICE, ClaimSetMode.ANY_CLAIM),
                    List.of(evidenceFile), verifiedBy(ALICE),
                    claim(ClaimOutcome.INDETERMINATE,
                            IndeterminateReason.UNSUPPORTED_ALGORITHM, List.of()));

            assertThat(result.claims()).hasSize(2);
        }
    }

    @Nested
    class EvidenceThatCannotBeRead {

        /** A directory where a signature file was resolved: reading it fails as an unreadable file does. */
        @Test
        void isRecordedAndLeavesTheArtifactUndecidedWhileTheOtherFilesAreVerified(@TempDir Path dir)
                throws IOException {
            Path unreadable = Files.createDirectory(dir.resolve("lib.jar.sigstore.json"));

            ArtifactResult result = assess(expecting(ALICE, ClaimSetMode.ALL_CLAIMS),
                    List.of(unreadable, evidenceFile), verifiedBy(ALICE));

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.INDETERMINATE);
            assertThat(result.reason()).isEqualTo(IndeterminateReason.EVIDENCE_UNREADABLE);
            assertThat(result.claims()).hasSize(1);
            assertThat(result.evidenceWithoutClaims()).singleElement().satisfies(record -> {
                assertThat(record.file()).isEqualTo(unreadable);
                assertThat(record.source()).isEqualTo(Evidence.SOURCE_SIDECAR);
                assertThat(record.message()).isNotBlank();
            });
        }

        @Test
        void aFileGoneSinceItWasResolvedSaysSo(@TempDir Path dir) {
            Path gone = dir.resolve("lib.jar.asc");

            ArtifactResult result = assess(expecting(ALICE, ClaimSetMode.ALL_CLAIMS), List.of(gone));

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.INDETERMINATE);
            assertThat(result.evidenceWithoutClaims()).singleElement()
                    .satisfies(record -> assertThat(record.message()).isEqualTo("no such file"));
        }

        @Test
        void theOtherArtifactsOfTheRunAreStillAssessed(@TempDir Path dir) throws IOException {
            Path unreadable = Files.createDirectory(dir.resolve("lib.jar.asc"));
            TrustPolicy policy = expecting(ALICE, ClaimSetMode.ALL_CLAIMS);
            TrustVerifier verifier = new TrustVerifier(policy, List.of(provider(verifiedBy(ALICE))),
                    new ClaimIdentityResolver(policy, Map.of(), false));

            List<ArtifactResult> results = verifier.assessAll(List.of(
                    new AssessmentRequest(COORDS, artifact, List.of(unreadable)),
                    new AssessmentRequest(COORDS, artifact, List.of(evidenceFile))));

            assertThat(results).extracting(ArtifactResult::outcome)
                    .containsExactly(ArtifactOutcome.INDETERMINATE, ArtifactOutcome.SATISFIED);
        }
    }

    /** A file read but holding no signature is malformed evidence, not the absence of it. */
    @Nested
    class EvidenceHoldingNoSignature {

        @Test
        void anEmptySignatureFileIsMalformedRatherThanNoClaim(@TempDir Path dir) throws IOException {
            Path empty = Files.writeString(dir.resolve("lib.jar.asc"), "");

            ArtifactResult result = assess(expecting(ALICE, ClaimSetMode.ALL_CLAIMS), List.of(empty));

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.INDETERMINATE);
            assertThat(result.reason()).isEqualTo(IndeterminateReason.EVIDENCE_MALFORMED);
            assertThat(result.evidenceWithoutClaims()).singleElement().satisfies(record -> {
                assertThat(record.file()).isEqualTo(empty);
                assertThat(record.digest()).isEqualTo(DigestSet.sha256(new byte[0]));
                assertThat(record.describe()).isEqualTo(empty + " is empty");
            });
        }

        @Test
        void aFileWithoutASignatureSaysItHoldsNone(@TempDir Path dir) throws IOException {
            Path page = Files.writeString(dir.resolve("lib.jar.asc"), "<html>Not Found</html>");

            ArtifactResult result = assess(expecting(ALICE, ClaimSetMode.ALL_CLAIMS), List.of(page));

            assertThat(result.evidenceWithoutClaims()).singleElement()
                    .satisfies(record -> assertThat(record.describe()).isEqualTo(page + " holds no signature"));
        }

        @Test
        void besideAVerifiedClaimItLeavesTheArtifactUndecidedWhenSurplusClaimsAreRejected(@TempDir Path dir)
                throws IOException {
            Path empty = Files.writeString(dir.resolve("lib.jar.sigstore.json"), "");
            TrustPolicy policy = expecting(ALICE, ClaimSetMode.ALL_CLAIMS);
            EvidenceProvider onlyTheAsc = new EvidenceProvider() {
                @Override
                public String name() {
                    return "openpgp";
                }

                @Override
                public boolean isAvailable() {
                    return true;
                }

                @Override
                public boolean canHandle(Evidence evidence) {
                    return true;
                }

                @Override
                public List<ClaimResult> verify(Path artifactFile, Evidence evidence) {
                    return evidence.file().equals(evidenceFile) ? List.of(verifiedBy(ALICE)) : List.of();
                }
            };

            ArtifactResult result = new TrustVerifier(policy, List.of(onlyTheAsc),
                    new ClaimIdentityResolver(policy, Map.of(), false)).assess(COORDS, artifact,
                            List.of(evidenceFile, empty));

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.INDETERMINATE);
            assertThat(result.reason()).isEqualTo(IndeterminateReason.EVIDENCE_MALFORMED);
        }

        @Test
        void aFileNoProviderHandlesIsNotRecorded(@TempDir Path dir) throws IOException {
            Path other = Files.writeString(dir.resolve("lib.jar.md5"), "d41d8cd98f00b204e9800998ecf8427e");
            TrustPolicy policy = expecting(ALICE, ClaimSetMode.ALL_CLAIMS);
            EvidenceProvider handlesNothing = new EvidenceProvider() {
                @Override
                public String name() {
                    return "openpgp";
                }

                @Override
                public boolean isAvailable() {
                    return true;
                }

                @Override
                public boolean canHandle(Evidence evidence) {
                    return false;
                }

                @Override
                public List<ClaimResult> verify(Path artifactFile, Evidence evidence) {
                    return List.of();
                }
            };

            ArtifactResult result = new TrustVerifier(policy, List.of(handlesNothing),
                    new ClaimIdentityResolver(policy, Map.of(), false)).assess(COORDS, artifact, List.of(other));

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.NO_CLAIM);
            assertThat(result.evidenceWithoutClaims()).isEmpty();
        }
    }
}
