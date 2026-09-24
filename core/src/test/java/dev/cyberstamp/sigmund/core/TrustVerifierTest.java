package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TrustVerifierTest {

    private static final String FP = "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12";
    private static final SignerIdentity ALICE = new SignerIdentity("alice", "Alice",
            List.of(new FingerprintCredential(Credential.TYPE_OPENPGP_V4, FP)));
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
        return new TrustVerifier(policy, List.of(provider))
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
                AttesterRole.UNKNOWN, TrustRootRef.unknown(),
                new EvidenceRef(evidenceFile, DigestSet.sha256(FP.toLowerCase()),
                        Evidence.SOURCE_SIDECAR),
                null, ClaimTimeSource.SIGNER, Instant.EPOCH, "RSA", "bc");
    }

    private static ClaimResult verifiedBy(SignerIdentity signer) {
        return claim(ClaimOutcome.VERIFIED, null, signer.credentials());
    }

    private static TrustPolicy expecting(SignerIdentity signer,
            ListedEvidencePolicy listedEvidence) {
        return new DefaultTrustPolicy(Map.of(COORDS.namespace(), List.of(signer)), List.of(),
                listedEvidence, UnlistedEvidencePolicy.IGNORE, UntrustedPolicy.FAIL);
    }

    @Nested
    class OutcomeAssignment {

        @Test
        void aClaimFromAnExpectedSignerSatisfiesThePolicy() {
            ArtifactResult result = assess(expecting(ALICE, ListedEvidencePolicy.ALL),
                    List.of(evidenceFile), verifiedBy(ALICE));

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.SATISFIED);
        }

        @Test
        void aClaimFromAnotherSignerIsUnsatisfied() {
            SignerIdentity mallory = new SignerIdentity("mallory", "Mallory",
                    List.of(new FingerprintCredential(Credential.TYPE_OPENPGP_V4, "DEADBEEF")));

            ArtifactResult result = assess(expecting(ALICE, ListedEvidencePolicy.ALL),
                    List.of(evidenceFile), verifiedBy(mallory));

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.UNSATISFIED);
        }

        @Test
        void aFailedSignatureIsTheAttackSignal() {
            ArtifactResult result = assess(expecting(ALICE, ListedEvidencePolicy.ALL),
                    List.of(evidenceFile), claim(ClaimOutcome.FAILED, null, List.of()));

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.FAILED);
        }

        @Test
        void noEvidenceAtAllIsNoClaimRatherThanAFailure() {
            ArtifactResult result = assess(expecting(ALICE, ListedEvidencePolicy.ALL), List.of());

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.NO_CLAIM);
        }

        @Test
        void anArtifactNoRuleCoversIsNotConfigured() {
            ArtifactResult result = assess(DefaultTrustPolicy.EMPTY, List.of(evidenceFile),
                    verifiedBy(ALICE));

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.NOT_CONFIGURED);
        }

        @Test
        void anUnavailableKeyLeavesTheVerdictUndecided() {
            ArtifactResult result = assess(expecting(ALICE, ListedEvidencePolicy.ALL),
                    List.of(evidenceFile),
                    claim(ClaimOutcome.INDETERMINATE, IndeterminateReason.KEY_UNAVAILABLE,
                            List.of()));

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.INDETERMINATE);
            assertThat(result.reason()).isEqualTo(IndeterminateReason.KEY_UNAVAILABLE);
        }
    }

    @Nested
    class ClaimSetMode {

        @Test
        void allClaimsRejectsEvidenceFromAnUnlistedSigner() {
            SignerIdentity stranger = new SignerIdentity("stranger", "Stranger",
                    List.of(new FingerprintCredential(Credential.TYPE_OPENPGP_V4, "BEEF")));

            ArtifactResult result = assess(expecting(ALICE, ListedEvidencePolicy.ALL),
                    List.of(evidenceFile), verifiedBy(ALICE), verifiedBy(stranger));

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.UNSATISFIED);
        }

        @Test
        void anyClaimAcceptsOnTheStrengthOfTheOneItNeeded() {
            SignerIdentity stranger = new SignerIdentity("stranger", "Stranger",
                    List.of(new FingerprintCredential(Credential.TYPE_OPENPGP_V4, "BEEF")));

            ArtifactResult result = assess(expecting(ALICE, ListedEvidencePolicy.ANY),
                    List.of(evidenceFile), verifiedBy(ALICE), verifiedBy(stranger));

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.SATISFIED);
        }
    }

    @Nested
    class ResultContents {

        @Test
        void theSubjectIsIdentifiedByTheBytesThatWereVerified() throws IOException {
            ArtifactResult result = assess(expecting(ALICE, ListedEvidencePolicy.ALL),
                    List.of(evidenceFile), verifiedBy(ALICE));

            assertThat(result.subject().coords()).isEqualTo(COORDS);
            assertThat(result.subject().digests())
                    .isEqualTo(DigestSet.sha256(artifact));
        }

        @Test
        void everyClaimIsKeptIncludingOnesThatDidNotContribute() {
            ArtifactResult result = assess(expecting(ALICE, ListedEvidencePolicy.ANY),
                    List.of(evidenceFile), verifiedBy(ALICE),
                    claim(ClaimOutcome.INDETERMINATE,
                            IndeterminateReason.UNSUPPORTED_ALGORITHM, List.of()));

            assertThat(result.claims()).hasSize(2);
        }
    }
}
