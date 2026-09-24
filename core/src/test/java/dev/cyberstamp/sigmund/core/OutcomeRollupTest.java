package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class OutcomeRollupTest {

    private static final ArtifactCoords COORDS = new ArtifactCoords("org.example", "lib", "", "jar", "1.0");

    private static final EvidenceRef REF = new EvidenceRef(Path.of("lib.jar.asc"),
            DigestSet.sha256("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            Evidence.SOURCE_SIDECAR);

    private static ClaimResult claim(ClaimOutcome outcome, IndeterminateReason reason) {
        return new ClaimResult("openpgp", outcome, reason, List.of(), null,
                AttesterRole.UNKNOWN, TrustRootRef.unknown(), REF, null,
                ClaimTimeSource.SIGNER, Instant.EPOCH, "RSA", "bc");
    }

    private static ClaimResult verified() {
        return verifiedBy("alice");
    }

    /** Distinct verified claims: records with identical components are equal. */
    private static ClaimResult verifiedBy(String attester) {
        return new ClaimResult("openpgp", ClaimOutcome.VERIFIED, null, List.of(), attester,
                AttesterRole.UNKNOWN, TrustRootRef.unknown(), REF, null,
                ClaimTimeSource.SIGNER, Instant.EPOCH, "RSA", "bc");
    }

    /** Requirements that accept the listed claims and reject everything else. */
    private static RequirementEvaluator accepting(ClaimResult... accepted) {
        List<ClaimResult> acceptable = List.of(accepted);
        return (coords, claims) -> {
            assertThat(coords).isEqualTo(COORDS);
            return new RequirementEvaluator.Evaluation(true,
                    claims.stream().filter(acceptable::contains).toList(),
                    claims.stream().filter(c -> !acceptable.contains(c)).toList());
        };
    }

    private static RequirementEvaluator unmet() {
        return (coords, claims) -> {
            assertThat(coords).isEqualTo(COORDS);
            return new RequirementEvaluator.Evaluation(false, List.of(), claims);
        };
    }

    private static RequirementEvaluator notConfigured() {
        return (coords, claims) -> null;
    }

    @Nested
    class Precedence {

        @Test
        void aFailedClaimDominatesEvenAlongsideAVerifiedOne() {
            ClaimResult failed = claim(ClaimOutcome.FAILED, null);

            assertThat(OutcomeRollup.derive(COORDS, List.of(verified(), failed), accepting(verified()),
                    null, ClaimSetMode.ANY_CLAIM).outcome()).isEqualTo(ArtifactOutcome.FAILED);
        }

        @Test
        void noRequirementMeansNotConfigured() {
            assertThat(OutcomeRollup.derive(COORDS, List.of(verified()), notConfigured(), null,
                    ClaimSetMode.ALL_CLAIMS).outcome()).isEqualTo(ArtifactOutcome.NOT_CONFIGURED);
        }

        @Test
        void noClaimsAtAllMeansNoClaim() {
            assertThat(OutcomeRollup.derive(COORDS, List.of(), unmet(), null, ClaimSetMode.ALL_CLAIMS)
                    .outcome()).isEqualTo(ArtifactOutcome.NO_CLAIM);
        }
    }

    @Nested
    class UnsupportedClaimsAreSetAside {

        @Test
        void aHybridSignatureVerifiesOnItsClassicBlock() {
            ClaimResult pqcUnsupported = claim(ClaimOutcome.INDETERMINATE, IndeterminateReason.UNSUPPORTED_ALGORITHM);
            ClaimResult classic = verified();

            OutcomeRollup.Result result = OutcomeRollup.derive(COORDS, List.of(classic, pqcUnsupported),
                    accepting(classic), null, ClaimSetMode.ALL_CLAIMS);

            // the set-aside claim is not lost: it stays in the artifact's claim list, where
            // its reason identifies it
            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.SATISFIED);
            assertThat(pqcUnsupported
                    .isIndeterminateBecause(IndeterminateReason.UNSUPPORTED_ALGORITHM)).isTrue();
        }

        @Test
        void onlyUnsupportedClaimsIsIndeterminateNotNoClaim() {
            ClaimResult unsupported = claim(ClaimOutcome.INDETERMINATE, IndeterminateReason.UNSUPPORTED_ALGORITHM);

            OutcomeRollup.Result result = OutcomeRollup.derive(COORDS, List.of(unsupported), unmet(), null,
                    ClaimSetMode.ALL_CLAIMS);

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.INDETERMINATE);
            assertThat(result.reason()).isEqualTo(IndeterminateReason.UNSUPPORTED_ALGORITHM);
        }

        @Test
        void aRequiredClaimKindThatNoToolSupportsIsIndeterminate() {
            ClaimResult unsupported = claim(ClaimOutcome.INDETERMINATE, IndeterminateReason.UNSUPPORTED_ALGORITHM);

            OutcomeRollup.Result result = OutcomeRollup.derive(COORDS, List.of(unsupported), unmet(),
                    "openpgp", ClaimSetMode.ALL_CLAIMS);

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.INDETERMINATE);
            assertThat(result.reason()).isEqualTo(IndeterminateReason.UNSUPPORTED_ALGORITHM);
        }
    }

    @Nested
    class ClaimSetModes {

        @Test
        void allClaimsRejectsAVerifiedClaimPolicyDoesNotAccept() {
            ClaimResult accepted = verifiedBy("alice");
            ClaimResult stranger = verifiedBy("mallory");

            assertThat(OutcomeRollup.derive(COORDS, List.of(accepted, stranger), accepting(accepted), null,
                    ClaimSetMode.ALL_CLAIMS).outcome()).isEqualTo(ArtifactOutcome.UNSATISFIED);
        }

        @Test
        void anyClaimIgnoresTheOnesItDidNotNeed() {
            ClaimResult accepted = verifiedBy("alice");
            ClaimResult stranger = verifiedBy("mallory");

            assertThat(OutcomeRollup.derive(COORDS, List.of(accepted, stranger), accepting(accepted), null,
                    ClaimSetMode.ANY_CLAIM).outcome()).isEqualTo(ArtifactOutcome.SATISFIED);
        }

        @Test
        void anUnresolvedClaimLeavesTheVerdictUndecidedUnderAllClaims() {
            ClaimResult accepted = verified();
            ClaimResult unresolved = claim(ClaimOutcome.INDETERMINATE, IndeterminateReason.KEY_UNAVAILABLE);

            OutcomeRollup.Result result = OutcomeRollup.derive(COORDS, List.of(accepted, unresolved),
                    accepting(accepted), null, ClaimSetMode.ALL_CLAIMS);

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.INDETERMINATE);
            assertThat(result.reason()).isEqualTo(IndeterminateReason.KEY_UNAVAILABLE);
        }
    }

    @Nested
    class WhenRequirementsAreNotMet {

        @Test
        void anUnresolvedClaimThatCouldHaveSatisfiedThemIsIndeterminate() {
            ClaimResult unresolved = claim(ClaimOutcome.INDETERMINATE, IndeterminateReason.KEY_UNAVAILABLE);

            OutcomeRollup.Result result = OutcomeRollup.derive(COORDS, List.of(unresolved), unmet(), null,
                    ClaimSetMode.ANY_CLAIM);

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.INDETERMINATE);
            assertThat(result.reason()).isEqualTo(IndeterminateReason.KEY_UNAVAILABLE);
        }

        @Test
        void aVerifiedClaimPolicyRejectsIsUnsatisfied() {
            assertThat(OutcomeRollup.derive(COORDS, List.of(verified()), unmet(), null,
                    ClaimSetMode.ANY_CLAIM).outcome()).isEqualTo(ArtifactOutcome.UNSATISFIED);
        }
    }
}
