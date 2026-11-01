package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class OutcomeRollupTest {

    private static final EvidenceRef REF = new EvidenceRef(Path.of("lib.jar.asc"),
            DigestSet.sha256("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            Evidence.SOURCE_SIDECAR);

    private static ClaimResult claim(ClaimOutcome outcome, IndeterminateReason reason) {
        return new ClaimResult("openpgp", outcome, reason, List.of(), null,
                TrustRootRef.unknown(), REF, null,
                ClaimTimeSource.SIGNER, Instant.EPOCH, "RSA", "bc");
    }

    private static ClaimResult verified() {
        return verifiedBy("alice");
    }

    /** Distinct verified claims: records with identical components are equal. */
    private static ClaimResult verifiedBy(String attester) {
        return new ClaimResult("openpgp", ClaimOutcome.VERIFIED, null, List.of(), attester,
                TrustRootRef.unknown(), REF, null,
                ClaimTimeSource.SIGNER, Instant.EPOCH, "RSA", "bc");
    }

    /** Requirements that accept the listed claims and reject everything else. */
    private static RequirementEvaluator accepting(ClaimResult... accepted) {
        List<ClaimResult> acceptable = List.of(accepted);
        return claims -> new RequirementEvaluator.Evaluation(true,
                claims.stream().filter(acceptable::contains).toList(),
                claims.stream().filter(c -> !acceptable.contains(c)).toList());
    }

    private static RequirementEvaluator unmet() {
        return claims -> new RequirementEvaluator.Evaluation(false, List.of(), claims);
    }

    private static RequirementEvaluator notConfigured() {
        return null;
    }

    @Nested
    class Precedence {

        @Test
        void aFailedClaimDominatesEvenAlongsideAVerifiedOne() {
            ClaimResult failed = claim(ClaimOutcome.FAILED, null);

            assertThat(OutcomeRollup.derive(List.of(verified(), failed), accepting(verified()),
                    ClaimSetMode.ANY_CLAIM).outcome()).isEqualTo(ArtifactOutcome.FAILED);
        }

        @Test
        void noRequirementMeansNotConfigured() {
            assertThat(OutcomeRollup.derive(List.of(verified()), notConfigured(),
                    ClaimSetMode.ALL_CLAIMS).outcome()).isEqualTo(ArtifactOutcome.NOT_CONFIGURED);
        }

        @Test
        void noClaimsAtAllMeansNoClaim() {
            assertThat(OutcomeRollup.derive(List.of(), unmet(), ClaimSetMode.ALL_CLAIMS)
                    .outcome()).isEqualTo(ArtifactOutcome.NO_CLAIM);
        }
    }

    @Nested
    class UnsupportedClaimsAreSetAside {

        @Test
        void aHybridSignatureVerifiesOnItsClassicBlock() {
            ClaimResult pqcUnsupported = claim(ClaimOutcome.INDETERMINATE, IndeterminateReason.UNSUPPORTED_ALGORITHM);
            ClaimResult classic = verified();

            OutcomeRollup.Result result = OutcomeRollup.derive(List.of(classic, pqcUnsupported),
                    accepting(classic), ClaimSetMode.ALL_CLAIMS);

            // the set-aside claim is not lost: it stays in the artifact's claim list, where
            // its reason identifies it
            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.SATISFIED);
            assertThat(pqcUnsupported
                    .isIndeterminateBecause(IndeterminateReason.UNSUPPORTED_ALGORITHM)).isTrue();
        }

        @Test
        void onlyUnsupportedClaimsIsIndeterminateNotNoClaim() {
            ClaimResult unsupported = claim(ClaimOutcome.INDETERMINATE, IndeterminateReason.UNSUPPORTED_ALGORITHM);

            OutcomeRollup.Result result = OutcomeRollup.derive(List.of(unsupported), unmet(),
                    ClaimSetMode.ALL_CLAIMS);

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

            assertThat(OutcomeRollup.derive(List.of(accepted, stranger), accepting(accepted),
                    ClaimSetMode.ALL_CLAIMS).outcome()).isEqualTo(ArtifactOutcome.UNSATISFIED);
        }

        @Test
        void anyClaimIgnoresTheOnesItDidNotNeed() {
            ClaimResult accepted = verifiedBy("alice");
            ClaimResult stranger = verifiedBy("mallory");

            assertThat(OutcomeRollup.derive(List.of(accepted, stranger), accepting(accepted),
                    ClaimSetMode.ANY_CLAIM).outcome()).isEqualTo(ArtifactOutcome.SATISFIED);
        }

        @Test
        void anUnresolvedClaimLeavesTheVerdictUndecidedUnderAllClaims() {
            ClaimResult accepted = verified();
            ClaimResult unresolved = claim(ClaimOutcome.INDETERMINATE, IndeterminateReason.KEY_UNAVAILABLE);

            OutcomeRollup.Result result = OutcomeRollup.derive(List.of(accepted, unresolved),
                    accepting(accepted), ClaimSetMode.ALL_CLAIMS);

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.INDETERMINATE);
            assertThat(result.reason()).isEqualTo(IndeterminateReason.KEY_UNAVAILABLE);
        }
    }

    @Nested
    class WhenRequirementsAreNotMet {

        @Test
        void anUnresolvedClaimThatCouldHaveSatisfiedThemIsIndeterminate() {
            ClaimResult unresolved = claim(ClaimOutcome.INDETERMINATE, IndeterminateReason.KEY_UNAVAILABLE);

            OutcomeRollup.Result result = OutcomeRollup.derive(List.of(unresolved), unmet(),
                    ClaimSetMode.ANY_CLAIM);

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.INDETERMINATE);
            assertThat(result.reason()).isEqualTo(IndeterminateReason.KEY_UNAVAILABLE);
        }

        @Test
        void aVerifiedClaimPolicyRejectsIsUnsatisfied() {
            assertThat(OutcomeRollup.derive(List.of(verified()), unmet(),
                    ClaimSetMode.ANY_CLAIM).outcome()).isEqualTo(ArtifactOutcome.UNSATISFIED);
        }
    }

    /**
     * A requirement left unmet only for signers that claims no installed tool can check say
     * made them is undecidable here, not a wrong signer.
     */
    @Nested
    class SignersOnlyAnUncheckableClaimNames {

        private static final String CLASSIC = "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12";
        private static final String PQC = "CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9";
        private static final String OTHER = "BBE7232D7991050B54C8EA0ADC08637CA615D22C";

        private static SignerIdentity signer(String id, String... fingerprints) {
            List<Credential> keys = new java.util.ArrayList<>();
            for (String fingerprint : fingerprints) {
                keys.add(KeyCredential.openPgp(fingerprint));
            }
            return new SignerIdentity(id, keys);
        }

        private static Requirement requiring(SignerIdentity... signers) {
            List<Clause> clauses = new java.util.ArrayList<>();
            for (SignerIdentity signer : signers) {
                clauses.add(new Clause(List.of(signer)));
            }
            return new Requirement(clauses, List.of());
        }

        private static ClaimResult verifiedBy(String fingerprint) {
            return new ClaimResult("openpgp", ClaimOutcome.VERIFIED, null,
                    List.of(KeyCredential.openPgp(fingerprint)), null, TrustRootRef.unknown(), REF,
                    null, ClaimTimeSource.SIGNER, Instant.EPOCH, "RSA", "bc",
                    KeyCredential.openPgp(fingerprint), null);
        }

        private static ClaimResult unsupportedNaming(String fingerprint) {
            return new ClaimResult("openpgp", ClaimOutcome.INDETERMINATE,
                    IndeterminateReason.UNSUPPORTED_ALGORITHM, List.of(), null,
                    TrustRootRef.unknown(), REF, null, ClaimTimeSource.SIGNER, Instant.EPOCH,
                    "ML-DSA-87+Ed448", null, KeyCredential.openPgp(fingerprint), null);
        }

        @Test
        void aCoSignerOnlyAnUncheckableClaimNamesIsUnsupportedNotUnsatisfied() {
            Requirement both = requiring(signer("classic", CLASSIC), signer("pqc", PQC));

            OutcomeRollup.Result result = OutcomeRollup.derive(
                    List.of(verifiedBy(CLASSIC), unsupportedNaming(PQC)), both,
                    ClaimSetMode.ALL_CLAIMS);

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.INDETERMINATE);
            assertThat(result.reason()).isEqualTo(IndeterminateReason.UNSUPPORTED_ALGORITHM);
        }

        @Test
        void anUncheckableClaimNamingSomeoneElseLeavesTheRequirementUnsatisfied() {
            Requirement both = requiring(signer("classic", CLASSIC), signer("pqc", PQC));

            assertThat(OutcomeRollup.derive(List.of(verifiedBy(CLASSIC), unsupportedNaming(OTHER)),
                    both, ClaimSetMode.ALL_CLAIMS).outcome())
                    .isEqualTo(ArtifactOutcome.UNSATISFIED);
        }

        /**
         * An appended block naming the co-signer cannot rescue a signature from the wrong key:
         * the clause the classic key belongs in stays unmet, and the appended block names a key
         * that does not belong in it.
         */
        @Test
        void anUncheckableClaimDoesNotExcuseAWrongVerifiedSigner() {
            Requirement both = requiring(signer("classic", CLASSIC), signer("pqc", PQC));

            assertThat(OutcomeRollup.derive(List.of(verifiedBy(OTHER), unsupportedNaming(PQC)),
                    both, ClaimSetMode.ALL_CLAIMS).outcome())
                    .isEqualTo(ArtifactOutcome.UNSATISFIED);
        }

        @Test
        void anUncheckableClaimAloneNamingARequiredSignerIsUnsupported() {
            Requirement pqc = requiring(signer("pqc", PQC));

            OutcomeRollup.Result result = OutcomeRollup.derive(List.of(unsupportedNaming(PQC)),
                    pqc, ClaimSetMode.ALL_CLAIMS);

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.INDETERMINATE);
            assertThat(result.reason()).isEqualTo(IndeterminateReason.UNSUPPORTED_ALGORITHM);
        }

        /**
         * Whether a classic block verified alongside it does not change what an uncheckable
         * claim naming a signer the policy does not trust reads as.
         */
        @Test
        void anUncheckableClaimAloneNamingSomeoneElseIsUnsatisfied() {
            Requirement pqc = requiring(signer("pqc", PQC));

            assertThat(OutcomeRollup.derive(List.of(unsupportedNaming(OTHER)), pqc,
                    ClaimSetMode.ALL_CLAIMS).outcome())
                    .isEqualTo(ArtifactOutcome.UNSATISFIED);
        }

        @Test
        void anUncheckableClaimNamingNoOneLeavesNothingToJudgeTheSignerBy() {
            Requirement pqc = requiring(signer("pqc", PQC));
            ClaimResult anonymous = claim(ClaimOutcome.INDETERMINATE,
                    IndeterminateReason.UNSUPPORTED_ALGORITHM);

            OutcomeRollup.Result result = OutcomeRollup.derive(
                    List.of(unsupportedNaming(OTHER), anonymous), pqc, ClaimSetMode.ALL_CLAIMS);

            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.INDETERMINATE);
            assertThat(result.reason()).isEqualTo(IndeterminateReason.UNSUPPORTED_ALGORITHM);
        }

        @Test
        void oneSignerWithBothKeysIsSatisfiedByTheClassicClaimAlone() {
            Requirement publisher = requiring(signer("publisher", CLASSIC, PQC));

            assertThat(OutcomeRollup.derive(List.of(verifiedBy(CLASSIC), unsupportedNaming(PQC)),
                    publisher, ClaimSetMode.ALL_CLAIMS).outcome())
                    .isEqualTo(ArtifactOutcome.SATISFIED);
        }
    }
}
