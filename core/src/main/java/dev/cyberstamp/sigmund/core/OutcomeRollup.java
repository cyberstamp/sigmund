package dev.cyberstamp.sigmund.core;

import java.util.ArrayList;
import java.util.List;

/**
 * Derives an {@link ArtifactOutcome} from the results of the claims found for an artifact.
 *
 * <p>
 * One implementation, used by every insertion point, so that a goal and a resolver-level
 * extension cannot reach different verdicts from the same policy and the same evidence.
 *
 * <p>
 * The rules apply in a fixed order, each deciding only if the earlier ones did not:
 *
 * <ol>
 * <li>any failed claim wins — a valid claim alongside a failing one does not mask it;</li>
 * <li>claims no installed tool supports are set aside, and take no further part unless a rule
 * demanded that claim kind;</li>
 * <li>no applicable rule means {@link ArtifactOutcome#NOT_CONFIGURED};</li>
 * <li>requirements met, honouring the claim-set mode, means
 * {@link ArtifactOutcome#SATISFIED};</li>
 * <li>otherwise whichever remaining state is most informative decides: an unresolved claim
 * over a rejected one, a rejected one over no evidence at all.</li>
 * </ol>
 */
final class OutcomeRollup {

    private OutcomeRollup() {
    }

    /**
     * Derives the outcome for one artifact.
     *
     * @param coords the artifact being evaluated, which selects the applicable rule
     * @param claims every claim found for the artifact, in the order they were parsed
     * @param evaluator decides whether the verified claims satisfy the applicable rule
     * @param requiredKind the claim kind a rule demands, by format name, or {@code null}
     * @param mode what to do with claims beyond those that satisfied the requirements
     * @return the outcome and, where one applies, the reason it could not be decided
     */
    public static Result derive(ArtifactCoords coords, List<ClaimResult> claims,
            RequirementEvaluator evaluator, String requiredKind, ClaimSetMode mode) {
        List<ClaimResult> found = claims == null ? List.of() : claims;

        // One pass: a failed claim ends it, an unsupported one is set aside before
        // requirements are evaluated - which is what lets a hybrid signature verify on its
        // classic block when the post-quantum tooling is absent - and the rest are sorted
        // into what verified and why anything else did not.
        boolean anySetAside = false;
        List<ClaimResult> verified = null;
        IndeterminateReason unresolvedReason = null;
        for (ClaimResult claim : found) {
            switch (claim.outcome()) {
                case FAILED -> {
                    // an attack signal is never masked by evidence that did verify
                    return new Result(ArtifactOutcome.FAILED, null);
                }
                case VERIFIED -> verified = append(verified, claim);
                case INDETERMINATE -> {
                    if (claim.reason() == IndeterminateReason.UNSUPPORTED_ALGORITHM) {
                        anySetAside = true;
                    } else if (unresolvedReason == null) {
                        unresolvedReason = claim.reason();
                    }
                }
                // A claim outcome nobody accounted for must not be skipped into a pass:
                // an unhandled state silently dropped here is how a verdict stops meaning
                // what it says.
                default -> throw new IllegalStateException(
                        "unhandled claim outcome: " + claim.outcome());
            }
        }

        // no rule applies to this artifact
        RequirementEvaluator.Evaluation evaluation = evaluator == null ? null
                : evaluator.evaluate(coords, verified == null ? List.of() : verified);
        if (evaluation == null) {
            return new Result(ArtifactOutcome.NOT_CONFIGURED, null);
        }

        // the rule demanded a claim kind that nothing installed could check
        if (requiredKind != null && anySetAside && !evaluation.satisfied()) {
            return indeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM);
        }

        // requirements met, subject to what the claim-set mode says about the rest
        if (evaluation.satisfied()) {
            if (mode == ClaimSetMode.ANY_CLAIM) {
                return new Result(ArtifactOutcome.SATISFIED, null);
            }
            if (!evaluation.unaccepted().isEmpty()) {
                return new Result(ArtifactOutcome.UNSATISFIED, null);
            }
            if (unresolvedReason != null) {
                return indeterminate(unresolvedReason);
            }
            return new Result(ArtifactOutcome.SATISFIED, null);
        }

        // requirements unmet: report whichever remaining state tells an operator the most
        if (unresolvedReason != null) {
            return indeterminate(unresolvedReason);
        }
        if (verified != null) {
            return new Result(ArtifactOutcome.UNSATISFIED, null);
        }
        if (anySetAside) {
            return indeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM);
        }
        return new Result(ArtifactOutcome.NO_CLAIM, null);
    }

    private static Result indeterminate(IndeterminateReason reason) {
        return new Result(ArtifactOutcome.INDETERMINATE, reason);
    }

    private static List<ClaimResult> append(List<ClaimResult> claims, ClaimResult claim) {
        List<ClaimResult> target = claims == null ? new ArrayList<>() : claims;
        target.add(claim);
        return target;
    }

    /**
     * What the roll-up decided.
     *
     * <p>
     * Claims set aside for an unsupported algorithm are not repeated here: they stay in the
     * artifact's claim list, where {@link ClaimResult#isIndeterminateBecause} identifies them.
     *
     * @param outcome the artifact's outcome
     * @param reason why it could not be decided, {@code null} unless indeterminate
     */
    public record Result(ArtifactOutcome outcome, IndeterminateReason reason) {
    }
}
