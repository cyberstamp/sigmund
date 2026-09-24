package dev.cyberstamp.sigmund.core;

import java.util.List;

/**
 * Decides whether the claims found for an artifact satisfy the policy rule that applies to it.
 *
 * <p>
 * Kept separate from the roll-up so that deriving an outcome from claims stays independent of
 * how requirements are written: the roll-up needs to know whether requirements were met and
 * which claims did it, not what a requirement is.
 */
@FunctionalInterface
public interface RequirementEvaluator {

    /**
     * Evaluates the verified claims found for an artifact.
     *
     * @param coords the artifact being evaluated, which is what selects the applicable rule;
     *        rules match at GAV level, so the coordinate rather than the digest-bearing
     *        subject is what a requirement needs
     * @param verifiedClaims the claims that verified
     * @return the evaluation, or {@code null} when no requirement applies to this artifact
     */
    Evaluation evaluate(ArtifactCoords coords, List<ClaimResult> verifiedClaims);

    /**
     * The result of evaluating requirements.
     *
     * @param satisfied whether the requirements were met
     * @param accepted the claims that policy accepted
     * @param unaccepted the verified claims no requirement accepted
     */
    record Evaluation(boolean satisfied, List<ClaimResult> accepted,
            List<ClaimResult> unaccepted) {

        /** Defensively copies the claim lists. */
        public Evaluation {
            accepted = accepted == null ? List.of() : List.copyOf(accepted);
            unaccepted = unaccepted == null ? List.of() : List.copyOf(unaccepted);
        }
    }
}
