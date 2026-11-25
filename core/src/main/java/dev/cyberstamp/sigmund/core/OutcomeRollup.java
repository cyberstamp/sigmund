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
 * <li>claims no installed tool supports are set aside: they cannot satisfy a requirement, and
 * cannot block one that the other claims meet;</li>
 * <li>no applicable rule means {@link ArtifactOutcome#NOT_CONFIGURED};</li>
 * <li>requirements met, honouring the claim-set mode, means
 * {@link ArtifactOutcome#SATISFIED};</li>
 * <li>otherwise whichever remaining state is most informative decides: an unresolved claim
 * first; then requirements left unmet only for want of a tool, which are
 * {@link IndeterminateReason#UNSUPPORTED_ALGORITHM}; then any other claim, which leaves a signer
 * the requirements do not accept; and last no evidence at all.</li>
 * </ol>
 *
 * <p>
 * An evidence file that yielded no claim — one that could not be read, or whose bytes hold no
 * signature — is unresolved like a claim no tool could decide, with its own reason
 * ({@link IndeterminateReason#EVIDENCE_UNREADABLE} or
 * {@link IndeterminateReason#EVIDENCE_MALFORMED}) when no claim's reason comes first: it may hold
 * a claim from a signer the rule does not accept, and an artifact whose only evidence yielded
 * none is not unsigned.
 */
final class OutcomeRollup {

    private OutcomeRollup() {
    }

    /**
     * Derives the outcome for one artifact.
     *
     * @param claims every claim found for the artifact, in the order they were parsed
     * @param evidenceWithoutClaims the evidence files found for the artifact that yielded no claim
     * @param evaluator the requirement of the rule that matched the artifact, or {@code null}
     *        when no rule did
     * @param mode what to do with claims beyond those that satisfied the requirements
     * @return the outcome and, where one applies, the reason it could not be decided
     */
    public static Result derive(List<ClaimResult> claims, List<EvidenceWithoutClaims> evidenceWithoutClaims,
            RequirementEvaluator evaluator, ClaimSetMode mode) {
        List<ClaimResult> found = claims == null ? List.of() : claims;

        // One pass: a failed claim ends it, an unsupported one is set aside before
        // requirements are evaluated - which is what lets a hybrid signature verify on its
        // classic block when the post-quantum tooling is absent - and the rest are sorted
        // into what verified and why anything else did not.
        List<ClaimResult> setAside = null;
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
                        setAside = append(setAside, claim);
                    } else if (unresolvedReason == null) {
                        unresolvedReason = claim.reason();
                    }
                }
                // A claim outcome nobody accounted for must not be skipped into a pass:
                // an unhandled state silently dropped here is how a verdict stops meaning
                // what it says.
                default -> throw new IllegalStateException("unhandled claim outcome: " + claim.outcome());
            }
        }
        if (unresolvedReason == null && evidenceWithoutClaims != null && !evidenceWithoutClaims.isEmpty()) {
            unresolvedReason = evidenceWithoutClaims.get(0).reason();
        }

        // no rule applies to this artifact
        RequirementEvaluator.Evaluation evaluation = evaluator == null ? null
                : evaluator.evaluate(verified == null ? List.of() : verified);
        if (evaluation == null) {
            return new Result(ArtifactOutcome.NOT_CONFIGURED, null);
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
        if (setAside != null && onlyAToolIsMissing(evaluator, verified, setAside)) {
            return indeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM);
        }
        if (verified != null || setAside != null) {
            return new Result(ArtifactOutcome.UNSATISFIED, null);
        }
        return new Result(ArtifactOutcome.NO_CLAIM, null);
    }

    /**
     * Asks whether unmet requirements are unmet only because no installed tool can check the
     * claims set aside.
     *
     * <p>
     * They are when the requirements would be met had each set-aside claim been made by the key
     * it names, and when nothing verified and some set-aside claim names no key, leaving no
     * signer to judge. Otherwise every signer in view — proven by a verified claim or named by a
     * set-aside one — leaves the requirements unmet, and installing a tool cannot change that:
     * the outcome is {@code UNSATISFIED}, whether or not a classic block verified alongside. An
     * artifact co-signed with a post-quantum key reads as "install a tool that can check this"
     * only when its key is one the policy accepts.
     */
    private static boolean onlyAToolIsMissing(RequirementEvaluator evaluator,
            List<ClaimResult> verified, List<ClaimResult> setAside) {
        return couldBeMetBy(evaluator, verified, setAside)
                || verified == null && namesNoKey(setAside);
    }

    /**
     * Asks whether the requirements would be met had the set-aside claims been made by the keys
     * they name.
     *
     * <p>
     * The verified claims are evaluated again alongside them because a requirement is a
     * conjunction: a verified claim may meet one clause and a set-aside claim another, and the
     * evaluator says only whether a set of claims meets the requirement, not which clauses it
     * left open. Adding claims can only meet more clauses, so this cannot excuse a wrong signer:
     * it holds only when every clause the verified claims leave unmet accepts a key some
     * set-aside claim names — a key the verifier cannot tell from the real thing without a tool
     * that checks it. A set-aside claim contributes that key alone, never an identity.
     */
    private static boolean couldBeMetBy(RequirementEvaluator evaluator,
            List<ClaimResult> verified, List<ClaimResult> setAside) {
        List<ClaimResult> hypothetical = verified == null ? new ArrayList<>() : new ArrayList<>(verified);
        for (ClaimResult claim : setAside) {
            ClaimResult asNamed = claim.asIfVerifiedByDeclaredIssuer();
            if (asNamed != null) {
                hypothetical.add(asNamed);
            }
        }
        RequirementEvaluator.Evaluation evaluation = evaluator.evaluate(hypothetical);
        return evaluation != null && evaluation.satisfied();
    }

    private static boolean namesNoKey(List<ClaimResult> setAside) {
        return setAside.stream().anyMatch(claim -> claim.declaredIssuer() == null);
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
