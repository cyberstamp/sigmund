package dev.cyberstamp.sigmund.core;

import java.time.Instant;
import java.util.List;

/**
 * What verification established about one artifact, and the claims it was established from.
 *
 * <p>
 * Every claim found is kept, including those that did not contribute: a claim set aside
 * because no installed tool understands its algorithm, or one from an attester policy does not
 * accept, is exactly what explains an outcome someone did not expect. A result that records
 * only its verdict leaves a reader unable to tell a coverage gap from a policy gap.
 *
 * @param subject the artifact, identified by the bytes that were verified
 * @param outcome what verification established
 * @param reason why it could not be decided, {@code null} unless indeterminate
 * @param matchedRule the policy rule that applied to the artifact, {@code null} when none did
 * @param claims every claim found for the artifact, contributing or not
 * @param evidenceWithoutClaims the evidence files found for the artifact that yielded no claim —
 *        one that could not be read, or whose bytes hold no signature — which leave the outcome
 *        undecided with their reason unless something else decides it
 * @param verifiedAt when Sigmund evaluated the artifact
 */
public record ArtifactResult(
        ArtifactSubject subject,
        ArtifactOutcome outcome,
        IndeterminateReason reason,
        MatchedRule matchedRule,
        List<ClaimResult> claims,
        List<EvidenceWithoutClaims> evidenceWithoutClaims,
        Instant verifiedAt) {

    /**
     * Rejects results that cannot be read back consistently.
     *
     * @throws IllegalArgumentException if the subject or outcome is missing, or the outcome and
     *         reason disagree
     */
    public ArtifactResult {
        if (subject == null) {
            throw new IllegalArgumentException("an artifact result must name its subject");
        }
        if (outcome == null) {
            throw new IllegalArgumentException("artifact outcome must not be null");
        }
        if (outcome == ArtifactOutcome.INDETERMINATE && reason == null) {
            throw new IllegalArgumentException(
                    "an indeterminate artifact result must carry a reason: " + subject.coords());
        }
        if (outcome != ArtifactOutcome.INDETERMINATE && reason != null) {
            throw new IllegalArgumentException(
                    "a " + outcome + " artifact result must not carry an indeterminate reason: "
                            + subject.coords());
        }
        claims = claims == null ? List.of() : List.copyOf(claims);
        evidenceWithoutClaims = evidenceWithoutClaims == null ? List.of() : List.copyOf(evidenceWithoutClaims);
    }

}
