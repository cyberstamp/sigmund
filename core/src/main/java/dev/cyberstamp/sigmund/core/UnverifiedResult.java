package dev.cyberstamp.sigmund.core;

/**
 * A {@link VerifyResult} for cases where no real verification was performed.
 * <p>
 * Used when no tool could verify a claim, or when
 * verification fails before producing a format-specific result
 * evidence could not be parsed at all.
 *
 * @see VerifyResult
 */
public final class UnverifiedResult extends VerifyResult {

    /**
     * Creates an unverified result with the given verdict.
     *
     * @param outcome what verification established; never {@link ClaimOutcome#VERIFIED}
     * @param reason why verification could not complete, or {@code null} when it failed
     */
    public UnverifiedResult(ClaimOutcome outcome, IndeterminateReason reason) {
        super(outcome, reason, null, null);
        if (outcome == ClaimOutcome.VERIFIED) {
            throw new IllegalArgumentException(
                    "UnverifiedResult cannot claim a verified outcome: no tool verified it");
        }
    }
}
