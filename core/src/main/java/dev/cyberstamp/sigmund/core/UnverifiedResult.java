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
        this(outcome, reason, null);
    }

    /**
     * Creates an unverified result saying why its reason applies.
     *
     * @param outcome what verification established; never {@link ClaimOutcome#VERIFIED}
     * @param reason why verification could not complete, or {@code null} when it failed
     * @param detail why the outcome came out as it did, such as the evidence file that could
     *        not be read, or {@code null}
     */
    public UnverifiedResult(ClaimOutcome outcome, IndeterminateReason reason, String detail) {
        super(outcome, reason, null, null, detail);
        if (outcome == ClaimOutcome.VERIFIED) {
            throw new IllegalArgumentException(
                    "UnverifiedResult cannot claim a verified outcome: no tool verified it");
        }
    }
}
