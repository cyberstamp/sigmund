package dev.cyberstamp.sigmund.core;

/**
 * What verifying a single {@link Claim} established.
 *
 * <p>
 * This is the claim-level vocabulary, deliberately narrower than the artifact-level one: a
 * claim is never "no claim" and is never "unsatisfied", because satisfaction is a property
 * of requirements evaluated over a set of claims, not of one assertion.
 *
 * <p>
 * The load-bearing distinction is between {@link #FAILED} and {@link #INDETERMINATE}.
 * A failed claim is an attack signal — evidence exists and the cryptography does not hold.
 * An indeterminate claim is an infrastructure or coverage problem — verification could not
 * complete. Collapsing the two makes a flaky keyserver look like a tampered artifact, and a
 * tampered artifact look like a flaky keyserver.
 */
public enum ClaimOutcome {

    /** The claim verified: the signature or attestation is cryptographically sound. */
    VERIFIED,

    /** Cryptographic verification failed. This is the attack signal. */
    FAILED,

    /**
     * Verification could not complete. The accompanying {@link IndeterminateReason} says
     * why, and whether waiting could change the answer.
     */
    INDETERMINATE;

    /**
     * Indicates whether this outcome is more conclusive than another, used when several
     * tools attempt the same claim and the most conclusive answer wins.
     *
     * @param other the outcome to compare against
     * @return {@code true} when this outcome is more conclusive
     */
    public boolean outranks(ClaimOutcome other) {
        return rank() > other.rank();
    }

    private int rank() {
        return switch (this) {
            case VERIFIED -> 2;
            case FAILED -> 1;
            case INDETERMINATE -> 0;
        };
    }
}
