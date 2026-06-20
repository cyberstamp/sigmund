package io.github.aloubyansky.sigmund.core;

/**
 * Aggregate outcome of verifying all signatures in a report.
 *
 * @see VerificationReport#outcome()
 */
public enum VerificationOutcome {

    /** Every signature in the report has {@link VerificationResult#PASS}. */
    ALL_PASS,

    /** At least one signature passed; none failed (some were skipped or had no key). */
    PASS_WITH_SKIPS,

    /** At least one signature passed but at least one also failed. */
    PASS_WITH_FAILURES,

    /** No signature passed (all failed, all skipped, or the list is empty). */
    NONE_PASSED
}
