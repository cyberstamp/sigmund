package io.github.aloubyansky.sigmund.core;

/**
 * Determines how to handle artifacts that are not matched by the trust policy.
 *
 * @see TrustPolicy#onUntrusted()
 */
public enum UntrustedPolicy {

    /**
     * Reject untrusted artifacts — treat them as verification failures.
     */
    FAIL,

    /**
     * Log a warning for untrusted artifacts but continue.
     */
    WARN
}
