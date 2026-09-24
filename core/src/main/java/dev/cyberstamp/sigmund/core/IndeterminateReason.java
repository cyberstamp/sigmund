package dev.cyberstamp.sigmund.core;

/**
 * Why verification of a claim could not complete.
 *
 * <p>
 * Operators triage these differently, which is the whole point of separating them: a
 * transient reason may resolve on the next run or from a cached result, while a permanent
 * one will not change until the tooling or the evidence does. Reporting them as one state
 * makes a permanently unverifiable artifact look like a flaky network forever.
 */
public enum IndeterminateReason {

    /**
     * OpenPGP only: the signer's key is not available locally and no configured keyserver
     * supplied it.
     */
    KEY_UNAVAILABLE(true),

    /** Sigstore: trust-root metadata is missing or too stale to verify against. */
    TRUST_ROOT_UNAVAILABLE(true),

    /**
     * Evidence might exist but a source could not be queried. Only arises for
     * network-backed discovery.
     */
    DISCOVERY_UNAVAILABLE(true),

    /**
     * A verification tool could not be run, or failed while running. Distinct from
     * {@link #UNSUPPORTED_ALGORITHM}: the tool would understand the claim, but it is
     * missing, misconfigured or broken.
     */
    TOOL_UNAVAILABLE(true),

    /**
     * No available tool implements the claim's algorithm. Permanent until the toolchain
     * changes — installing Sequoia is what resolves it for post-quantum signatures.
     */
    UNSUPPORTED_ALGORITHM(false),

    /** The evidence could not be parsed. Permanent: the bytes will not improve. */
    EVIDENCE_MALFORMED(false);

    private final boolean isTransient;

    IndeterminateReason(boolean isTransient) {
        this.isTransient = isTransient;
    }

    /**
     * Indicates whether retrying, or a cached earlier result, could yield a different
     * answer.
     *
     * @return {@code true} when the condition may resolve on its own
     */
    public boolean isTransient() {
        return isTransient;
    }
}
