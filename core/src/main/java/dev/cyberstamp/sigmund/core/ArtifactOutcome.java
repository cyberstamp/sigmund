package dev.cyberstamp.sigmund.core;

/**
 * What verification established about one artifact, as distinct from what any single claim
 * established ({@link ClaimOutcome}).
 *
 * <p>
 * The load-bearing split is between an attack signal and an infrastructure problem: these must
 * never collapse into one state. A failed signature is a security event; an unreachable
 * keyserver is an operational one; no evidence at all is a coverage decision.
 */
public enum ArtifactOutcome {

    /** Requirements met. Nobody needs to act. */
    SATISFIED,

    /**
     * Claims verified, but the identity or role does not match policy. The policy owner acts:
     * either the artifact changed hands, or the policy is out of date.
     */
    UNSATISFIED,

    /** Cryptographic verification failed. This is the attack signal, and security acts. */
    FAILED,

    /**
     * No evidence was found. A coverage decision rather than an incident — most artifacts
     * carry no attestation today — and named so that counts stay honest.
     */
    NO_CLAIM,

    /** Evidence exists but verification could not complete. Infrastructure acts. */
    INDETERMINATE,

    /** No requirement applies to this artifact. Nobody needs to act. */
    NOT_CONFIGURED
}
