package io.github.aloubyansky.sigmund.core;

/**
 * The verdict for an artifact's trust assessment — the answer to
 * "is this artifact from someone I trust?"
 *
 * @see TrustResult
 */
public enum TrustVerdict {

    /**
     * Evidence matches at least one expected signer.
     */
    TRUSTED,

    /**
     * Evidence is present and cryptographically valid, but does not match
     * any expected signer in the trust policy.
     */
    UNTRUSTED,

    /**
     * No evidence files were found for this artifact.
     */
    UNSIGNED,

    /**
     * The artifact has no entry in the trust policy — it is neither trusted,
     * unsigned-allowed, nor explicitly untrusted. The policy's
     * {@link UntrustedPolicy} setting determines whether this is a failure or a warning.
     */
    NOT_CONFIGURED,

    /**
     * Evidence is present but cryptographically invalid (signature verification failed).
     */
    VERIFICATION_FAILED
}
