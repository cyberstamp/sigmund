package io.github.aloubyansky.sigmund.core;

/**
 * The outcome of a signature verification operation.
 * <p>
 * Distinguishes between successful verification, failed verification,
 * missing keys, and skipped verification.
 *
 * @see SignatureTool#verify(java.nio.file.Path, VerificationUnit)
 */
public enum Verdict {

    /**
     * The signature is valid and verification passed.
     * <p>
     * This indicates that the signature was successfully verified against the
     * expected public key and the signed data matches the signature.
     */
    PASS,

    /**
     * The signature verification failed.
     * <p>
     * This indicates that either:
     * <ul>
     * <li>The signature is invalid (does not match the signed data)</li>
     * <li>The signature was created by a different key than expected</li>
     * <li>The signed data has been modified since signing</li>
     * </ul>
     */
    FAIL,

    /**
     * The required key for verification is not available.
     * <p>
     * This indicates that the verification tool does not have access to the
     * public key needed to verify the signature. This is distinct from
     * {@link #FAIL}, as it represents a configuration issue rather than an
     * invalid signature.
     */
    NO_KEY,

    /**
     * Verification was not attempted.
     * <p>
     * This indicates that no signature was present or the tool could not
     * handle the verification unit. This is distinct from {@link #FAIL},
     * which indicates that verification was attempted and the signature
     * was invalid.
     */
    SKIPPED
}
