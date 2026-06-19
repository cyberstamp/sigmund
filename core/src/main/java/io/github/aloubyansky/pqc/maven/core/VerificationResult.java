package io.github.aloubyansky.pqc.maven.core;

/**
 * Represents the outcome of a signature verification operation.
 * <p>
 * This enum is used by {@link HybridVerifier} to report the result of each
 * individual signature verification. It distinguishes between successful
 * verification, failed verification, missing keys, absent signatures,
 * and intentionally skipped verification.
 *
 *
 * @see HybridVerifier
 * @see VerificationReport
 */
public enum VerificationResult {

    /**
     * The signature is valid and verification passed.
     * <p>
     * This indicates that the signature was successfully verified against the
     * expected public key and the signed data matches the signature.
     *
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
     *
     */
    FAIL,

    /**
     * The required key for verification is not available.
     * <p>
     * This indicates that the verification tool does not have access to the
     * public key needed to verify the signature. This is distinct from
     * {@link #FAIL}, as it represents a configuration issue rather than an
     * invalid signature.
     *
     */
    NO_KEY,

    /**
     * The signature is not present in the signature file.
     * <p>
     * This indicates that no signature block of the expected type was found
     * in the signature file.
     *
     */
    NOT_PRESENT,

    /**
     * Verification was intentionally skipped.
     * <p>
     * This is used when the keys map entry indicates that no signature is
     * expected (e.g., {@code noSig}), so verification was never attempted.
     * This is distinct from {@link #PASS}, which indicates that verification
     * was performed and succeeded.
     */
    SKIPPED
}
