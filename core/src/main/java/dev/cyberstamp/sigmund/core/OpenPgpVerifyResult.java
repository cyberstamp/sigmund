package dev.cyberstamp.sigmund.core;

/**
 * Verification result for an OpenPGP signature block.
 * <p>
 * Carries OpenPGP-specific fields: the signature packet version, the short key ID,
 * and the full fingerprint. The credential type produced by
 * {@link SignatureTool#extractCredentials(VerifyResult)} is determined by the packet
 * version — {@code version < 6} produces {@code "openpgp4"}, {@code version >= 6}
 * produces {@code "openpgp6"}.
 *
 * @see VerifyResult
 */
public final class OpenPgpVerifyResult extends VerifyResult {

    private final int version;
    private final String keyId;
    private final String fingerprint;

    /**
     * Creates a new OpenPGP verification result.
     *
     * @param outcome what verification established
     * @param reason why verification could not complete, or {@code null}
     * @param signerDisplayName human-readable signer (typically the UID), or {@code null}
     * @param algorithm the algorithm name, or {@code null}
     * @param version the signature packet version (4, 6, etc.)
     * @param keyId the short key ID, or {@code null} if unknown
     * @param fingerprint the full fingerprint, or {@code null} if unknown
     */
    public OpenPgpVerifyResult(ClaimOutcome outcome, IndeterminateReason reason,
            String signerDisplayName, String algorithm, int version, String keyId,
            String fingerprint) {
        super(outcome, reason, signerDisplayName, algorithm);
        this.version = version;
        this.keyId = keyId;
        this.fingerprint = fingerprint;
    }

    /**
     * Creates a result for a verified OpenPGP signature.
     *
     * @param signerDisplayName the signer's user ID, or {@code null} if unknown
     * @param algorithm the signing algorithm name
     * @param version the signature packet version
     * @param keyId the signing key ID
     * @param fingerprint the signing key fingerprint
     * @return a verified result
     */
    public static OpenPgpVerifyResult verified(String signerDisplayName, String algorithm,
            int version, String keyId, String fingerprint) {
        return new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, signerDisplayName,
                algorithm, version, keyId, fingerprint);
    }

    /**
     * Creates a result for a signature that did not verify — the attack signal.
     *
     * @param signerDisplayName the signer's user ID, or {@code null} if unknown
     * @param algorithm the signing algorithm name
     * @param version the signature packet version
     * @param keyId the signing key ID
     * @param fingerprint the signing key fingerprint
     * @return a failed result
     */
    public static OpenPgpVerifyResult failed(String signerDisplayName, String algorithm,
            int version, String keyId, String fingerprint) {
        return new OpenPgpVerifyResult(ClaimOutcome.FAILED, null, signerDisplayName,
                algorithm, version, keyId, fingerprint);
    }

    /**
     * Creates a result for a claim that could not be verified, carrying nothing but the
     * reason.
     *
     * <p>
     * Used where the claim revealed nothing usable — a tool that does not handle this claim
     * kind, or evidence whose signature packet could not be read at all.
     *
     * @param reason why verification could not complete
     * @return an indeterminate result with no signature metadata
     */
    public static OpenPgpVerifyResult indeterminate(IndeterminateReason reason) {
        return indeterminate(reason, null, null, -1, null, null);
    }

    /**
     * Creates a result for a claim that could not be verified, keeping what the signature
     * packet already revealed.
     *
     * <p>
     * The metadata matters for reporting even though no verdict was reached: an operator
     * triaging {@link IndeterminateReason#KEY_UNAVAILABLE} needs the fingerprint in order to
     * fetch the key.
     *
     * @param reason why verification could not complete
     * @param signerDisplayName the signer's user ID, or {@code null} if unknown
     * @param algorithm the signing algorithm name, or {@code null} if unknown
     * @param version the signature packet version, or {@code -1} if unknown
     * @param keyId the signing key ID, or {@code null} if unknown
     * @param fingerprint the signing key fingerprint, or {@code null} if unknown
     * @return an indeterminate result
     */
    public static OpenPgpVerifyResult indeterminate(IndeterminateReason reason,
            String signerDisplayName, String algorithm, int version, String keyId,
            String fingerprint) {
        return new OpenPgpVerifyResult(ClaimOutcome.INDETERMINATE, reason, signerDisplayName,
                algorithm, version, keyId, fingerprint);
    }

    /**
     * Returns the OpenPGP signature packet version.
     *
     * @return the version (e.g., 4 or 6)
     */
    public int version() {
        return version;
    }

    /**
     * Returns the short key ID (typically 16 hex characters).
     *
     * @return the key ID, or {@code null} if not available
     */
    public String keyId() {
        return keyId;
    }

    /**
     * Returns the full key fingerprint.
     *
     * @return the fingerprint as an uppercase hex string, or {@code null} if not available
     */
    public String fingerprint() {
        return fingerprint;
    }

    /**
     * Returns the fingerprint if available, falling back to the short key ID.
     *
     * @return the best available key identifier, or {@code null} if neither is known
     */
    public String preferredKeyId() {
        return fingerprint != null ? fingerprint : keyId;
    }

    @Override
    public String signerIdentifier() {
        return preferredKeyId();
    }
}
