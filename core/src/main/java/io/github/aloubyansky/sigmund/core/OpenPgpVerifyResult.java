package io.github.aloubyansky.sigmund.core;

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
     * @param verdict the verification outcome
     * @param signerDisplayName human-readable signer (typically the UID), or {@code null}
     * @param algorithm the algorithm name, or {@code null}
     * @param version the signature packet version (4, 6, etc.)
     * @param keyId the short key ID, or {@code null} if unknown
     * @param fingerprint the full fingerprint, or {@code null} if unknown
     */
    public OpenPgpVerifyResult(Verdict verdict, String signerDisplayName,
            String algorithm, int version, String keyId, String fingerprint) {
        super(verdict, signerDisplayName, algorithm);
        this.version = version;
        this.keyId = keyId;
        this.fingerprint = fingerprint;
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
