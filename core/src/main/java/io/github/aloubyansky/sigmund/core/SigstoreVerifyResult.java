package io.github.aloubyansky.sigmund.core;

/**
 * Verification result for a Sigstore signature bundle.
 * <p>
 * Carries Sigstore-specific fields: the OIDC issuer URL and the Rekor
 * transparency log index. This is a placeholder for future Sigstore integration.
 *
 * @see VerifyResult
 */
public final class SigstoreVerifyResult extends VerifyResult {

    private final String issuer;
    private final String logIndex;

    /**
     * Creates a new Sigstore verification result.
     *
     * @param verdict the verification outcome
     * @param signerDisplayName human-readable signer (typically the OIDC subject), or {@code null}
     * @param algorithm the algorithm name, or {@code null}
     * @param issuer the OIDC issuer URL, or {@code null}
     * @param logIndex the Rekor transparency log entry index, or {@code null}
     */
    public SigstoreVerifyResult(Verdict verdict, String signerDisplayName,
            String algorithm, String issuer, String logIndex) {
        super(verdict, signerDisplayName, algorithm);
        this.issuer = issuer;
        this.logIndex = logIndex;
    }

    /**
     * Returns the OIDC issuer URL.
     *
     * @return the issuer URL, or {@code null}
     */
    public String issuer() {
        return issuer;
    }

    /**
     * Returns the Rekor transparency log entry index.
     *
     * @return the log index, or {@code null}
     */
    public String logIndex() {
        return logIndex;
    }

}
