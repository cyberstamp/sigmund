package dev.cyberstamp.sigmund.core;

/**
 * Verification result for a Sigstore signature bundle.
 * <p>
 * Carries Sigstore-specific fields: the extracted Sigstore credential,
 * the Rekor transparency log index, and the SAN subject type from the
 * Fulcio certificate. The {@code subjectType} uses RFC 5280 {@code GeneralName}
 * tag values (1 = rfc822Name for email, 6 = uniformResourceIdentifier
 * for CI workflow URIs).
 *
 * @see VerifyResult
 */
public final class SigstoreVerifyResult extends VerifyResult {

    private final SigstoreCredential sigstoreCredential;
    private final String logIndex;
    private final int subjectType;

    /**
     * Creates a new Sigstore verification result.
     *
     * @param outcome what verification established
     * @param reason why verification could not complete, or {@code null}
     * @param signerDisplayName human-readable signer (typically the OIDC subject), or {@code null}
     * @param algorithm the algorithm name, or {@code null}
     * @param sigstoreCredential extracted Sigstore certificate credential, or {@code null}
     * @param logIndex the Rekor transparency log entry index, or {@code null}
     * @param subjectType the SAN type from the Sigstore certificate
     */
    public SigstoreVerifyResult(ClaimOutcome outcome, IndeterminateReason reason,
            String signerDisplayName, String algorithm, SigstoreCredential sigstoreCredential,
            String logIndex, int subjectType) {
        super(outcome, reason, signerDisplayName, algorithm);
        this.sigstoreCredential = sigstoreCredential;
        this.logIndex = logIndex;
        this.subjectType = subjectType;
    }

    /**
     * Creates a result for a bundle that could not be verified, carrying nothing but the
     * reason.
     *
     * <p>
     * Sigstore verification is all-or-nothing: until the bundle parses and its chain
     * verifies, there is no certificate to read an identity or log index from.
     *
     * @param reason why verification could not complete
     * @return an indeterminate result with no certificate metadata
     */
    public static SigstoreVerifyResult indeterminate(IndeterminateReason reason) {
        return new SigstoreVerifyResult(ClaimOutcome.INDETERMINATE, reason, null, null, null,
                null, -1);
    }

    /**
     * Returns the extracted Sigstore certificate credential, or {@code null}.
     *
     * @return the Sigstore credential, or {@code null}
     */
    public SigstoreCredential sigstoreCredential() {
        return sigstoreCredential;
    }

    /**
     * Returns the OIDC issuer URL, or {@code null}.
     *
     * @return the issuer URL, or {@code null}
     */
    public String issuer() {
        return sigstoreCredential != null ? sigstoreCredential.issuer() : null;
    }

    /**
     * Returns the Rekor transparency log entry index.
     *
     * @return the log index, or {@code null}
     */
    public String logIndex() {
        return logIndex;
    }

    /**
     * Returns the SAN subject type from the Fulcio certificate.
     * <p>
     * Uses RFC 5280 {@code GeneralName} tag values:
     * 1 = rfc822Name (email), 6 = uniformResourceIdentifier (CI workflow URI).
     * Returns {@code -1} if the type could not be determined.
     *
     * @return the GeneralName tag value
     */
    public int subjectType() {
        return subjectType;
    }

    /**
     * Returns the OIDC subject as the signer identifier.
     * <p>
     * For Sigstore, the most meaningful identifier is the OIDC subject
     * (email or workflow URI), paralleling how OpenPGP returns the key
     * fingerprint.
     *
     * @return the OIDC subject, or {@code null}
     */
    @Override
    public String signerIdentifier() {
        return signerDisplayName();
    }
}
