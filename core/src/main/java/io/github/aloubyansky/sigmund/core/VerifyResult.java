package io.github.aloubyansky.sigmund.core;

/**
 * The result of verifying a single {@link VerificationUnit} via a {@link SignatureTool}.
 * <p>
 * Each backend produces a typed subclass with backend-specific fields (e.g.,
 * {@link OpenPgpVerifyResult} carries the key fingerprint, {@link SigstoreVerifyResult}
 * carries the OIDC issuer). The sealed hierarchy ensures new backends are added
 * intentionally in core.
 * <p>
 * The {@link SignatureTool#extractCredentials(VerifyResult)} method converts this
 * result into proven {@link Credential}s for identity matching — the tool owns
 * the mapping from its result type to proven credentials.
 *
 * @see SignatureTool#verify(java.nio.file.Path, VerificationUnit)
 * @see OpenPgpVerifyResult
 * @see SigstoreVerifyResult
 * @see UnverifiedResult
 */
public abstract sealed class VerifyResult
        permits OpenPgpVerifyResult, SigstoreVerifyResult, UnverifiedResult {

    private final Verdict verdict;
    private final String signerDisplayName;
    private final String algorithm;

    /**
     * Creates a new verify result.
     *
     * @param verdict the verification outcome
     * @param signerDisplayName human-readable signer description (UID, email, URI),
     *        or {@code null} if unknown
     * @param algorithm the signing algorithm name, or {@code null} if unknown
     */
    protected VerifyResult(Verdict verdict, String signerDisplayName, String algorithm) {
        this.verdict = verdict;
        this.signerDisplayName = signerDisplayName;
        this.algorithm = algorithm;
    }

    /**
     * Returns the verification outcome.
     *
     * @return the verdict (PASS, FAIL, NO_KEY, or SKIPPED)
     */
    public Verdict verdict() {
        return verdict;
    }

    /**
     * Returns a human-readable description of the signer.
     *
     * @return the signer display name, or {@code null} if unknown
     */
    public String signerDisplayName() {
        return signerDisplayName;
    }

    /**
     * Returns the signing algorithm name.
     *
     * @return the algorithm name (e.g., {@code "RSA"}, {@code "ML-DSA-87+Ed448"}),
     *         or {@code null} if unknown
     */
    public String algorithm() {
        return algorithm;
    }

    /**
     * Returns a format-agnostic identifier for the signer.
     * <p>
     * For OpenPGP this is the key fingerprint (or short key ID as fallback);
     * for Sigstore this is the OIDC subject. Subclasses override to provide
     * the appropriate value.
     *
     * @return the signer identifier, or {@code null} if unknown
     */
    public String signerIdentifier() {
        return null;
    }
}
