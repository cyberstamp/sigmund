package dev.cyberstamp.sigmund.core;

/**
 * The result of verifying a single {@link Claim} via a {@link SignatureTool}.
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
 * @see SignatureTool#verify(java.nio.file.Path, Claim)
 * @see OpenPgpVerifyResult
 * @see SigstoreVerifyResult
 * @see UnverifiedResult
 */
public abstract sealed class VerifyResult
        permits OpenPgpVerifyResult, SigstoreVerifyResult, UnverifiedResult {

    private final ClaimOutcome outcome;
    private final IndeterminateReason reason;
    private final String signerDisplayName;
    private final String algorithm;
    private final String reasonDetail;

    /**
     * Creates a new verify result.
     *
     * @param outcome what verification established
     * @param reason why verification could not complete, required when the outcome is
     *        {@link ClaimOutcome#INDETERMINATE} and meaningless otherwise
     * @param signerDisplayName human-readable signer description (UID, email, URI),
     *        or {@code null} if unknown
     * @param algorithm the signing algorithm name, or {@code null} if unknown
     * @throws IllegalArgumentException if an indeterminate outcome carries no reason, or a
     *         conclusive one carries a reason
     */
    protected VerifyResult(ClaimOutcome outcome, IndeterminateReason reason,
            String signerDisplayName, String algorithm) {
        this(outcome, reason, signerDisplayName, algorithm, null);
    }

    /**
     * Creates a new verify result saying why its reason applies.
     *
     * @param outcome what verification established
     * @param reason why verification could not complete, required when the outcome is
     *        {@link ClaimOutcome#INDETERMINATE} and meaningless otherwise
     * @param signerDisplayName human-readable signer description (UID, email, URI),
     *        or {@code null} if unknown
     * @param algorithm the signing algorithm name, or {@code null} if unknown
     * @param reasonDetail why the reason applies, or {@code null}
     * @throws IllegalArgumentException if an indeterminate outcome carries no reason, a
     *         conclusive one carries a reason, or a detail explains no reason
     */
    protected VerifyResult(ClaimOutcome outcome, IndeterminateReason reason,
            String signerDisplayName, String algorithm, String reasonDetail) {
        requireConsistent(outcome, reason);
        if (reason == null && reasonDetail != null) {
            throw new IllegalArgumentException("a reason detail needs a reason to explain");
        }
        this.outcome = outcome;
        this.reason = reason;
        this.signerDisplayName = signerDisplayName;
        this.algorithm = algorithm;
        this.reasonDetail = reasonDetail;
    }

    private static void requireConsistent(ClaimOutcome outcome, IndeterminateReason reason) {
        if (outcome == ClaimOutcome.INDETERMINATE && reason == null) {
            throw new IllegalArgumentException(
                    "an indeterminate result must carry a reason");
        }
        if (outcome != ClaimOutcome.INDETERMINATE && reason != null) {
            throw new IllegalArgumentException(
                    "a " + outcome + " result must not carry an indeterminate reason");
        }
    }

    /**
     * Returns what verification established.
     *
     * @return the claim outcome
     */
    public ClaimOutcome outcome() {
        return outcome;
    }

    /**
     * Returns why verification could not complete.
     *
     * @return the reason, or {@code null} when the outcome is conclusive
     */
    public IndeterminateReason reason() {
        return reason;
    }

    /**
     * Returns why the reason applies, in a few words, when the tool could say.
     *
     * <p>
     * One reason covers situations an operator resolves differently:
     * {@link IndeterminateReason#KEY_UNAVAILABLE} is a key no store or keyserver has, a key
     * served without the self-signature that binds it, and a key whose certificate a tool cannot
     * use. The detail tells them apart for the report; it never changes the outcome.
     *
     * @return the detail, such as {@code "no local key store or configured keyserver has it"},
     *         or {@code null}
     */
    public String reasonDetail() {
        return reasonDetail;
    }

    /**
     * Indicates whether the claim verified.
     *
     * @return {@code true} when the outcome is {@link ClaimOutcome#VERIFIED}
     */
    public boolean isVerified() {
        return outcome == ClaimOutcome.VERIFIED;
    }

    /**
     * Indicates whether cryptographic verification failed — the attack signal.
     *
     * @return {@code true} when the outcome is {@link ClaimOutcome#FAILED}
     */
    public boolean isFailed() {
        return outcome == ClaimOutcome.FAILED;
    }

    /**
     * Indicates whether verification could not complete.
     *
     * @return {@code true} when the outcome is {@link ClaimOutcome#INDETERMINATE}
     */
    public boolean isIndeterminate() {
        return outcome == ClaimOutcome.INDETERMINATE;
    }

    /**
     * Indicates whether verification could not complete for a particular reason.
     *
     * @param expected the reason to test for
     * @return {@code true} when the outcome is indeterminate for that reason
     */
    public boolean isIndeterminate(IndeterminateReason expected) {
        return outcome == ClaimOutcome.INDETERMINATE && reason == expected;
    }

    /**
     * Indicates whether this result settles the claim better than another, used when
     * several tools attempt the same claim and the most conclusive answer is kept.
     *
     * <p>
     * A verified result beats a failed one, which beats an indeterminate one. Between two
     * indeterminate results the transient reason wins: "the keyserver was unreachable" tells
     * an operator more than "no installed tool understands this algorithm", because the
     * first may resolve on its own.
     *
     * @param other the result to compare against, may be {@code null}
     * @return {@code true} when this result is the more conclusive of the two
     */
    public boolean isMoreConclusiveThan(VerifyResult other) {
        if (other == null) {
            return true;
        }
        if (outcome != other.outcome) {
            return outcome.outranks(other.outcome);
        }
        return isIndeterminate()
                && reason.isTransient()
                && !other.reason.isTransient();
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
