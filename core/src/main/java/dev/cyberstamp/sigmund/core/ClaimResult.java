package dev.cyberstamp.sigmund.core;

import java.time.Instant;
import java.util.List;

/**
 * What verifying one {@link Claim} established, with everything needed to explain it later.
 *
 * <p>
 * A result that changes between runs has to be explainable from the record: which claim was
 * checked, who attested it and in what capacity, which trust root answered, which evidence
 * file it came from, when the claim was made and who said so. Recording only a verdict leaves
 * a differing outcome indistinguishable from a bug.
 *
 * <p>
 * This is deliberately not the artifact-level view: a claim is never {@code NO_CLAIM} and is
 * never {@code UNSATISFIED}, because satisfaction is a property of requirements evaluated over
 * a set of claims rather than of any one assertion.
 *
 * @param kind the format that produced the claim, such as {@code openpgp} or
 *        {@code sigstore}; the same name formats and toolchains are configured by
 * @param outcome what verification established
 * @param reason why verification could not complete, {@code null} unless indeterminate
 * @param attesterCredentials the credentials the claim proved, empty unless it verified
 * @param attesterDisplayName a human-readable attester description, or {@code null}
 * @param role the capacity the attester acted in
 * @param trustRoot the trust root the claim was verified against
 * @param evidence the evidence the claim was parsed from
 * @param claimTime when the claim was made, or {@code null} when the evidence records none
 * @param claimTimeSource who asserted {@code claimTime}
 * @param verifiedAt when Sigmund evaluated the claim
 * @param algorithm the signing algorithm, or {@code null} when unknown
 * @param verifiedBy the tool that produced the outcome, or {@code null} when none could
 */
public record ClaimResult(
        String kind,
        ClaimOutcome outcome,
        IndeterminateReason reason,
        List<Credential> attesterCredentials,
        String attesterDisplayName,
        AttesterRole role,
        TrustRootRef trustRoot,
        EvidenceRef evidence,
        Instant claimTime,
        ClaimTimeSource claimTimeSource,
        Instant verifiedAt,
        String algorithm,
        String verifiedBy) {

    /**
     * Normalizes the optional components and rejects results that cannot be explained.
     *
     * @throws IllegalArgumentException if the outcome and reason disagree, or the evidence,
     *         kind or outcome is missing
     */
    public ClaimResult {
        if (kind == null || kind.isBlank()) {
            throw new IllegalArgumentException("claim kind must not be blank");
        }
        if (outcome == null) {
            throw new IllegalArgumentException("claim outcome must not be null");
        }
        if (outcome == ClaimOutcome.INDETERMINATE && reason == null) {
            throw new IllegalArgumentException("an indeterminate claim must carry a reason");
        }
        if (outcome != ClaimOutcome.INDETERMINATE && reason != null) {
            throw new IllegalArgumentException(
                    "a " + outcome + " claim must not carry an indeterminate reason");
        }
        if (evidence == null) {
            throw new IllegalArgumentException("a claim result must name its evidence");
        }
        attesterCredentials = attesterCredentials == null
                ? List.of()
                : List.copyOf(attesterCredentials);
        role = role == null ? AttesterRole.UNKNOWN : role;
        trustRoot = trustRoot == null ? TrustRootRef.unknown() : trustRoot;
    }

    /**
     * Records the verification of a claim by a tool.
     *
     * <p>
     * The claim supplies its kind and its time; the tool's result supplies the outcome, and the
     * tool itself supplies the credentials the claim proved — that mapping belongs to the tool
     * ({@link SignatureTool#extractCredentials(VerifyResult)}), because only it knows what its
     * own result type establishes. Role is left {@link AttesterRole#UNKNOWN} here — deriving it is a
     * policy-time decision, because the issuer that asserted an identity is what says in which
     * capacity it was acting.
     *
     * @param claim the claim that was verified
     * @param kind the format that produced the claim
     * @param result what the tool established
     * @param provenCredentials the credentials the tool says the claim proved
     * @param evidence the evidence the claim was parsed from
     * @param trustRoot the trust root the tool verified against
     * @param verifiedBy the tool's name
     * @param verifiedAt when the evaluation happened
     * @return the claim result
     */
    public static ClaimResult of(Claim claim, String kind, VerifyResult result,
            List<Credential> provenCredentials, EvidenceRef evidence, TrustRootRef trustRoot,
            String verifiedBy, Instant verifiedAt) {
        return new ClaimResult(kind, result.outcome(), result.reason(), provenCredentials,
                result.signerDisplayName(), AttesterRole.UNKNOWN, trustRoot, evidence,
                claim.claimTime(), claim.claimTimeSource(), verifiedAt, result.algorithm(),
                verifiedBy);
    }

    /**
     * Indicates whether this claim could not be verified for a particular reason.
     *
     * @param expected the reason to test for
     * @return {@code true} when the claim is indeterminate for that reason
     */
    public boolean isIndeterminateBecause(IndeterminateReason expected) {
        return outcome == ClaimOutcome.INDETERMINATE && reason == expected;
    }
}
