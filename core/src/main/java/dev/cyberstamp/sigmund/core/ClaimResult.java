package dev.cyberstamp.sigmund.core;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * What verifying one {@link Claim} established, with everything needed to explain it later.
 *
 * <p>
 * A result that changes between runs has to be explainable from the record: which claim was
 * checked, who attested it, which trust root answered, which evidence file it came from, when
 * the claim was made and who said so. Recording only a verdict leaves a differing outcome
 * indistinguishable from a bug.
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
 * @param attesterCredentials the credentials the claim proved: empty unless its signature
 *        verified; a claim left indeterminate because an identity could not be looked up
 *        keeps the key credentials its signature proved, for the report
 * @param attesterDisplayName a human-readable attester description, or {@code null}
 * @param trustRoot the trust root the claim was verified against
 * @param evidence the evidence the claim was parsed from
 * @param claimTime when the claim was made, or {@code null} when the evidence records none
 * @param claimTimeSource who asserted {@code claimTime}
 * @param verifiedAt when Sigmund evaluated the claim
 * @param algorithm the signing algorithm, or {@code null} when unknown
 * @param verifiedBy the tool that produced the outcome, or {@code null} when none could
 * @param declaredIssuer the key the evidence names as having made the claim — never proven, and
 *        never a credential; {@code null} when the evidence names none by full fingerprint. It
 *        lets a claim no installed tool can check say whose signature it would be, so that a
 *        requirement left unmet only for want of such a claim reads as unsupported rather than
 *        as the wrong signer
 * @param reasonDetail why the reason applies, in the verifying tool's words — a key no keyserver
 *        has, or one served without the self-signature that binds it — or {@code null}; it
 *        explains the reason and never changes the outcome
 */
public record ClaimResult(
        String kind,
        ClaimOutcome outcome,
        IndeterminateReason reason,
        List<Credential> attesterCredentials,
        String attesterDisplayName,
        TrustRootRef trustRoot,
        EvidenceRef evidence,
        Instant claimTime,
        ClaimTimeSource claimTimeSource,
        Instant verifiedAt,
        String algorithm,
        String verifiedBy,
        Credential declaredIssuer,
        String reasonDetail) {

    /**
     * Creates a result for a claim whose evidence names no issuer by full fingerprint.
     *
     * @param kind the format that produced the claim
     * @param outcome what verification established
     * @param reason why verification could not complete, {@code null} unless indeterminate
     * @param attesterCredentials the credentials the claim proved
     * @param attesterDisplayName a human-readable attester description, or {@code null}
     * @param trustRoot the trust root the claim was verified against
     * @param evidence the evidence the claim was parsed from
     * @param claimTime when the claim was made, or {@code null}
     * @param claimTimeSource who asserted {@code claimTime}
     * @param verifiedAt when Sigmund evaluated the claim
     * @param algorithm the signing algorithm, or {@code null} when unknown
     * @param verifiedBy the tool that produced the outcome, or {@code null} when none could
     */
    public ClaimResult(String kind, ClaimOutcome outcome, IndeterminateReason reason,
            List<Credential> attesterCredentials, String attesterDisplayName,
            TrustRootRef trustRoot, EvidenceRef evidence, Instant claimTime,
            ClaimTimeSource claimTimeSource, Instant verifiedAt, String algorithm,
            String verifiedBy) {
        this(kind, outcome, reason, attesterCredentials, attesterDisplayName, trustRoot, evidence,
                claimTime, claimTimeSource, verifiedAt, algorithm, verifiedBy, null, null);
    }

    /**
     * Normalizes the optional components and rejects results that cannot be explained.
     *
     * @throws IllegalArgumentException if the outcome and reason disagree, a detail explains
     *         no reason, or the evidence, kind or outcome is missing
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
        if (reason == null && reasonDetail != null) {
            throw new IllegalArgumentException("a reason detail needs a reason to explain");
        }
        if (evidence == null) {
            throw new IllegalArgumentException("a claim result must name its evidence");
        }
        attesterCredentials = attesterCredentials == null
                ? List.of()
                : List.copyOf(attesterCredentials);
        trustRoot = trustRoot == null ? TrustRootRef.unknown() : trustRoot;
    }

    /**
     * Records the verification of a claim by a tool.
     *
     * <p>
     * The claim supplies its kind and its time; the tool's result supplies the outcome, and the
     * tool itself supplies the credentials the claim proved — that mapping belongs to the tool
     * ({@link SignatureTool#extractCredentials(VerifyResult)}), because only it knows what its
     * own result type establishes.
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
                result.signerDisplayName(), trustRoot, evidence,
                claim.claimTime(), claim.claimTimeSource(), verifiedAt, result.algorithm(),
                verifiedBy, declaredIssuerOf(claim), result.reasonDetail());
    }

    /**
     * The key an OpenPGP signature packet names as its issuer, when it names it by full
     * fingerprint; a 64-bit key ID does not identify a key.
     */
    private static Credential declaredIssuerOf(Claim claim) {
        return claim instanceof OpenPgpClaim openPgp
                && KeyCredential.isOpenPgpFingerprint(openPgp.issuerFingerprint())
                        ? KeyCredential.openPgp(openPgp.issuerFingerprint())
                        : null;
    }

    /**
     * Returns this claim as it would be had the key it names verified it, or {@code null} when
     * it names none.
     *
     * <p>
     * Only for asking whether a requirement <em>could</em> be met by claims no installed tool
     * can check; the copy is never reported, stored or used to accept anything.
     *
     * @return the hypothetical copy, or {@code null}
     */
    ClaimResult asIfVerifiedByDeclaredIssuer() {
        if (declaredIssuer == null) {
            return null;
        }
        return new ClaimResult(kind, ClaimOutcome.VERIFIED, null, List.of(declaredIssuer),
                attesterDisplayName, trustRoot, evidence, claimTime, claimTimeSource, verifiedAt,
                algorithm, verifiedBy, declaredIssuer, null);
    }

    /**
     * Returns a copy that also proves the given credentials, such as identities a directory
     * vouched for once the key was known.
     *
     * @param additional the credentials to add
     * @return the copy
     */
    public ClaimResult withAdditionalCredentials(List<Credential> additional) {
        List<Credential> credentials = new ArrayList<>(attesterCredentials);
        credentials.addAll(additional);
        return new ClaimResult(kind, outcome, reason, credentials, attesterDisplayName,
                trustRoot, evidence, claimTime, claimTimeSource, verifiedAt, algorithm,
                verifiedBy, declaredIssuer, reasonDetail);
    }

    /**
     * Returns a copy that could not be resolved: the signature verified, but something the
     * verdict depends on, such as the signer's identity, could not be established.
     *
     * @param unresolvedReason why the claim could not be resolved
     * @return an indeterminate copy keeping the credentials already proven
     */
    public ClaimResult unresolved(IndeterminateReason unresolvedReason) {
        return new ClaimResult(kind, ClaimOutcome.INDETERMINATE, unresolvedReason,
                attesterCredentials, attesterDisplayName, trustRoot, evidence, claimTime,
                claimTimeSource, verifiedAt, algorithm, verifiedBy, declaredIssuer, null);
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
