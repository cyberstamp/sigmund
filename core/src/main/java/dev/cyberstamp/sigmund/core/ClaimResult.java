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
 * @param detail why the outcome came out as it did, in the verifying tool's words — a key no
 *        keyserver has, a key revoked, or bytes that do not match — or {@code null}; allowed on
 *        an indeterminate or failed claim, never on a verified one, and it never changes the
 *        outcome
 * @param verifyResult the verifying tool's own result this record was built from, for format
 *        details such as an OpenPGP key ID or packet version; {@code null} when it was not built
 *        from one. It is what the tool said, not what the claim established: {@code outcome} can
 *        differ, as when a verified signature's signer could not be resolved
 * @param displayNameVouchedBy the issuer URL — a directory or an OIDC provider — that vouches for
 *        {@code attesterDisplayName}, or {@code null} when none does. It decides only how the name
 *        is labelled when shown; it is never a credential and never changes the outcome
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
        String detail,
        VerifyResult verifyResult,
        String displayNameVouchedBy) {

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
                claimTime, claimTimeSource, verifiedAt, algorithm, verifiedBy, null, null, null, null);
    }

    /**
     * Normalizes the optional components and rejects results that cannot be explained.
     *
     * @throws IllegalArgumentException if the outcome and reason disagree, a verified claim
     *         carries a detail, or the evidence, kind or outcome is missing
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
        if (outcome == ClaimOutcome.VERIFIED && detail != null) {
            throw new IllegalArgumentException("a verified claim carries no detail");
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
                verifiedBy, declaredIssuerOf(claim), result.detail(), result, null);
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
                algorithm, verifiedBy, declaredIssuer, null, null, displayNameVouchedBy);
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
                verifiedBy, declaredIssuer, detail, verifyResult, displayNameVouchedBy);
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
                claimTimeSource, verifiedAt, algorithm, verifiedBy, declaredIssuer, null,
                verifyResult, displayNameVouchedBy);
    }

    /**
     * Returns a copy recording which issuer vouches for the displayed name.
     *
     * @param issuer the issuer URL, or {@code null} for none
     * @return the copy
     */
    public ClaimResult withDisplayNameVouchedBy(String issuer) {
        return new ClaimResult(kind, outcome, reason, attesterCredentials, attesterDisplayName,
                trustRoot, evidence, claimTime, claimTimeSource, verifiedAt, algorithm,
                verifiedBy, declaredIssuer, detail, verifyResult, issuer);
    }

    /**
     * Returns the display name followed by who vouches for it, so a name read from a signed
     * key is never mistaken for a verified one: {@code (address verified by keys.openpgp.org)}
     * for a directory, {@code (attested by <issuer URL>)} for an OIDC provider, and
     * {@code (unverified)} when no listed issuer vouches for it.
     *
     * @return the labelled name, or {@code null} when the claim has no display name
     */
    public String labeledDisplayName() {
        if (attesterDisplayName == null) {
            return null;
        }
        return attesterDisplayName + voucherLabel();
    }

    private String voucherLabel() {
        if (displayNameVouchedBy == null) {
            return " (unverified)";
        }
        if (IssuerKind.of(displayNameVouchedBy) == IssuerKind.OPENPGP_DIRECTORY) {
            return " (address verified by " + displayNameVouchedBy.replaceFirst("^https://", "") + ")";
        }
        return " (attested by " + displayNameVouchedBy + ")";
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
