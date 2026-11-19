package dev.cyberstamp.sigmund.core;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Resolves who the key behind a verified OpenPGP claim belongs to, by adding the identities a
 * directory vouches for, where policy needs them.
 *
 * <p>
 * An OpenPGP signature proves a key, not who holds it. When a signer is named by address with
 * a directory as issuer, the directory is asked which verified addresses it serves for the
 * signing key, and each becomes an {@link IdentityCredential} the claim proves. That is what
 * lets policy accept a publisher's key generated after the policy was written.
 *
 * <p>
 * The directory is asked only when the answer can matter: for an artifact whose expected
 * signers include an email entry a directory can vouch for, and for a claim whose key none of
 * those signers' pinned fingerprints already accepts. A signer carrying both fingerprints and
 * an address therefore verifies offline for the keys already pinned, and only a new key costs
 * a lookup.
 *
 * <p>
 * A lookup that fails leaves the claim {@link IndeterminateReason#KEY_UNAVAILABLE}, never a
 * pass and never a rejection: whether the signer is trusted could not be decided.
 */
final class ClaimIdentityResolver {

    private final TrustPolicy policy;
    private final Map<String, OpenPgpDirectory> directories;
    private final boolean lookupsEnabled;

    /**
     * Creates the resolver for a policy.
     *
     * @param policy the policy whose signers decide when a lookup is needed
     * @param directories the known directories by canonical name
     * @param lookupsEnabled whether directories may be asked over the network; when not, a
     *        needed lookup leaves the claim indeterminate
     */
    ClaimIdentityResolver(TrustPolicy policy, Map<String, OpenPgpDirectory> directories,
            boolean lookupsEnabled) {
        this.policy = policy;
        this.directories = Map.copyOf(directories);
        this.lookupsEnabled = lookupsEnabled;
    }

    /**
     * Creates the resolver for callers that name the signers and issuers themselves and have no
     * policy, such as signing checking a fresh signature against the configured signer. Only
     * {@link #resolve(List, List, List)} can be used on it.
     *
     * @param directories the known directories by canonical name
     * @param lookupsEnabled whether directories may be asked over the network; when not, a
     *        needed lookup leaves the claim indeterminate
     */
    ClaimIdentityResolver(Map<String, OpenPgpDirectory> directories, boolean lookupsEnabled) {
        this.policy = null;
        this.directories = Map.copyOf(directories);
        this.lookupsEnabled = lookupsEnabled;
    }

    /**
     * Resolves who the keys of an artifact's claims belong to, where policy needs it, by
     * adding the identities a directory vouches for.
     *
     * @param coords the artifact, which selects the expected signers
     * @param claims the claims found for it
     * @return the claims, with directory identities added where policy needs them
     */
    List<ClaimResult> resolve(ArtifactCoords coords, List<ClaimResult> claims) {
        if (policy == null) {
            throw new IllegalStateException("resolving by artifact needs a policy");
        }
        return resolve(expectedSigners(coords), policy.issuers(), claims);
    }

    /**
     * Resolves who the keys of claims belong to for explicitly given signers, by adding the
     * identities a directory vouches for. This is the per-artifact resolution with the expected
     * signers and the default issuers supplied directly rather than taken from a policy.
     *
     * @param expected the signers whose directory-backed identities a lookup could satisfy
     * @param issuers the default issuers for identity entries that name none
     * @param claims the claims to resolve
     * @return the claims, with directory identities added where the signers need them
     */
    List<ClaimResult> resolve(List<SignerIdentity> expected, List<String> issuers,
            List<ClaimResult> claims) {
        Set<String> needed = neededDirectories(expected, issuers);
        if (needed.isEmpty()) {
            return claims;
        }
        List<ClaimResult> resolved = new ArrayList<>(claims.size());
        for (ClaimResult claim : claims) {
            resolved.add(needsLookup(claim, expected) ? lookUp(claim, needed) : claim);
        }
        return resolved;
    }

    /**
     * Records, for each claim, which listed issuer vouches for the name it displays, so a report
     * never shows a name read from a signed key as though it were verified.
     *
     * <p>
     * An OpenPGP claim's name is vouched for by the first listed directory whose own copy of the
     * signing key carried exactly that user ID; a Sigstore claim's by the OIDC issuer that
     * certified it, when listed. Nothing is asked of the network, and the result is never a
     * credential and never changes an outcome.
     *
     * @param issuers the issuers policy lists, in any form {@link IssuerKind#canonicalName(String)}
     *        accepts
     * @param claims the claims to label
     * @return the claims, each carrying the issuer vouching for its displayed name where one does
     */
    List<ClaimResult> vouchForDisplayNames(List<String> issuers, List<ClaimResult> claims) {
        List<String> listed = issuers.stream().map(IssuerKind::canonicalName).toList();
        List<ClaimResult> vouched = new ArrayList<>(claims.size());
        for (ClaimResult claim : claims) {
            String voucher = claim.attesterDisplayName() == null ? null : voucherOf(claim, listed);
            vouched.add(voucher == null ? claim : claim.withDisplayNameVouchedBy(voucher));
        }
        return vouched;
    }

    private String voucherOf(ClaimResult claim, List<String> listed) {
        if (claim.verifyResult() instanceof OpenPgpVerifyResult openPgp) {
            return directoryCarrying(openPgp, claim.attesterDisplayName(), listed);
        }
        if (claim.verifyResult() instanceof SigstoreVerifyResult sigstore
                && sigstore.issuer() != null
                && listed.contains(IssuerKind.canonicalName(sigstore.issuer()))) {
            return sigstore.issuer();
        }
        return null;
    }

    private String directoryCarrying(OpenPgpVerifyResult result, String displayName,
            List<String> listed) {
        String fingerprint = result.primaryFingerprint() != null
                ? result.primaryFingerprint()
                : result.fingerprint();
        if (fingerprint == null) {
            return null;
        }
        for (String name : listed) {
            OpenPgpDirectory directory = directories.get(name);
            if (directory != null && directory.carried(fingerprint, displayName)) {
                return name;
            }
        }
        return null;
    }

    /**
     * Collects the signers of the rule that applies to an artifact, flattening its requirement's
     * clauses, so the resolver knows which directory-backed identities a lookup could satisfy.
     *
     * @param coords the artifact being resolved
     * @return the expected signers, or an empty list when no rule applies
     */
    private List<SignerIdentity> expectedSigners(ArtifactCoords coords) {
        Rule rule = policy.matchRule(coords);
        if (rule == null) {
            return List.of();
        }
        List<SignerIdentity> signers = new ArrayList<>();
        for (Clause clause : rule.requirement().clauses()) {
            signers.addAll(clause.signers());
        }
        return signers;
    }

    private Set<String> neededDirectories(List<SignerIdentity> signers, List<String> issuers) {
        Set<String> needed = new LinkedHashSet<>();
        for (SignerIdentity signer : signers) {
            for (Credential credential : signer.credentials()) {
                if (credential instanceof IdentityCredential entry
                        && IssuerKind.OPENPGP_DIRECTORY.asserts(entry.attributes().keySet())) {
                    addDirectories(needed, entry, issuers);
                }
            }
        }
        return needed;
    }

    private void addDirectories(Set<String> needed, IdentityCredential entry,
            List<String> defaultIssuers) {
        List<String> issuers = entry.issuer() != null ? List.of(entry.issuer()) : defaultIssuers;
        for (String issuer : issuers) {
            if (directories.containsKey(issuer)) {
                needed.add(issuer);
            }
        }
    }

    private static boolean needsLookup(ClaimResult claim, List<SignerIdentity> expected) {
        List<KeyCredential> keys = keysOf(claim);
        return claim.outcome() == ClaimOutcome.VERIFIED
                && !keys.isEmpty()
                && !pinned(keys, expected);
    }

    private static boolean pinned(List<KeyCredential> keys, List<SignerIdentity> expected) {
        for (SignerIdentity signer : expected) {
            for (Credential credential : signer.credentials()) {
                for (KeyCredential key : keys) {
                    if (credential.matches(key)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private ClaimResult lookUp(ClaimResult claim, Set<String> needed) {
        if (!lookupsEnabled) {
            return claim.unresolved(IndeterminateReason.KEY_UNAVAILABLE);
        }
        String fingerprint = keysOf(claim).get(0).fingerprint();
        List<IdentityCredential> identities;
        try {
            identities = directoryIdentities(directories, needed, fingerprint);
        } catch (IOException unavailable) {
            return claim.unresolved(IndeterminateReason.KEY_UNAVAILABLE);
        }
        return identities.isEmpty() ? claim : claim.withAdditionalCredentials(List.<Credential> copyOf(identities));
    }

    /**
     * Asks directories which verified addresses they serve for a key.
     *
     * @param directories the known directories by canonical name
     * @param names the canonical names of the directories to ask; names that are not known
     *        directories are skipped
     * @param fingerprint the key's full fingerprint
     * @return each address as an email identity from the directory that served it
     * @throws IOException if a directory cannot be reached
     */
    static List<IdentityCredential> directoryIdentities(Map<String, OpenPgpDirectory> directories,
            Collection<String> names, String fingerprint) throws IOException {
        List<IdentityCredential> identities = new ArrayList<>();
        for (String name : names) {
            OpenPgpDirectory directory = directories.get(name);
            if (directory == null) {
                continue;
            }
            for (String address : directory.verifiedAddresses(fingerprint)) {
                identities.add(IdentityCredential.email(name, address));
            }
        }
        return identities;
    }

    private static List<KeyCredential> keysOf(ClaimResult claim) {
        List<KeyCredential> keys = List.of();
        for (Credential credential : claim.attesterCredentials()) {
            if (credential instanceof KeyCredential key) {
                if (keys.isEmpty()) {
                    keys = new ArrayList<>(2);
                }
                keys.add(key);
            }
        }
        return keys;
    }
}
