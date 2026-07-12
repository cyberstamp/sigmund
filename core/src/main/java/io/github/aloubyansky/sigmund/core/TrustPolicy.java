package io.github.aloubyansky.sigmund.core;

import java.util.List;

/**
 * Defines who should produce what and how strictly to verify.
 * <p>
 * The trust policy is the identity-first model's answer to "who do I trust for this artifact?"
 * rather than "does this signature verify?" It maps artifact patterns to expected signer
 * identities and controls how strictly evidence must match.
 * <p>
 * Declared as an interface to allow pluggable policy sources beyond YAML — for example,
 * OPA, a database, or hardcoded configuration. The default implementation is parsed from
 * {@code sigmund.yaml}.
 *
 * <h3>Separation of concerns</h3>
 * <p>
 * {@code TrustPolicy} is purely about trust decisions — who to trust and how strict to be.
 * Operational concerns like key fetching and keyserver configuration live in
 * {@link DiscoveryConfig}. This means a policy backed by OPA or a database does not need
 * to implement key-fetching logic.
 *
 * @see SignerIdentity
 * @see DiscoveryConfig
 */
public interface TrustPolicy {

    /**
     * Looks up expected signers for an artifact.
     * <p>
     * Returns an empty list if the artifact has no trust mapping ({@link TrustVerdict#NOT_CONFIGURED}).
     * A trust mapping with zero signers is a configuration error caught at parse time.
     *
     * @param artifact the artifact to look up
     * @return the expected signers, or an empty list if not configured
     */
    List<SignerIdentity> expectedSigners(ArtifactIdentity artifact);

    /**
     * Checks whether this artifact is explicitly marked as unsigned-ok.
     *
     * @param artifact the artifact to check
     * @return {@code true} if the artifact is allowed to be unsigned
     */
    boolean isUnsignedAllowed(ArtifactIdentity artifact);

    /**
     * Returns whether all evidence must match an expected signer.
     * <p>
     * When {@code true}, every piece of evidence must match an expected signer —
     * no unmatched evidence is allowed. When {@code false}, at least one match is sufficient.
     *
     * @return {@code true} if all evidence must match
     */
    boolean requireAllEvidenceMatch();

    /**
     * Returns the policy for handling untrusted or unconfigured artifacts.
     *
     * @return the untrusted policy
     * @see UntrustedPolicy
     */
    UntrustedPolicy onUntrusted();
}
