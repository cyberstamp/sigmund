package io.github.aloubyansky.sigmund.core;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Default {@link TrustPolicy} implementation backed by parsed configuration.
 * <p>
 * Pattern matching uses a colon-separated format with 1–3 parts:
 * {@code namespace}, {@code namespace:name}, or {@code namespace:name:version}.
 * Wildcards ({@code *}) match any value. When multiple patterns match,
 * the most specific one wins (exact matches score higher than wildcards,
 * and more segments score higher than fewer).
 */
public class DefaultTrustPolicy implements TrustPolicy {

    static final DefaultTrustPolicy EMPTY = new DefaultTrustPolicy(
            Map.of(), List.of(), false, UntrustedPolicy.FAIL);

    private final Map<String, List<SignerIdentity>> trustMappings;
    private final List<String> unsignedPatterns;
    private final boolean requireAllEvidenceMatch;
    private final UntrustedPolicy untrustedPolicy;

    /**
     * Creates a new default trust policy.
     *
     * @param trustMappings artifact patterns mapped to expected signers
     * @param unsignedPatterns patterns for artifacts allowed to be unsigned
     * @param requireAllEvidenceMatch whether all evidence must match
     * @param untrustedPolicy how to handle untrusted artifacts
     */
    public DefaultTrustPolicy(
            Map<String, List<SignerIdentity>> trustMappings,
            List<String> unsignedPatterns,
            boolean requireAllEvidenceMatch,
            UntrustedPolicy untrustedPolicy) {
        this.trustMappings = Map.copyOf(trustMappings);
        this.unsignedPatterns = List.copyOf(unsignedPatterns);
        this.requireAllEvidenceMatch = requireAllEvidenceMatch;
        this.untrustedPolicy = untrustedPolicy;
    }

    @Override
    public List<SignerIdentity> expectedSigners(ArtifactIdentity artifact) {
        String bestPattern = ArtifactPatternMatcher.findBestMatch(artifact, trustMappings.keySet());
        if (bestPattern == null) {
            return List.of();
        }
        return trustMappings.get(bestPattern);
    }

    @Override
    public boolean isUnsignedAllowed(ArtifactIdentity artifact) {
        return ArtifactPatternMatcher.findBestMatch(artifact, unsignedPatterns) != null;
    }

    @Override
    public boolean requireAllEvidenceMatch() {
        return requireAllEvidenceMatch;
    }

    @Override
    public UntrustedPolicy onUntrusted() {
        return untrustedPolicy;
    }

    /**
     * Creates a builder-like list of trust mappings from raw parsed data.
     */
    static Map<String, List<SignerIdentity>> resolveTrustMappings(
            Map<String, List<String>> rawTrust,
            Map<String, SignerIdentity> signers) {
        var result = new HashMap<String, List<SignerIdentity>>(rawTrust.size());
        for (var entry : rawTrust.entrySet()) {
            List<SignerIdentity> resolved = new ArrayList<>();
            for (String ref : entry.getValue()) {
                SignerIdentity signer = signers.get(ref);
                if (signer == null) {
                    throw new PolicyConfigException(
                            "Trust entry '" + entry.getKey() + "' references undefined signer '" + ref + "'");
                }
                resolved.add(signer);
            }
            result.put(entry.getKey(), List.copyOf(resolved));
        }
        return result;
    }
}
