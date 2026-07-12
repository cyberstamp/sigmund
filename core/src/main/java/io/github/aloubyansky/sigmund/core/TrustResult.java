package io.github.aloubyansky.sigmund.core;

import java.util.List;

/**
 * The verdict for an artifact — the answer to "is this from someone I trust?"
 * <p>
 * Contains the {@link TrustVerdict}, the evidence that matched expected signers,
 * and any valid evidence that did not match. This allows callers to understand
 * <em>why</em> an artifact was trusted or rejected.
 *
 * @see TrustVerdict
 */
public class TrustResult {

    private final ArtifactIdentity artifact;
    private final TrustVerdict verdict;
    private final List<MatchedEvidence> matchedEvidence;
    private final List<EvidenceResult> unmatchedEvidence;

    /**
     * Creates a new trust result.
     *
     * @param artifact the artifact that was assessed
     * @param verdict the trust verdict
     * @param matchedEvidence evidence that matched an expected signer
     * @param unmatchedEvidence valid evidence that did not match any expected signer
     */
    public TrustResult(ArtifactIdentity artifact, TrustVerdict verdict,
            List<MatchedEvidence> matchedEvidence, List<EvidenceResult> unmatchedEvidence) {
        this.artifact = artifact;
        this.verdict = verdict;
        this.matchedEvidence = matchedEvidence != null ? List.copyOf(matchedEvidence) : List.of();
        this.unmatchedEvidence = unmatchedEvidence != null ? List.copyOf(unmatchedEvidence) : List.of();
    }

    /**
     * Returns the artifact that was assessed.
     *
     * @return the artifact identity
     */
    public ArtifactIdentity artifact() {
        return artifact;
    }

    /**
     * Returns the trust verdict.
     *
     * @return the verdict
     */
    public TrustVerdict verdict() {
        return verdict;
    }

    /**
     * Returns evidence that matched an expected signer.
     *
     * @return an unmodifiable list of matched evidence
     */
    public List<MatchedEvidence> matchedEvidence() {
        return matchedEvidence;
    }

    /**
     * Returns valid evidence that did not match any expected signer.
     *
     * @return an unmodifiable list of unmatched evidence
     */
    public List<EvidenceResult> unmatchedEvidence() {
        return unmatchedEvidence;
    }
}
