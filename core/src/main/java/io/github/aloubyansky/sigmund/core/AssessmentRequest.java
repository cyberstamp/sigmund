package io.github.aloubyansky.sigmund.core;

import java.nio.file.Path;
import java.util.List;

/**
 * A request to assess the trust status of a single artifact.
 *
 * @param artifact the artifact identity
 * @param artifactFile the artifact file on disk
 * @param evidenceFiles the evidence files (signatures, attestations) to verify
 * @see TrustVerifier#assessAll(List)
 */
public record AssessmentRequest(
        ArtifactIdentity artifact,
        Path artifactFile,
        List<Path> evidenceFiles) {

    /**
     * Creates a request with a defensive copy of evidence files.
     */
    public AssessmentRequest {
        evidenceFiles = evidenceFiles != null ? List.copyOf(evidenceFiles) : List.of();
    }
}
