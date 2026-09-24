package dev.cyberstamp.sigmund.core;

import java.io.IOException;
import java.nio.file.Path;

/**
 * The artifact a verification result is about: a coordinate together with the digest of
 * the bytes that were actually verified.
 *
 * <p>
 * The digest is what makes this a subject rather than a name. A coordinate says which file
 * was requested; the digest says which bytes answered. Verification results, cache keys and
 * attestation subjects all need the second, which is why the digest is required here and
 * why code that only names a file — policy matching, reporting, map keys — takes
 * {@link ArtifactCoords} instead.
 *
 * <p>
 * Subjects are built where the bytes are available, normally straight after resolution.
 * There is deliberately no way to construct one from a coordinate alone.
 *
 * @param coords the artifact's coordinate, never {@code null}
 * @param digests digests over the file's bytes, never empty
 */
public record ArtifactSubject(ArtifactCoords coords, DigestSet digests) {

    /**
     * Rejects subjects that do not identify content.
     *
     * @throws IllegalArgumentException if the coordinate is {@code null} or no digest is
     *         present
     */
    public ArtifactSubject {
        if (coords == null) {
            throw new IllegalArgumentException("coords must not be null");
        }
        if (digests == null || digests.isEmpty()) {
            throw new IllegalArgumentException(
                    "a subject must carry at least one digest: " + coords);
        }
    }

    /**
     * Creates a subject for a resolved artifact by hashing the file it resolved to.
     *
     * @param coords the artifact's coordinate
     * @param artifactFile the resolved file whose bytes identify the artifact
     * @return the subject for that file
     * @throws SigmundException if the file cannot be read
     */
    public static ArtifactSubject of(ArtifactCoords coords, Path artifactFile) {
        try {
            return new ArtifactSubject(coords, DigestSet.sha256(artifactFile));
        } catch (IOException e) {
            throw new SigmundException(
                    "Failed to compute the digest of " + artifactFile + ": " + e.getMessage(), e);
        }
    }

    /**
     * Projects the coordinate to a package URL.
     *
     * @return the package URL for this artifact
     * @see ArtifactCoords#purl()
     */
    public String purl() {
        return coords.purl();
    }
}
