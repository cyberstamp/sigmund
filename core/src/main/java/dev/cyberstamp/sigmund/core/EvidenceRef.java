package dev.cyberstamp.sigmund.core;

import java.io.IOException;
import java.nio.file.Path;

/**
 * The evidence a claim came from: which file was consumed, its digest, and which source
 * supplied it.
 *
 * <p>
 * The digest is what makes a result reproducible after the fact. A signature file can be
 * replaced between runs, so recording the path alone would leave a result that cannot be
 * re-derived; recording the bytes that were read settles what was actually verified.
 *
 * <p>
 * The source matters because a claim from an organization's own store carries different
 * weight from one found in a public log, and policy may reasonably distinguish them. Until
 * evidence discovery becomes pluggable, every claim comes from a sidecar file published
 * alongside the artifact.
 *
 * @param file the evidence file that was read
 * @param digest digests over that file's bytes, never empty
 * @param source the source that supplied it, never blank
 */
public record EvidenceRef(Path file, DigestSet digest, String source) {

    /**
     * Rejects references that cannot identify the evidence they describe.
     *
     * @throws IllegalArgumentException if the file, digest or source is missing
     */
    public EvidenceRef {
        if (file == null) {
            throw new IllegalArgumentException("evidence file must not be null");
        }
        if (digest == null || digest.isEmpty()) {
            throw new IllegalArgumentException(
                    "evidence must carry at least one digest: " + file);
        }
        if (source == null || source.isBlank()) {
            throw new IllegalArgumentException("evidence source must not be blank: " + file);
        }
    }

    /**
     * Creates a reference by hashing the evidence file.
     *
     * @param file the evidence file that was read
     * @param source the source that supplied it
     * @return the reference
     * @throws SigmundException if the file cannot be read
     */
    public static EvidenceRef of(Path file, String source) {
        try {
            return new EvidenceRef(file, DigestSet.sha256(file), source);
        } catch (IOException e) {
            throw new SigmundException(
                    "Failed to compute the digest of evidence " + file + ": " + e.getMessage(), e);
        }
    }
}
