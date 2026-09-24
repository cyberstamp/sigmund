package dev.cyberstamp.sigmund.core;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * An evidence file, read once: its bytes, and the digest of exactly those bytes.
 *
 * <p>
 * Everything that examines evidence — deciding which format handles it, parsing claims out of
 * it, and recording what was verified — works from this single read. That is a correctness
 * property rather than an optimization: reading the file separately for each step leaves a
 * window in which the file changes between steps, and a result whose recorded digest does not
 * describe the bytes its claims came from. A result exists to be trusted after the fact, so
 * the digest and the claims must come from the same bytes.
 *
 * <p>
 * Evidence also carries where it came from. That is stated by whatever located the file —
 * the sidecar lookup today, a {@code ProvenanceSource} later — rather than inferred further
 * down, because a claim found in an organization's own store carries different weight from
 * one pulled out of a public log, and policy may reasonably distinguish them.
 *
 * @see #read(Path, String)
 */
public final class Evidence {

    /** Evidence published alongside the artifact, as {@code .asc} files and bundles are. */
    public static final String SOURCE_SIDECAR = "sidecar";

    private final Path file;
    private final byte[] content;
    private final DigestSet digest;
    private final String source;
    private String text;

    private Evidence(Path file, byte[] content, DigestSet digest, String source) {
        this.file = file;
        this.content = content;
        this.digest = digest;
        this.source = source;
    }

    /**
     * Reads an evidence file and digests what was read.
     *
     * @param file the evidence file
     * @param source the source that supplied it, such as {@link #SOURCE_SIDECAR}
     * @return the evidence
     * @throws IllegalArgumentException if the source is blank
     * @throws ToolExecutionException if the file cannot be read
     */
    public static Evidence read(Path file, String source) {
        if (source == null || source.isBlank()) {
            throw new IllegalArgumentException("evidence source must not be blank: " + file);
        }
        try {
            byte[] content = Files.readAllBytes(file);
            return new Evidence(file, content, DigestSet.sha256(content), source);
        } catch (IOException e) {
            throw new ToolExecutionException("Failed to read evidence file: " + file, e);
        }
    }

    /**
     * Returns the source that supplied this evidence.
     *
     * @return the source
     */
    public String source() {
        return source;
    }

    /**
     * Returns the file this evidence was read from.
     *
     * @return the evidence file
     */
    public Path file() {
        return file;
    }

    /**
     * Returns the content decoded as UTF-8, which is how every evidence format Sigmund reads
     * is written — ASCII-armored OpenPGP, JSON Sigstore bundles, and the DSSE envelopes that
     * follow them.
     *
     * <p>
     * The raw bytes are kept rather than discarded after decoding, because the digest must
     * describe what was read: decoding is lossy for content that is not valid UTF-8, so a
     * digest taken over re-encoded text would not be the same value. They are not exposed,
     * since no format needs them; a binary evidence format would be the reason to add an
     * accessor, not speculation that one might arrive.
     *
     * @return the evidence content as text
     */
    public String text() {
        if (text == null) {
            text = new String(content, StandardCharsets.UTF_8);
        }
        return text;
    }

    /**
     * Returns the digest of the bytes that were read.
     *
     * @return the digest
     */
    public DigestSet digest() {
        return digest;
    }

    /**
     * Creates the reference recorded in a result for this evidence.
     *
     * @return the reference
     */
    public EvidenceRef ref() {
        return new EvidenceRef(file, digest, source);
    }
}
