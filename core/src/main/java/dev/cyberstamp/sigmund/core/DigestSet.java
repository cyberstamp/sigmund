package dev.cyberstamp.sigmund.core;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * A set of digests over the same content, keyed by algorithm name.
 *
 * <p>
 * Digests are algorithm-tagged everywhere they appear — artifact subjects, evidence
 * references and policy references — so that an additional algorithm can be introduced
 * without a format change. The shape mirrors the in-toto {@code DigestSet}:
 * {@code {"sha256": "..."}}.
 *
 * <p>
 * SHA-256 is the required algorithm. It is what Sigstore bundles, Rekor entries, in-toto
 * statements and the checksums published alongside artifacts in Maven repositories
 * already use, and it can be recomputed with standard tooling.
 *
 * <p>
 * Values are normalized to lower case, so digests produced by tools that print upper-case
 * hex compare equal to those that do not.
 *
 * @param values digest values keyed by algorithm name, never {@code null}
 */
public record DigestSet(Map<String, String> values) {

    /** Algorithm name for SHA-256, the required algorithm. */
    public static final String SHA_256 = "sha256";

    private static final int BUFFER_SIZE = 8192;

    /**
     * Normalizes algorithm names and values to lower case and rejects blank entries.
     *
     * @throws IllegalArgumentException if an algorithm name or value is blank
     */
    public DigestSet {
        values = normalize(values);
    }

    /**
     * Creates a set holding a single SHA-256 digest.
     *
     * @param hex the digest value in hexadecimal, case-insensitive
     * @return a digest set containing only that value
     */
    public static DigestSet sha256(String hex) {
        return new DigestSet(Map.of(SHA_256, hex));
    }

    /**
     * Computes the SHA-256 digest of a file's bytes.
     *
     * <p>
     * This is the one place digests enter the model: a subject identifies the bytes that
     * were verified, so the digest is taken from the file itself rather than from any
     * metadata that travelled alongside it.
     *
     * @param file the file to hash
     * @return a digest set containing the file's SHA-256 digest
     * @throws IOException if the file cannot be read
     */
    public static DigestSet sha256(Path file) throws IOException {
        MessageDigest digest = sha256Digest();
        try (InputStream in = Files.newInputStream(file)) {
            byte[] buffer = new byte[BUFFER_SIZE];
            int read;
            while ((read = in.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
        }
        return sha256(HexFormat.of().formatHex(digest.digest()));
    }

    private static MessageDigest sha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required but unavailable", e);
        }
    }

    /**
     * Computes the SHA-256 digest of content already in memory.
     *
     * @param content the bytes to hash
     * @return a digest set containing their SHA-256 digest
     */
    public static DigestSet sha256(byte[] content) {
        return sha256(HexFormat.of().formatHex(sha256Digest().digest(content)));
    }

    /**
     * Returns the SHA-256 value, or {@code null} when this set does not carry one.
     *
     * @return the SHA-256 digest in lower-case hexadecimal, or {@code null}
     */
    public String sha256() {
        return values.get(SHA_256);
    }

    /**
     * Returns the digest for an algorithm, or {@code null} when absent.
     *
     * @param algorithm the algorithm name
     * @return the digest value, or {@code null}
     */
    public String get(String algorithm) {
        return algorithm == null ? null : values.get(algorithm.toLowerCase(Locale.ROOT));
    }

    /**
     * Indicates whether this set carries no digests at all.
     *
     * @return {@code true} when empty
     */
    public boolean isEmpty() {
        return values.isEmpty();
    }

    /**
     * Compares two digest sets using the algorithms both of them carry.
     *
     * <p>
     * Two sets match when they share at least one algorithm and every shared algorithm
     * agrees. Sharing no algorithm is not a match: the comparison is undecidable, and an
     * undecidable comparison must not read as identity.
     *
     * @param other the digest set to compare against, may be {@code null}
     * @return {@code true} when the sets provably describe the same content
     */
    public boolean matches(DigestSet other) {
        if (other == null) {
            return false;
        }
        boolean shared = false;
        for (Map.Entry<String, String> entry : values.entrySet()) {
            String otherValue = other.values.get(entry.getKey());
            if (otherValue == null) {
                continue;
            }
            if (!otherValue.equals(entry.getValue())) {
                return false;
            }
            shared = true;
        }
        return shared;
    }

    private static Map<String, String> normalize(Map<String, String> values) {
        if (values == null || values.isEmpty()) {
            return Map.of();
        }
        Map<String, String> normalized = new LinkedHashMap<>(values.size());
        for (Map.Entry<String, String> entry : values.entrySet()) {
            normalized.put(normalizeAlgorithm(entry.getKey()), normalizeValue(entry.getValue()));
        }
        return Map.copyOf(normalized);
    }

    private static String normalizeAlgorithm(String algorithm) {
        if (algorithm == null || algorithm.isBlank()) {
            throw new IllegalArgumentException("digest algorithm must not be null or blank");
        }
        return algorithm.trim().toLowerCase(Locale.ROOT);
    }

    private static String normalizeValue(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("digest value must not be null or blank");
        }
        return value.trim().toLowerCase(Locale.ROOT);
    }
}
