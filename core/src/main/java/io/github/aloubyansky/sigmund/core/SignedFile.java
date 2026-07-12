package io.github.aloubyansky.sigmund.core;

import java.nio.file.Path;

/**
 * Metadata about a single produced signature file.
 *
 * @param path the signature file path
 * @param toolName the tool that produced it (e.g., {@code "gpg"}, {@code "sq"})
 * @param format the signature format name (e.g., {@code "openpgp"})
 * @param algorithm the algorithm used (e.g., {@code "RSA"}, {@code "ML-DSA-87+Ed448"})
 */
public record SignedFile(
        Path path,
        String toolName,
        String format,
        String algorithm) {
}
