package io.github.aloubyansky.sigmund.core;

/**
 * The result of a signing operation, carrying metadata about the produced signature.
 * <p>
 * Currently only carries the algorithm used, but exists as a dedicated type
 * (rather than a bare {@code String}) because it is the return type of the
 * {@link SignatureTool#sign} SPI. Future signing backends (e.g., Sigstore)
 * may need to return additional metadata such as transparency log indices
 * or certificate chains — adding fields here is backward-compatible.
 *
 * @param algorithm the algorithm actually used for signing
 *        (e.g., {@code "RSA"}, {@code "ML-DSA-87+Ed448"})
 */
public record SignResult(String algorithm) {
}
