package io.github.aloubyansky.sigmund.core;

/**
 * Capability interface for tools that can generate signing keys.
 * <p>
 * Not all backends support key generation — Sigstore is keyless, and GPG key
 * generation is typically done outside this tool. Callers can check for this
 * capability via {@code sigmund.findTool(KeyGenerator.class)}.
 *
 * @see CertExporter
 */
public interface KeyGenerator {

    /**
     * Generates a new signing key.
     *
     * @param userId the user ID for the key (e.g., {@code "Alice <alice@example.com>"})
     * @param cipherSuite the cipher suite to use (e.g., {@code "mldsa87-ed448"})
     * @return the fingerprint of the generated key
     * @throws ToolExecutionException if key generation fails
     */
    String generateKey(String userId, String cipherSuite);
}
