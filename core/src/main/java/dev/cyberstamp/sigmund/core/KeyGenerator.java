package dev.cyberstamp.sigmund.core;

/**
 * Capability interface for tools that can generate signing keys.
 * <p>
 * Only Bouncy Castle generates keys through Sigmund, since it has no command-line tool of its
 * own: Sigstore is keyless, and {@code gpg} and {@code sq} keys are generated with those tools
 * themselves, which cover passphrases, expiry and profiles. Callers can check for this
 * capability via {@code sigmund.findTool(KeyGenerator.class)}.
 *
 * @see CertExporter
 */
public interface KeyGenerator {

    /**
     * Generates a new signing key.
     *
     * @param userId the user ID for the key (e.g., {@code "Alice <alice@example.com>"})
     * @param cipherSuite the cipher suite to use (e.g., {@code "ed25519"}), or {@code null} for
     *        the tool's default
     * @param credentialType the key version to generate, {@code pgp4} or {@code pgp6}, or
     *        {@code null} for the tool's default
     * @return the fingerprint of the generated key
     * @throws ToolExecutionException if key generation fails, or the tool cannot produce the
     *         type with the suite
     */
    String generateKey(String userId, String cipherSuite, String credentialType);
}
