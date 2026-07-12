package io.github.aloubyansky.sigmund.core;

/**
 * Capability interface for tools that can look up signer identity information
 * from a key ID.
 * <p>
 * Used to resolve a key ID to a user ID string (e.g., {@code "Alice <alice@example.com>"})
 * from the local keyring, for display and trust matching purposes.
 */
public interface SignerIdentityResolver {

    /**
     * Looks up the user ID associated with a key in the local keyring.
     *
     * @param keyId the key ID or fingerprint to look up
     * @return the user ID string, or {@code null} if not found
     * @throws ToolExecutionException if the lookup operation fails
     */
    String lookupKeyUserId(String keyId);
}
