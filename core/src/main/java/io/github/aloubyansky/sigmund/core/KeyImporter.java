package io.github.aloubyansky.sigmund.core;

/**
 * Capability interface for tools that can import public keys from keyservers.
 * <p>
 * Used during verification when a signing key is not in the local keyring.
 * The {@link SignatureEvidenceAdapter} calls this when a verification result
 * has {@link Verdict#NO_KEY} and {@link DiscoveryConfig#fetchSignerInfo()}
 * is enabled.
 *
 * @see DiscoveryConfig
 */
public interface KeyImporter {

    /**
     * Imports a public key from a keyserver.
     *
     * @param keyId the key ID or fingerprint to fetch
     * @param keyserver the keyserver URL to fetch from
     * @return {@code true} if the key was successfully imported
     * @throws ToolExecutionException if the import operation fails
     */
    boolean importKey(String keyId, String keyserver);
}
