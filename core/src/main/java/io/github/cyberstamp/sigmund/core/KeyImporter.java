package io.github.cyberstamp.sigmund.core;

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

    /**
     * Fetches a public key from a keyserver into an ephemeral in-memory cache
     * without persisting it to the tool's keyring on disk.
     * <p>
     * Used when {@link DiscoveryConfig#importToKeyring()} is {@code false} (the default).
     * The key is available for verification during this session but is discarded
     * when the JVM exits. Tools that cannot support ephemeral key storage (e.g.,
     * GnuPG, which requires keys in its on-disk keyring) return {@code false}.
     *
     * @param keyId the key ID or fingerprint to fetch
     * @param keyserver the keyserver URL to fetch from
     * @return {@code true} if the key was fetched and cached successfully
     */
    default boolean fetchKeyEphemeral(String keyId, String keyserver) {
        return false;
    }

    /**
     * Fetches a public key from a keyserver, choosing between persistent import
     * and ephemeral in-memory caching based on the {@code persistToKeyring} flag.
     *
     * @param keyId the key ID or fingerprint to fetch
     * @param keyserver the keyserver URL to fetch from
     * @param persistToKeyring {@code true} to import permanently, {@code false} for ephemeral cache
     * @return {@code true} if the key was fetched successfully
     */
    default boolean fetchKey(String keyId, String keyserver, boolean persistToKeyring) {
        return persistToKeyring ? importKey(keyId, keyserver) : fetchKeyEphemeral(keyId, keyserver);
    }
}
