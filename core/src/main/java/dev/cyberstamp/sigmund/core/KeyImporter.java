package dev.cyberstamp.sigmund.core;

/**
 * Capability interface for tools that can fetch public keys from keyservers.
 * <p>
 * Each tool that implements this interface owns its key fetching configuration:
 * keyservers, persistence mode ({@code importToKeyring}), and whether fetching
 * is enabled at all ({@code resolveSigners}). The caller simply asks the tool
 * to fetch a key by ID — the tool handles keyserver iteration, caching, circuit
 * breaking, and storage internally.
 *
 * @see KeyFetchCache
 */
public interface KeyImporter {

    /**
     * Attempts to fetch a public key from the configured keyservers.
     * <p>
     * Returns {@code true} if a copy of the key was fetched, so that verifying again may give a
     * different answer: usually the key is now available, but a copy the tool cannot read counts
     * too, so that verifying again reports why the key cannot be used rather than that it is
     * missing. Returns {@code false} if fetching is disabled
     * ({@code resolveSigners=false}), the tool cannot fetch in its current
     * mode (e.g., GPG with {@code importToKeyring=false}), the key was not
     * found, or a connection failure occurred.
     *
     * @param keyId the key ID or fingerprint to fetch
     * @return {@code true} if a copy of the key was fetched
     */
    boolean fetchKey(String keyId);

    /**
     * Returns {@code true} if this tool is capable of fetching keys in its
     * current configuration.
     * <p>
     * A tool returns {@code false} when fetching is structurally impossible —
     * e.g., {@code resolveSigners} is disabled, or the tool requires
     * {@code importToKeyring=true} but it is {@code false}.
     *
     * @return {@code true} if key fetching is available
     */
    boolean canFetchKeys();
}
