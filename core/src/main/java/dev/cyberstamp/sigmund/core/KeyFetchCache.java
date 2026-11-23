package dev.cyberstamp.sigmund.core;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-build cache that prevents redundant keyserver requests.
 * <p>
 * Combines two mechanisms:
 * <ul>
 * <li><b>Per-keyserver circuit breaker</b> — trips when a server could not answer: a
 * connection-level failure (timeout, refused, DNS resolution) or, for an HKP server, any
 * answer but the key or HTTP 404, such as 429 or 503. Once open, all subsequent fetch
 * attempts to that keyserver are skipped for the remainder of the build. HTTP 404 does not
 * trip the circuit — the server answered, it just does not have the key.</li>
 * <li><b>Per-keyId negative cache</b> — records key IDs every server asked answered it does
 * not have, so multiple artifacts signed by the same unknown key don't each trigger a round of
 * requests.</li>
 * </ul>
 * <p>
 * Thread-safe. Intended to be created per {@code BcRunner} instance (= per build).
 * No reset or half-open logic — the JVM exits after the build.
 */
class KeyFetchCache {

    private final Set<String> trippedServers = ConcurrentHashMap.newKeySet();
    private final Set<String> notFoundKeys = ConcurrentHashMap.newKeySet();

    /**
     * Returns {@code true} if the key is worth attempting at all — i.e., it has
     * not been negatively cached from a prior failed lookup. Does not check
     * keyserver availability.
     *
     * @param keyId the key ID or fingerprint
     * @return {@code false} if the key is negatively cached
     */
    boolean shouldAttemptKey(String keyId) {
        return !notFoundKeys.contains(keyId);
    }

    /**
     * Returns {@code true} if a fetch attempt should be made for this
     * keyserver/key combination.
     *
     * @param keyserver the keyserver URL
     * @param keyId the key ID or fingerprint
     * @return {@code false} if the circuit is open for this server or the key is negatively cached
     */
    boolean shouldAttempt(String keyserver, String keyId) {
        return !trippedServers.contains(keyserver) && !notFoundKeys.contains(keyId);
    }

    /**
     * Records a successful fetch.
     * <p>
     * Currently a no-op: the circuit stays closed by default, and
     * {@link #recordKeyNotFound(String)} is only called when no server has
     * the key, so a successfully fetched key is never in the negative cache.
     */
    void recordSuccess(String keyserver, String keyId) {
    }

    /**
     * Trips the circuit breaker for a keyserver that could not answer.
     */
    void recordServerFailure(String keyserver) {
        trippedServers.add(keyserver);
    }

    /**
     * Records that no server has a key: every server asked answered that it does not.
     */
    void recordKeyNotFound(String keyId) {
        notFoundKeys.add(keyId);
    }
}
