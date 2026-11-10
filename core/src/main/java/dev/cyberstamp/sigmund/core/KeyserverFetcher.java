package dev.cyberstamp.sigmund.core;

import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.bouncycastle.openpgp.PGPPublicKeyRing;

/**
 * Fetches OpenPGP keys from HKP keyservers into a {@link BcKeyStore}.
 *
 * <p>
 * Keyservers supply key material only: the signature proves the key whoever served it, so
 * which server answered changes what can be verified, never what is accepted. The store
 * records the server that supplied each key it keeps.
 *
 * <p>
 * A per-build {@link KeyFetchCache} keeps a slow or unreachable server from slowing every
 * lookup: a connection-level failure trips that server's circuit breaker, and a key no healthy
 * server has is not asked for again.
 */
class KeyserverFetcher implements AutoCloseable {

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);
    private static final int OK = 200;

    private final BcKeyStore keyStore;
    private final List<String> keyservers;
    private final KeyFetchCache fetchCache = new KeyFetchCache();
    private final HttpClient httpClient;
    private final List<UnreadableCertificate> unreadableServed = new CopyOnWriteArrayList<>();

    /**
     * Creates a fetcher.
     *
     * @param keyStore the store fetched keys are added to
     * @param keyservers the keyserver URLs to ask, in order; must not be empty
     */
    KeyserverFetcher(BcKeyStore keyStore, List<String> keyservers) {
        if (keyservers == null || keyservers.isEmpty()) {
            throw new IllegalArgumentException("at least one keyserver is required");
        }
        this.keyStore = keyStore;
        this.keyservers = List.copyOf(keyservers);
        this.httpClient = HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).build();
    }

    /**
     * Returns the keyservers asked, in order.
     *
     * @return the keyserver URLs
     */
    List<String> keyservers() {
        return keyservers;
    }

    /**
     * Makes a key available in the store, fetching it if needed.
     *
     * <p>
     * Short-circuits if the store already holds the key with user IDs. Otherwise asks each
     * keyserver in order, skipping those whose circuit breaker has tripped, and adds what it
     * gets to the store. A copy with user IDs is preferred, so reports can show who a key
     * claims to belong to: keys.openpgp.org serves keys whose owners have not verified an
     * address without any. That preference is safe because user IDs are display text only —
     * identities come only from directories the policy names. A key no healthy server has is
     * remembered as missing for the rest of the build. A copy a server serves that cannot be
     * read is not a missing key: it is kept ({@link #unreadableCopyOf(String)}), so the key is
     * reported as served but unreadable, and the key is not asked for again.
     *
     * @param keyId the key ID or fingerprint
     * @return {@code true} if a copy of the key was obtained — one that could not be read
     *         included, so that verifying again reports it
     */
    boolean fetch(String keyId) {
        if (!fetchCache.shouldAttemptKey(keyId)) {
            return false;
        }
        if (unreadableCopyOf(keyId) != null) {
            return true;
        }
        BcKeyStore.KeyLookup existing = keyStore.findPublicKey(keyId);
        if (existing != null && hasUserIds(existing.ring())) {
            return true;
        }
        boolean fetched = existing != null;
        for (String keyserver : keyservers) {
            if (!fetchCache.shouldAttempt(keyserver, keyId)) {
                continue;
            }
            PGPPublicKeyRing ring = fetchAndStore(keyId, keyserver);
            if (ring != null) {
                fetched = true;
                if (hasUserIds(ring)) {
                    return true;
                }
            }
        }
        if (!fetched && unreadableCopyOf(keyId) != null) {
            return true;
        }
        if (!fetched) {
            fetchCache.recordKeyNotFound(keyId);
        }
        return fetched;
    }

    private PGPPublicKeyRing fetchAndStore(String keyId, String keyserver) {
        PGPPublicKeyRing keyRing = download(keyId, keyserver);
        if (keyRing == null) {
            return null;
        }
        keyStore.addFetched(keyRing, keyserver);
        fetchCache.recordSuccess(keyserver, keyId);
        return keyRing;
    }

    /**
     * Downloads a key from one keyserver without adding it to the store.
     *
     * <p>
     * Distinguishes connection-level failures, which trip the server's circuit breaker,
     * from HTTP-level errors, which mean a healthy server does not have the key. A copy the
     * server returns that cannot be read is recorded in the store as such, not taken for a key
     * the server does not have.
     *
     * @param keyId the key ID or fingerprint
     * @param keyserver the keyserver URL
     * @return the key ring, or {@code null} when the server did not supply it
     */
    PGPPublicKeyRing download(String keyId, String keyserver) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(lookupUrl(keyserver, keyId)))
                    .timeout(REQUEST_TIMEOUT)
                    .GET()
                    .build();
            HttpResponse<byte[]> response = httpClient.send(request,
                    HttpResponse.BodyHandlers.ofByteArray());
            if (response.statusCode() != OK) {
                return null;
            }
            return readServedCopy(response.body(), keyId, keyserver);
        } catch (HttpTimeoutException | ConnectException e) {
            fetchCache.recordConnectionFailure(keyserver);
            return null;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Reads the copy of a key a keyserver returned, keeping one that cannot be read rather than
     * discarding it.
     *
     * @param body what the keyserver returned
     * @param keyId the key ID or fingerprint it was asked for
     * @param keyserver the keyserver URL
     * @return the key ring, or {@code null} when the copy cannot be read
     */
    PGPPublicKeyRing readServedCopy(byte[] body, String keyId, String keyserver) {
        return KeyRingFiles.readServed(body, keyserver, keyId, unreadableServed);
    }

    /**
     * Returns the copy of a key a keyserver served this session that could not be read.
     *
     * @param fingerprint the key's fingerprint or key ID
     * @return the copy, or {@code null} when none was served unreadable
     */
    UnreadableCertificate unreadableCopyOf(String fingerprint) {
        return unreadableServed.stream()
                .filter(certificate -> certificate.holds(fingerprint))
                .findFirst()
                .orElse(null);
    }

    /**
     * Releases the HTTP client.
     *
     * <p>
     * {@link HttpClient} can be closed from Java 21 on; on Java 17 it has no close method,
     * and its resources are released once the client is no longer reachable.
     */
    @Override
    public void close() {
        if (httpClient instanceof AutoCloseable closeable) {
            try {
                closeable.close();
            } catch (Exception ignored) {
                // nothing left to release
            }
        }
    }

    /**
     * Builds the HKP lookup URL for a keyserver, mapping {@code hkps://} to HTTPS and
     * {@code hkp://} to HTTP, and treating a bare host name as HTTPS.
     */
    static String lookupUrl(String keyserver, String keyId) {
        String base;
        if (keyserver.startsWith("hkps://")) {
            base = "https://" + keyserver.substring(7);
        } else if (keyserver.startsWith("hkp://")) {
            base = "http://" + keyserver.substring(6);
        } else if (keyserver.startsWith("https://") || keyserver.startsWith("http://")) {
            base = keyserver;
        } else {
            base = "https://" + keyserver;
        }
        if (!base.endsWith("/")) {
            base += "/";
        }
        return base + "pks/lookup?op=get&options=mr&search=0x" + keyId;
    }

    private static boolean hasUserIds(PGPPublicKeyRing ring) {
        return ring.getPublicKey().getUserIDs().hasNext();
    }
}
