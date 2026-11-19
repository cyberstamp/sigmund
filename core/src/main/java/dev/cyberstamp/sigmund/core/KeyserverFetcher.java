package dev.cyberstamp.sigmund.core;

import java.io.InputStream;
import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.bouncycastle.openpgp.PGPPublicKeyRing;

/**
 * Fetches OpenPGP keys from HKP keyservers into a {@link BcKeyStore}.
 *
 * <p>
 * Keyservers supply key material only: the signature proves the key whoever served it, so
 * which server answered changes what can be verified, never what is accepted. Every healthy
 * keyserver is asked, concurrently, and the store joins what they serve into one certificate
 * while recording which servers supplied it and keeping each server's copy.
 *
 * <p>
 * A per-build {@link KeyFetchCache} keeps a slow or unreachable server from slowing every
 * lookup: a connection-level failure trips that server's circuit breaker, and a key no healthy
 * server has is not asked for again.
 */
class KeyserverFetcher implements AutoCloseable {

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration ANSWER_GRACE = Duration.ofMillis(500);
    private static final int OK = 200;

    /**
     * The largest copy of a key read from a keyserver, in bytes; a larger one is recorded as
     * unreadable and not parsed.
     */
    static final int MAX_COPY_BYTES = 1024 * 1024;

    private final BcKeyStore keyStore;
    private final List<String> keyservers;
    private final KeyFetchCache fetchCache = new KeyFetchCache();
    private final Duration requestTimeout;
    private final HttpClient httpClient;
    private final List<UnreadableCertificate> unreadableServed = new CopyOnWriteArrayList<>();

    /**
     * Creates a fetcher.
     *
     * @param keyStore the store fetched keys are added to
     * @param keyservers the keyserver URLs to ask, in order; must not be empty
     */
    KeyserverFetcher(BcKeyStore keyStore, List<String> keyservers) {
        this(keyStore, keyservers, REQUEST_TIMEOUT);
    }

    /**
     * Creates a fetcher with a given request timeout.
     *
     * @param keyStore the store fetched keys are added to
     * @param keyservers the keyserver URLs to ask, in order; must not be empty
     * @param requestTimeout how long one keyserver may take to answer
     */
    KeyserverFetcher(BcKeyStore keyStore, List<String> keyservers, Duration requestTimeout) {
        if (keyservers == null || keyservers.isEmpty()) {
            throw new IllegalArgumentException("at least one keyserver is required");
        }
        this.keyStore = keyStore;
        this.keyservers = List.copyOf(keyservers);
        this.requestTimeout = requestTimeout;
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
     * Short-circuits if the store already holds the key with user IDs. Otherwise asks every
     * keyserver whose circuit breaker has not tripped, all at once, and waits for the answers
     * for no longer than a request may take. The readable copies are joined into one
     * certificate by the store, which also keeps each server's copy: what one server withholds
     * — user IDs, which keys.openpgp.org omits until an owner verifies an address, or a
     * revocation — another may serve, and the joined certificate holds all of it. A server
     * whose copy is larger than {@link #MAX_COPY_BYTES} is not read. A key no healthy server
     * has is remembered as missing for the rest of the build. A copy a server serves that
     * cannot be read is not a missing key: it is kept ({@link #unreadableCopyOf(String)}), so
     * the key is reported as served but unreadable when no other server served a readable one,
     * and the key is not asked for again.
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
        Map<String, List<PGPPublicKeyRing>> copies = readableCopies(keyId, downloadAll(keyId));
        if (!copies.isEmpty()) {
            keyStore.addFetched(keyId, copies);
            copies.keySet().forEach(keyserver -> fetchCache.recordSuccess(keyserver, keyId));
        }
        boolean fetched = existing != null || !copies.isEmpty();
        if (!fetched && unreadableCopyOf(keyId) != null) {
            return true;
        }
        if (!fetched) {
            fetchCache.recordKeyNotFound(keyId);
        }
        return fetched;
    }

    private Map<String, byte[]> downloadAll(String keyId) {
        List<String> asked = keyservers.stream()
                .filter(keyserver -> fetchCache.shouldAttempt(keyserver, keyId))
                .toList();
        Map<String, byte[]> bodies = new LinkedHashMap<>();
        if (asked.isEmpty()) {
            return bodies;
        }
        ExecutorService pool = Executors.newFixedThreadPool(asked.size());
        try {
            List<Future<byte[]>> answers = pool.invokeAll(
                    asked.stream().<Callable<byte[]>> map(keyserver -> () -> download(keyId, keyserver)).toList(),
                    requestTimeout.plus(ANSWER_GRACE).toMillis(), TimeUnit.MILLISECONDS);
            for (int i = 0; i < asked.size(); i++) {
                bodies.put(asked.get(i), answerOf(asked.get(i), answers.get(i)));
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            pool.shutdownNow();
        }
        return bodies;
    }

    private byte[] answerOf(String keyserver, Future<byte[]> answer) {
        if (answer.isCancelled()) {
            fetchCache.recordConnectionFailure(keyserver);
            return null;
        }
        try {
            return answer.get();
        } catch (ExecutionException e) {
            return null;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    /**
     * Downloads and reads one keyserver's copy of a key without adding it to the store.
     *
     * <p>
     * A copy that cannot be read is recorded as such, not taken for a key the server does not
     * have. Of several certificates served, the one the key belongs to is returned, chosen as
     * the store chooses among every server's ({@link BcKeyStore#certificateAmong}): a
     * certificate of another primary key served before it is never shown in its place.
     *
     * @param keyId the key ID or fingerprint
     * @param keyserver the keyserver URL
     * @return the key ring, or {@code null} when the server did not supply a readable one
     */
    PGPPublicKeyRing downloadCopy(String keyId, String keyserver) {
        byte[] body = download(keyId, keyserver);
        return body == null ? null : BcKeyStore.certificateAmong(keyId, readCopy(body, keyId, keyserver));
    }

    private Map<String, List<PGPPublicKeyRing>> readableCopies(String keyId, Map<String, byte[]> bodies) {
        Map<String, List<PGPPublicKeyRing>> copies = new LinkedHashMap<>();
        bodies.forEach((keyserver, body) -> {
            List<PGPPublicKeyRing> served = body == null ? List.of()
                    : holdingTheKey(readCopy(body, keyId, keyserver), keyId);
            if (!served.isEmpty()) {
                copies.put(keyserver, served);
            }
        });
        return copies;
    }

    private static List<PGPPublicKeyRing> holdingTheKey(List<PGPPublicKeyRing> served, String keyId) {
        return served.stream().filter(copy -> BcKeyStore.matchesFingerprint(copy, keyId)).toList();
    }

    private List<PGPPublicKeyRing> readCopy(byte[] body, String keyId, String keyserver) {
        if (body.length > MAX_COPY_BYTES) {
            unreadableServed.add(new UnreadableCertificate(TrustRootRef.keyserver(keyserver), null,
                    Set.of(keyId), UnreadableCertificate.Cause.DAMAGED,
                    "larger than " + MAX_COPY_BYTES + " bytes, not read"));
            return List.of();
        }
        return readServedCopy(body, keyId, keyserver);
    }

    /**
     * Downloads what one keyserver serves for a key, without reading or storing it.
     *
     * <p>
     * Distinguishes connection-level failures, which trip the server's circuit breaker,
     * from HTTP-level errors, which mean a healthy server does not have the key. At most one
     * byte more than {@link #MAX_COPY_BYTES} is read, so that a server sending more is told
     * apart from one that does not, and the rest is never read.
     *
     * @param keyId the key ID or fingerprint
     * @param keyserver the keyserver URL
     * @return the response body, cut off one byte past {@link #MAX_COPY_BYTES}, or {@code null}
     *         when the server did not answer with HTTP 200
     */
    byte[] download(String keyId, String keyserver) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(lookupUrl(keyserver, keyId)))
                    .timeout(requestTimeout)
                    .GET()
                    .build();
            HttpResponse<InputStream> response = httpClient.send(request,
                    HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream body = response.body()) {
                return response.statusCode() == OK ? body.readNBytes(MAX_COPY_BYTES + 1) : null;
            }
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
     * Reads the certificates a keyserver returned for a key, keeping one that cannot be read
     * rather than discarding it.
     *
     * @param body what the keyserver returned
     * @param keyId the key ID or fingerprint it was asked for
     * @param keyserver the keyserver URL
     * @return the certificates read, in the order served; empty when none can be read
     */
    List<PGPPublicKeyRing> readServedCopy(byte[] body, String keyId, String keyserver) {
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
