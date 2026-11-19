package dev.cyberstamp.sigmund.core;

import java.io.IOException;
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
import java.util.concurrent.ConcurrentHashMap;
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
 * A per-build {@link KeyFetchCache} keeps a slow or failing server from slowing every lookup:
 * a server that does not answer, or answers with anything but the key or HTTP 404, trips its
 * circuit breaker, and a key every server asked answered it does not have is not asked for
 * again. Why each server could not answer for a key is kept ({@link #unansweredServers}), so
 * that a key no server served because servers failed is reported as such, not as missing.
 */
class KeyserverFetcher implements AutoCloseable {

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration ANSWER_GRACE = Duration.ofMillis(500);
    private static final int OK = 200;
    private static final int NOT_FOUND = 404;

    /**
     * The largest copy of a key read from a keyserver, in bytes; a larger one is recorded as
     * unreadable and not parsed.
     */
    static final int MAX_COPY_BYTES = 1024 * 1024;

    private final BcKeyStore keyStore;
    private final List<String> keyservers;
    private final KeyFetchCache fetchCache;
    private final Duration requestTimeout;
    private final HttpClient httpClient;
    private final List<UnreadableCertificate> unreadableServed = new CopyOnWriteArrayList<>();
    private final Map<String, Map<String, String>> unanswered = new ConcurrentHashMap<>();
    private final Map<String, String> firstFailures = new ConcurrentHashMap<>();

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
        this(keyStore, keyservers, requestTimeout, new KeyFetchCache());
    }

    /**
     * Creates a fetcher with a given request timeout and cache.
     *
     * @param keyStore the store fetched keys are added to
     * @param keyservers the keyserver URLs to ask, in order; must not be empty
     * @param requestTimeout how long one keyserver may take to answer
     * @param fetchCache the circuit breakers and missing keys of this build
     */
    KeyserverFetcher(BcKeyStore keyStore, List<String> keyservers, Duration requestTimeout,
            KeyFetchCache fetchCache) {
        if (keyservers == null || keyservers.isEmpty()) {
            throw new IllegalArgumentException("at least one keyserver is required");
        }
        this.keyStore = keyStore;
        this.keyservers = List.copyOf(keyservers);
        this.requestTimeout = requestTimeout;
        this.fetchCache = fetchCache;
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
     * whose copy is larger than {@link #MAX_COPY_BYTES} is not read. A key every server asked
     * answered it does not have is remembered as missing for the rest of the build; one a
     * server could not answer for, or whose fetch was interrupted, is not, and the servers that
     * could not answer are kept for {@link #unansweredServers}. A copy a server serves that
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
        Map<String, String> unansweredNow = new ConcurrentHashMap<>();
        Map<String, List<PGPPublicKeyRing>> copies = readableCopies(keyId, downloadAll(keyId, unansweredNow));
        keepUnanswered(keyId, unansweredNow);
        if (!copies.isEmpty()) {
            keyStore.addFetched(keyId, copies).forEach(keyserver -> fetchCache.recordSuccess(keyserver, keyId));
        }
        boolean fetched = existing != null || !copies.isEmpty();
        if (!fetched && unreadableCopyOf(keyId) != null) {
            return true;
        }
        if (!fetched && everyServerAnswered(unansweredNow)) {
            fetchCache.recordKeyNotFound(keyId);
        }
        return fetched;
    }

    private static boolean everyServerAnswered(Map<String, String> unansweredNow) {
        return !Thread.currentThread().isInterrupted() && unansweredNow.isEmpty();
    }

    /**
     * Keeps what this fetch learned of the servers that could not answer for a key, replacing
     * what an earlier fetch of it learned, for {@link #unansweredServers}.
     */
    private void keepUnanswered(String keyId, Map<String, String> unansweredNow) {
        if (unansweredNow.isEmpty()) {
            unanswered.remove(keyId);
        } else {
            unanswered.put(keyId, Map.copyOf(unansweredNow));
        }
    }

    /**
     * Returns why keyservers could not answer for a key the last time it was fetched.
     *
     * <p>
     * A server that did not answer in time or could not be reached, one that answered with
     * anything but the key or HTTP 404, and one not asked because its circuit breaker had
     * tripped are named, each with what happened — for one not asked, what happened when it
     * first failed this build; a server that answered is not.
     *
     * @param keyId the key ID or fingerprint, as it was fetched
     * @return what happened with each server that could not answer, by keyserver URL in the
     *         order the keyservers are configured; empty when every server asked answered
     */
    Map<String, String> unansweredServers(String keyId) {
        Map<String, String> causes = unanswered.getOrDefault(keyId, Map.of());
        Map<String, String> ordered = new LinkedHashMap<>();
        keyservers.stream()
                .filter(causes::containsKey)
                .forEach(keyserver -> ordered.put(keyserver, causes.get(keyserver)));
        return ordered;
    }

    /**
     * Records that a keyserver could not answer, tripping its circuit breaker and remembering
     * the first cause for the fetches that will not ask it again.
     */
    private void recordServerFailure(String keyserver, String cause) {
        fetchCache.recordServerFailure(keyserver);
        firstFailures.putIfAbsent(keyserver, cause);
    }

    /**
     * Asks every server whose circuit breaker has not tripped, noting in {@code unansweredNow}
     * each server that could not answer, or was not asked, in this fetch.
     */
    private Map<String, byte[]> downloadAll(String keyId, Map<String, String> unansweredNow) {
        List<String> asked = keyservers.stream()
                .filter(keyserver -> fetchCache.shouldAttempt(keyserver, keyId))
                .toList();
        keyservers.stream()
                .filter(keyserver -> !asked.contains(keyserver))
                .forEach(keyserver -> unansweredNow.put(keyserver,
                        "was not asked after it earlier " + firstFailures.getOrDefault(keyserver, "failed")));
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
                bodies.put(asked.get(i), answerOf(asked.get(i), answers.get(i), unansweredNow));
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            pool.shutdownNow();
        }
        return bodies;
    }

    private byte[] answerOf(String keyserver, Future<byte[]> answer, Map<String, String> unansweredNow) {
        if (answer.isCancelled()) {
            return unanswered(keyserver, "timed out", unansweredNow);
        }
        try {
            return answer.get();
        } catch (ExecutionException e) {
            return unanswered(keyserver, causeOf(e.getCause()), unansweredNow);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    private byte[] unanswered(String keyserver, String cause, Map<String, String> unansweredNow) {
        recordServerFailure(keyserver, cause);
        unansweredNow.put(keyserver, cause);
        return null;
    }

    private static String causeOf(Throwable failure) {
        return failure instanceof IOException && failure.getMessage() != null ? failure.getMessage() : failure(failure);
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
     * @return the key ring, or {@code null} when the server did not supply a readable one or
     *         could not answer, which trips its circuit breaker
     */
    PGPPublicKeyRing downloadCopy(String keyId, String keyserver) {
        byte[] body;
        try {
            body = download(keyId, keyserver);
        } catch (IOException e) {
            recordServerFailure(keyserver, causeOf(e));
            return null;
        }
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
     * HTTP 404 means the server does not have the key. Any other answer but HTTP 200, and a
     * server that cannot be reached, does not answer in time or fails mid-answer, means the
     * server could not answer: an {@link IOException} saying what happened is thrown, which the
     * caller records against the server. At most one
     * byte more than {@link #MAX_COPY_BYTES} is read, so that a server sending more is told
     * apart from one that does not, and the rest is never read.
     *
     * @param keyId the key ID or fingerprint
     * @param keyserver the keyserver URL
     * @return the response body, cut off one byte past {@link #MAX_COPY_BYTES}, or {@code null}
     *         when the server answered HTTP 404 or the download was interrupted
     * @throws IOException if the server could not answer, its message saying what happened, such
     *         as {@code "answered 429"}, {@code "timed out"} or {@code "could not be reached"}
     */
    byte[] download(String keyId, String keyserver) throws IOException {
        HttpResponse<InputStream> response;
        try {
            response = httpClient.send(lookupRequest(keyId, keyserver), HttpResponse.BodyHandlers.ofInputStream());
        } catch (HttpTimeoutException e) {
            throw new IOException("timed out", e);
        } catch (ConnectException e) {
            throw new IOException("could not be reached", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        } catch (IOException | RuntimeException e) {
            throw new IOException(failure(e), e);
        }
        try (InputStream body = response.body()) {
            return bodyOf(response.statusCode(), body);
        }
    }

    private HttpRequest lookupRequest(String keyId, String keyserver) {
        return HttpRequest.newBuilder()
                .uri(URI.create(lookupUrl(keyserver, keyId)))
                .timeout(requestTimeout)
                .GET()
                .build();
    }

    private static byte[] bodyOf(int status, InputStream body) throws IOException {
        if (status == NOT_FOUND) {
            return null;
        }
        if (status != OK) {
            throw new IOException("answered " + status);
        }
        try {
            return body.readNBytes(MAX_COPY_BYTES + 1);
        } catch (IOException e) {
            throw new IOException(failure(e), e);
        }
    }

    private static String failure(Throwable e) {
        return "failed (" + (e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName()) + ")";
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
