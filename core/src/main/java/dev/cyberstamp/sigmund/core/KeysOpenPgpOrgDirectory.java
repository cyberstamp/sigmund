package dev.cyberstamp.sigmund.core;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

/**
 * The keys.openpgp.org directory, asked through its VKS interface.
 *
 * <p>
 * keys.openpgp.org publishes a user ID only after the address owner confirms it by email, and
 * serves a key's other data without unverified user IDs, so every address on a key it returns
 * is one it vouches for. Keys are looked up with {@code GET /vks/v1/by-fingerprint/<FPR>}, which
 * accepts the fingerprint of a primary key or any subkey in upper-case hex; the returned key is
 * checked to hold that fingerprint before any address on it is believed. The service serves
 * OpenPGP v4 keys only and rejects a v6 fingerprint, so a v6 key is not asked about: the
 * directory vouches for no address on it, which is an answer, not a lookup that failed.
 *
 * <p>
 * Lookups, including failed ones, are cached for the life of the instance: the directory
 * rate-limits fingerprint lookups, and a build asks about the same keys many times.
 */
final class KeysOpenPgpOrgDirectory implements OpenPgpDirectory {

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);
    private static final int NOT_FOUND = 404;
    private static final int OK = 200;
    private static final int V4_FINGERPRINT_LENGTH = 40;

    private final String endpoint;
    private HttpClient httpClient;
    private final Map<String, Lookup> lookups = new ConcurrentHashMap<>();
    private volatile BcKeyStore fetched;

    /**
     * Creates a client for a directory endpoint.
     *
     * @param endpoint the base URL, such as {@code https://keys.openpgp.org}
     */
    KeysOpenPgpOrgDirectory(String endpoint) {
        this.endpoint = endpoint.replaceFirst("/+$", "");
    }

    /**
     * Creates a client for the public keys.openpgp.org service.
     *
     * @return the client
     */
    static KeysOpenPgpOrgDirectory standard() {
        return new KeysOpenPgpOrgDirectory(IssuerKind.KEYS_OPENPGP_ORG);
    }

    @Override
    public String name() {
        return IssuerKind.KEYS_OPENPGP_ORG;
    }

    /**
     * Makes the directory answer from the copies a key store has fetched from it.
     *
     * <p>
     * When the store holds the directory's own copy of a key, the addresses on that copy are
     * the directory's answer, none included, and no request is made; a key it holds no such
     * copy of is asked for as before. A copy fetched from another keyserver is never the directory's answer.
     *
     * @param store the store the keyservers' copies were added to
     */
    void answerFrom(BcKeyStore store) {
        this.fetched = store;
    }

    @Override
    public boolean carried(String fingerprint, String userId) {
        List<String> served = servedUserIds(fingerprint.toUpperCase(Locale.ROOT));
        return userId != null && served != null && served.contains(userId);
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * When the key store this directory answers from holds the directory's own copy of the key,
     * the addresses on that copy are the answer, none included: a copy served without user IDs
     * says the directory vouches for no address on the key, and asking again would return the
     * same.
     */
    @Override
    public List<String> verifiedAddresses(String fingerprint) throws IOException {
        if (fingerprint.length() != V4_FINGERPRINT_LENGTH) {
            return List.of();
        }
        String key = fingerprint.toUpperCase(Locale.ROOT);
        List<String> served = servedUserIds(key);
        if (served != null) {
            return addressesIn(served);
        }
        Lookup lookup = lookups.computeIfAbsent(key, this::lookUp);
        if (lookup.failure() != null) {
            throw new IOException("keys.openpgp.org could not be asked about " + key + ": "
                    + lookup.failure());
        }
        return lookup.addresses();
    }

    /**
     * The user IDs on the copy of a key the directory served this session, or {@code null} when
     * the store holds no copy of that key from the directory.
     */
    private List<String> servedUserIds(String fingerprint) {
        BcKeyStore store = fetched;
        if (store == null) {
            return null;
        }
        for (String keyserver : store.keyserversServing(fingerprint)) {
            if (name().equals(IssuerKind.directoryServing(keyserver))) {
                return store.userIdsServedBy(fingerprint, keyserver);
            }
        }
        return null;
    }

    private Lookup lookUp(String fingerprint) {
        try {
            HttpResponse<byte[]> response = client().send(request(fingerprint),
                    HttpResponse.BodyHandlers.ofByteArray());
            if (response.statusCode() == NOT_FOUND) {
                return Lookup.found(List.of());
            }
            if (response.statusCode() != OK) {
                return Lookup.failed("HTTP " + response.statusCode());
            }
            return Lookup.found(addressesFor(parse(response.body()), fingerprint));
        } catch (IOException e) {
            return Lookup.failed(e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Lookup.failed("interrupted");
        }
    }

    /**
     * Creates the HTTP client on first use, so a build that never needs a directory lookup
     * never starts one.
     */
    private synchronized HttpClient client() {
        if (httpClient == null) {
            httpClient = HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).build();
        }
        return httpClient;
    }

    /**
     * Releases the HTTP client, if one was started.
     *
     * <p>
     * {@link HttpClient} can be closed from Java 21 on; on Java 17 it has no close method,
     * and its resources are released once the client is no longer reachable.
     */
    @Override
    public synchronized void close() {
        if (httpClient instanceof AutoCloseable closeable) {
            try {
                closeable.close();
            } catch (Exception ignored) {
                // nothing left to release
            }
        }
        httpClient = null;
    }

    private HttpRequest request(String fingerprint) {
        return HttpRequest.newBuilder()
                .uri(URI.create(endpoint + "/vks/v1/by-fingerprint/" + fingerprint))
                .timeout(REQUEST_TIMEOUT)
                .GET()
                .build();
    }

    private static PGPPublicKeyRing parse(byte[] body) throws IOException {
        try (InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(body))) {
            return new PGPPublicKeyRing(in, new BcKeyFingerprintCalculator());
        }
    }

    /**
     * Returns the addresses on a returned key, or none when the key does not hold the
     * fingerprint that was looked up: a key that does not hold it vouches for nothing about it.
     */
    static List<String> addressesFor(PGPPublicKeyRing ring, String fingerprint) {
        if (!holds(ring, fingerprint)) {
            return List.of();
        }
        List<String> userIds = new ArrayList<>();
        ring.getPublicKey().getUserIDs().forEachRemaining(userIds::add);
        return addressesIn(userIds);
    }

    private static List<String> addressesIn(List<String> userIds) {
        List<String> addresses = new ArrayList<>();
        for (String userId : userIds) {
            String address = OpenPgpCredentials.email(userId);
            if (address != null) {
                String normalized = address.toLowerCase(Locale.ROOT);
                if (!addresses.contains(normalized)) {
                    addresses.add(normalized);
                }
            }
        }
        return List.copyOf(addresses);
    }

    private static boolean holds(PGPPublicKeyRing ring, String fingerprint) {
        Iterator<PGPPublicKey> keys = ring.getPublicKeys();
        while (keys.hasNext()) {
            if (KeyRingFiles.hex(keys.next().getFingerprint()).equals(fingerprint)) {
                return true;
            }
        }
        return false;
    }

    /**
     * The result of looking one fingerprint up in the directory: the verified addresses it
     * serves for the key, or why the directory could not be asked.
     *
     * @param addresses the verified addresses, empty when the directory has none or failed
     * @param failure why the lookup failed, or {@code null} when it succeeded
     */
    private record Lookup(List<String> addresses, String failure) {

        static Lookup found(List<String> addresses) {
            return new Lookup(addresses, null);
        }

        static Lookup failed(String failure) {
            return new Lookup(List.of(), failure);
        }
    }
}
