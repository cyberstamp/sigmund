package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.api.bc.BcOpenPGPApi;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class KeysOpenPgpOrgDirectoryTest {

    private HttpServer server;
    private final Map<String, byte[]> keys = new ConcurrentHashMap<>();
    private final Map<String, Integer> statuses = new ConcurrentHashMap<>();
    private final List<String> requests = new ArrayList<>();
    private KeysOpenPgpOrgDirectory directory;

    @TempDir
    Path tempDir;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/vks/v1/by-fingerprint/", exchange -> {
            String fingerprint = exchange.getRequestURI().getPath()
                    .substring("/vks/v1/by-fingerprint/".length());
            synchronized (requests) {
                requests.add(fingerprint);
            }
            byte[] body = keys.get(fingerprint);
            int status = statuses.getOrDefault(fingerprint, body != null ? 200 : 404);
            exchange.sendResponseHeaders(status, body != null && status == 200 ? body.length : -1);
            if (body != null && status == 200) {
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(body);
                }
            }
            exchange.close();
        });
        server.start();
        directory = new KeysOpenPgpOrgDirectory("http://127.0.0.1:" + server.getAddress().getPort());
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void servesTheVerifiedAddressOfAKey() throws Exception {
        PGPPublicKeyRing ring = generate("Release Manager <Release@Example.org>");
        String fingerprint = primaryFingerprint(ring);
        keys.put(fingerprint, ring.getEncoded());

        assertThat(directory.verifiedAddresses(fingerprint)).containsExactly("release@example.org");
    }

    @Test
    void findsTheKeyBySubkeyFingerprint() throws Exception {
        PGPPublicKeyRing ring = generate("Release Manager <release@example.org>");
        String subkey = lastFingerprint(ring);
        keys.put(subkey, ring.getEncoded());

        assertThat(directory.verifiedAddresses(subkey.toLowerCase()))
                .containsExactly("release@example.org");
        assertThat(requests).containsExactly(subkey);
    }

    @Test
    void anUnknownKeyHasNoAddresses() throws Exception {
        assertThat(directory.verifiedAddresses("4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12")).isEmpty();
    }

    /**
     * keys.openpgp.org serves v4 keys only, and answers a 64-hex fingerprint with HTTP 400. It
     * vouches for no address on a v6 key, which is an answer rather than a failure: a failure
     * would leave the claim key-unavailable, as if asking again could help.
     */
    @Test
    void aV6KeyHasNoAddressesAndIsNotAskedAbout() throws Exception {
        String v6 = "D62AAB339E45E5EA2FD036872B01D46A517A299115599CCADD4C50A956F8E707";
        statuses.put(v6, 400);

        assertThat(directory.verifiedAddresses(v6)).isEmpty();
        assertThat(requests).isEmpty();
    }

    @Test
    void anAnswerAboutAnotherKeyVouchesForNothing() throws Exception {
        PGPPublicKeyRing ring = generate("Someone Else <else@example.org>");
        String asked = "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12";
        keys.put(asked, ring.getEncoded());

        assertThat(directory.verifiedAddresses(asked)).isEmpty();
    }

    @Test
    void aServerErrorIsReportedAndNotRetriedWithinTheSession() {
        String fingerprint = "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12";
        statuses.put(fingerprint, 429);

        assertThatThrownBy(() -> directory.verifiedAddresses(fingerprint))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("HTTP 429");
        assertThatThrownBy(() -> directory.verifiedAddresses(fingerprint))
                .isInstanceOf(IOException.class);
        assertThat(requests).hasSize(1);
    }

    @Test
    void answersAreCachedForTheSession() throws Exception {
        PGPPublicKeyRing ring = generate("Release Manager <release@example.org>");
        String fingerprint = primaryFingerprint(ring);
        keys.put(fingerprint, ring.getEncoded());

        directory.verifiedAddresses(fingerprint);
        directory.verifiedAddresses(fingerprint);

        assertThat(requests).hasSize(1);
    }

    @Test
    void closingReleasesTheClientAndALaterLookupStartsAnother() throws Exception {
        directory.close();
        PGPPublicKeyRing ring = generate("Release Manager <release@example.org>");
        String fingerprint = primaryFingerprint(ring);
        keys.put(fingerprint, ring.getEncoded());

        assertThat(directory.verifiedAddresses(fingerprint)).containsExactly("release@example.org");

        directory.close();
        directory.close();
    }

    @Test
    void isNamedAsTheIssuerPolicyLists() {
        assertThat(KeysOpenPgpOrgDirectory.standard().name()).isEqualTo(IssuerKind.KEYS_OPENPGP_ORG);
    }

    @Test
    void answersFromAFetchedCopyWithoutARequest() throws Exception {
        PGPPublicKeyRing ring = generate("Release Manager <Release@Example.org>");
        BcKeyStore store = storeServing("hkps://keys.openpgp.org", ring);
        directory.answerFrom(store);

        assertThat(directory.verifiedAddresses(primaryFingerprint(ring)))
                .containsExactly("release@example.org");
        assertThat(requests).isEmpty();
    }

    /**
     * A copy the directory served without user IDs is its answer: it vouches for no address on
     * the key, and is not asked again.
     */
    @Test
    void aFetchedCopyWithoutUserIdsIsAnAnswerWithoutARequest() throws Exception {
        PGPPublicKeyRing ring = generate("Release Manager <release@example.org>");
        String fingerprint = primaryFingerprint(ring);
        keys.put(fingerprint, ring.getEncoded());
        directory.answerFrom(storeServing("hkps://keys.openpgp.org", withoutUserIds(ring)));

        assertThat(directory.verifiedAddresses(fingerprint)).isEmpty();
        assertThat(requests).isEmpty();
    }

    @Test
    void asksWhenNoCopyWasFetched() throws Exception {
        PGPPublicKeyRing ring = generate("Release Manager <release@example.org>");
        String fingerprint = primaryFingerprint(ring);
        keys.put(fingerprint, ring.getEncoded());
        directory.answerFrom(storeServing("hkps://keyserver.ubuntu.com", ring));

        assertThat(directory.verifiedAddresses(fingerprint)).containsExactly("release@example.org");
        assertThat(requests).containsExactly(fingerprint);
    }

    @Test
    void aCopyThatDoesNotHoldTheFingerprintVouchesForNothing() throws Exception {
        PGPPublicKeyRing served = generate("Served <served@example.org>");
        PGPPublicKeyRing other = generate("Other <other@example.org>");
        directory.answerFrom(storeServing("hkps://keys.openpgp.org", served));

        assertThat(directory.verifiedAddresses(primaryFingerprint(other))).isEmpty();
        assertThat(directory.carried(primaryFingerprint(other), "Served <served@example.org>")).isFalse();
    }

    @Test
    void carriedNeverMakesARequest() throws Exception {
        PGPPublicKeyRing ring = generate("Release Manager <release@example.org>");
        String fingerprint = primaryFingerprint(ring);
        keys.put(fingerprint, ring.getEncoded());

        assertThat(directory.carried(fingerprint, "Release Manager <release@example.org>")).isFalse();

        directory.answerFrom(storeServing("hkps://keys.openpgp.org", ring));
        assertThat(directory.carried(fingerprint, "Release Manager <release@example.org>")).isTrue();
        assertThat(directory.carried(fingerprint, "Impostor <release@example.org>")).isFalse();
        assertThat(directory.carried(fingerprint, null)).isFalse();
        assertThat(requests).isEmpty();
    }

    @Test
    void aSubkeyOnlyAnotherKeyserverServedIsAskedOfVksAndNotCarried() throws Exception {
        PGPPublicKeyRing full = generate("Release Manager <release@example.org>");
        PGPPublicKeyRing primaryOnly = new PGPPublicKeyRing(List.of(full.getPublicKey()));
        String subkey = lastFingerprint(full);
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        Map<String, PGPPublicKeyRing> copies = new LinkedHashMap<>();
        copies.put("hkps://keys.openpgp.org", primaryOnly);
        copies.put("hkps://keyserver.ubuntu.com", full);
        BcTestKeys.addFetched(store, copies);
        directory.answerFrom(store);

        assertThat(directory.verifiedAddresses(subkey)).isEmpty();
        assertThat(requests).containsExactly(subkey);
        assertThat(directory.carried(subkey, "Release Manager <release@example.org>")).isFalse();
    }

    private BcKeyStore storeServing(String keyserver, PGPPublicKeyRing ring) {
        BcKeyStore store = new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        BcTestKeys.addFetched(store, Map.of(keyserver, ring));
        return store;
    }

    /** The certificate as keys.openpgp.org serves it before its owner verified an address. */
    private static PGPPublicKeyRing withoutUserIds(PGPPublicKeyRing ring) {
        List<PGPPublicKey> keys = new ArrayList<>();
        ring.getPublicKeys().forEachRemaining(keys::add);
        PGPPublicKey primary = keys.get(0);
        Iterator<String> userIds = primary.getUserIDs();
        while (userIds.hasNext()) {
            primary = PGPPublicKey.removeCertification(primary, userIds.next());
        }
        keys.set(0, primary);
        return new PGPPublicKeyRing(keys);
    }

    /** A v4 key, the only version keys.openpgp.org serves. */
    private static PGPPublicKeyRing generate(String userId) throws Exception {
        return new BcOpenPGPApi().generateKey(PublicKeyPacket.VERSION_4)
                .ed25519x25519Key(userId)
                .addSigningSubkey()
                .build()
                .toCertificate()
                .getPGPPublicKeyRing();
    }

    private static String primaryFingerprint(PGPPublicKeyRing ring) {
        return HexFormat.of().withUpperCase().formatHex(ring.getPublicKey().getFingerprint());
    }

    private static String lastFingerprint(PGPPublicKeyRing ring) {
        PGPPublicKey last = null;
        Iterator<PGPPublicKey> it = ring.getPublicKeys();
        while (it.hasNext()) {
            last = it.next();
        }
        return HexFormat.of().withUpperCase().formatHex(last.getFingerprint());
    }
}
