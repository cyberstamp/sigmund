package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class KeyserverFetcherTest {

    @TempDir
    Path tempDir;

    private BcKeyStore createStore() {
        return new BcKeyStore(null, tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
    }

    @Nested
    class CanFetchKeys {

        @Test
        void trueWhenKeysAreFetchedFromKeyservers(@TempDir Path dir) {
            try (BcRunner runner = verifyOnly(dir, "true", "hkps://keys.openpgp.org")) {
                assertThat(runner.canFetchKeys()).isTrue();
            }
        }

        @Test
        void falseWhenResolveDisabled(@TempDir Path dir) {
            try (BcRunner runner = verifyOnly(dir, "false", "hkps://keys.openpgp.org")) {
                assertThat(runner.canFetchKeys()).isFalse();
            }
        }

        @Test
        void falseWhenNoKeyservers(@TempDir Path dir) {
            try (BcRunner runner = verifyOnly(dir, "true", "")) {
                assertThat(runner.canFetchKeys()).isFalse();
            }
        }

        @Test
        void aFetcherNeedsAKeyserver() {
            assertThatThrownBy(() -> {
                try (KeyserverFetcher fetcher = new KeyserverFetcher(createStore(), List.of())) {
                    // closed even if construction were to succeed
                }
            }).isInstanceOf(IllegalArgumentException.class);
        }

        private BcRunner verifyOnly(Path dir, String resolveSigners, String keyservers) {
            return (BcRunner) new BcToolFactory().createVerifyOnly(Map.of(
                    "cert-d-home", dir.resolve("cert-d").toString(),
                    "resolve-signers", resolveSigners,
                    "keyservers", keyservers));
        }
    }

    @Nested
    class EphemeralCacheWithUserIds {

        @Test
        void keyWithoutUidsReplacedByKeyWithUids() {
            BcKeyStore store = createStore();
            try (BcRunner generator = new BcRunner(store, null, null)) {

                String fp = generator.generateKey("Test User <test@example.com>", "ed25519", null);
                PGPPublicKeyRing fullKey = store.findPublicKey(fp).ring();
                assertThat(fullKey).isNotNull();
                assertThat(fullKey.getPublicKey().getUserIDs().hasNext()).isTrue();

                PGPPublicKeyRing strippedKey = stripUserIds(fullKey);
                assertThat(strippedKey.getPublicKey().getUserIDs().hasNext()).isFalse();

                BcKeyStore verifierStore = createStore();
                verifierStore.addFetched(strippedKey, "hkps://keys.example.org");

                PGPPublicKeyRing cached = verifierStore.findPublicKey(fp).ring();
                assertThat(cached).isNotNull();
                assertThat(cached.getPublicKey().getUserIDs().hasNext())
                        .as("Cached key should have no UIDs initially").isFalse();

                verifierStore.addFetched(fullKey, "hkps://keys.example.org");
                cached = verifierStore.findPublicKey(fp).ring();
                assertThat(cached).isNotNull();
                assertThat(cached.getPublicKey().getUserIDs().hasNext())
                        .as("Cached key should now have UIDs after replacement").isTrue();
            }
        }

        @Test
        void findPublicKeyReturnsKeyWithoutUids() throws Exception {
            BcKeyStore store = createStore();
            try (BcRunner generator = new BcRunner(store, null, null)) {

                String fp = generator.generateKey("Test <test@example.com>", "ed25519", null);
                PGPPublicKeyRing fullKey = store.findPublicKey(fp).ring();
                PGPPublicKeyRing strippedKey = stripUserIds(fullKey);

                BcKeyStore verifierStore = createStore();
                verifierStore.addFetched(strippedKey, "hkps://keys.example.org");

                PGPPublicKeyRing found = verifierStore.findPublicKey(fp).ring();
                assertThat(found).as("Key without UIDs should still be findable").isNotNull();
            }
        }
    }

    @Nested
    class FetchKeyLoop {

        @Test
        void continuesToAKeyserverWithUserIdsForDisplay() throws Exception {
            BcKeyStore genStore = createStore();
            try (BcRunner generator = new BcRunner(genStore, null, null)) {
                String fp = generator.generateKey("Test User <test@example.com>", "ed25519", null);
                PGPPublicKeyRing fullKey = genStore.findPublicKey(fp).ring();
                PGPPublicKeyRing strippedKey = stripUserIds(fullKey);

                BcKeyStore fetchStore = new BcKeyStore(null,
                        tempDir.resolve("fetch-cd"), tempDir.resolve("fetch-bp"));
                Map<String, PGPPublicKeyRing> responses = new HashMap<>();
                responses.put("hkps://server1", strippedKey);
                responses.put("hkps://server2", fullKey);

                try (StubFetcher fetcher = new StubFetcher(fetchStore, responses,
                        List.of("hkps://server1", "hkps://server2"))) {

                    assertThat(fetcher.fetch(fp)).isTrue();
                    assertThat(fetcher.queriedServers).isEqualTo(List.of("hkps://server1", "hkps://server2"));
                    assertThat(fetchStore.findPublicKey(fp).source()).isEqualTo(TrustRootRef.keyserver("hkps://server2"));
                }
            }
        }

        @Test
        void stopsAtTheFirstKeyserverWithUserIds() throws Exception {
            BcKeyStore genStore = createStore();
            try (BcRunner generator = new BcRunner(genStore, null, null)) {
                String fp = generator.generateKey("Test User <test@example.com>", "ed25519", null);
                PGPPublicKeyRing fullKey = genStore.findPublicKey(fp).ring();

                BcKeyStore fetchStore = new BcKeyStore(null,
                        tempDir.resolve("fetch-cd"), tempDir.resolve("fetch-bp"));
                try (StubFetcher fetcher = new StubFetcher(fetchStore,
                        Map.of("hkps://server1", fullKey, "hkps://server2", fullKey),
                        List.of("hkps://server1", "hkps://server2"))) {

                    assertThat(fetcher.fetch(fp)).isTrue();
                    assertThat(fetcher.queriedServers).isEqualTo(List.of("hkps://server1"));
                }
            }
        }

        @Test
        void aKeyWithoutUserIdsStillCountsAsFetched() throws Exception {
            BcKeyStore genStore = createStore();
            try (BcRunner generator = new BcRunner(genStore, null, null)) {
                String fp = generator.generateKey("Test User <test@example.com>", "ed25519", null);
                PGPPublicKeyRing strippedKey = stripUserIds(genStore.findPublicKey(fp).ring());

                BcKeyStore fetchStore = new BcKeyStore(null,
                        tempDir.resolve("fetch-cd"), tempDir.resolve("fetch-bp"));
                try (StubFetcher fetcher = new StubFetcher(fetchStore,
                        Map.of("hkps://server1", strippedKey),
                        List.of("hkps://server1", "hkps://server2"))) {

                    assertThat(fetcher.fetch(fp)).isTrue();
                }
            }
        }

        @Test
        void recordsWhichKeyserverSuppliedTheKey() throws Exception {
            BcKeyStore genStore = createStore();
            try (BcRunner generator = new BcRunner(genStore, null, null)) {
                String fp = generator.generateKey("Test User <test@example.com>", "ed25519", null);
                PGPPublicKeyRing fullKey = genStore.findPublicKey(fp).ring();

                BcKeyStore fetchStore = new BcKeyStore(null,
                        tempDir.resolve("fetch-cd"), tempDir.resolve("fetch-bp"));
                Map<String, PGPPublicKeyRing> responses = new HashMap<>();
                responses.put("hkps://server2", fullKey);

                try (StubFetcher fetcher = new StubFetcher(fetchStore, responses,
                        List.of("hkps://server1", "hkps://server2"))) {

                    assertThat(fetcher.fetch(fp)).isTrue();
                    assertThat(fetchStore.findPublicKey(fp).source()).isEqualTo(TrustRootRef.keyserver("hkps://server2"));
                }
            }
        }

        @Test
        void returnsFalseWhenNoKeyserverHasKey() throws Exception {
            BcKeyStore fetchStore = new BcKeyStore(null,
                    tempDir.resolve("fetch-cd"), tempDir.resolve("fetch-bp"));

            try (StubFetcher fetcher = new StubFetcher(fetchStore, Map.of(),
                    List.of("hkps://server1", "hkps://server2"))) {

                assertThat(fetcher.fetch("AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD")).isFalse();
                assertThat(fetcher.queriedServers).isEqualTo(List.of("hkps://server1", "hkps://server2"));
            }
        }

        @Test
        void skipsKeyserversWhenTheKeyIsAlreadyHeldWithUserIds() throws Exception {
            BcKeyStore genStore = createStore();
            try (BcRunner generator = new BcRunner(genStore, null, null)) {
                String fp = generator.generateKey("Test User <test@example.com>", "ed25519", null);

                BcKeyStore fetchStore = new BcKeyStore(null,
                        tempDir.resolve("fetch-cd"), tempDir.resolve("fetch-bp"));
                fetchStore.addFetched(genStore.findPublicKey(fp).ring(), "hkps://keys.example.org");

                try (StubFetcher fetcher = new StubFetcher(fetchStore, Map.of(),
                        List.of("hkps://server1"))) {

                    assertThat(fetcher.fetch(fp)).isTrue();
                    assertThat(fetcher.queriedServers).isEmpty();
                }
            }
        }
    }

    @Nested
    class ACopyThatCannotBeRead {

        private static final String FP = "AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD";

        @Test
        void isKeptAsServedButUnreadableRatherThanMissing() {
            try (JunkServingFetcher fetcher = new JunkServingFetcher(createStore())) {

                assertThat(fetcher.fetch(FP)).as("verifying again reports the copy").isTrue();

                UnreadableCertificate copy = fetcher.unreadableCopyOf(FP);
                assertThat(copy.source()).isEqualTo(TrustRootRef.keyserver("hkps://server1"));
                assertThat(copy.cause()).isEqualTo(UnreadableCertificate.Cause.DAMAGED);
            }
        }

        @Test
        void isNotAskedForAgain() {
            try (JunkServingFetcher fetcher = new JunkServingFetcher(createStore())) {
                fetcher.fetch(FP);
                fetcher.fetch(FP);

                assertThat(fetcher.downloads).isEqualTo(1);
            }
        }

        @Test
        void isReportedByBcAsTheCopyFromTheKeyserver(@TempDir Path dir) throws Exception {
            BcKeyStore store = createStore();
            JunkServingFetcher fetcher = new JunkServingFetcher(store);
            try (BcRunner runner = new BcRunner(store, null, null, null, null, fetcher)) {
                fetcher.fetch(FP);
                Path artifact = Files.writeString(dir.resolve("a.txt"), "a");
                VerifyResult result = runner.verify(artifact, new OpenPgpClaim("armored", 4, FP, 22, null));

                assertThat(result.isIndeterminate(IndeterminateReason.KEY_UNAVAILABLE)).isTrue();
                assertThat(result.reasonDetail()).startsWith("the copy from hkps://server1 cannot be read: ");
            }
        }
    }

    /** A keyserver returning something that is not a certificate. */
    private static class JunkServingFetcher extends KeyserverFetcher {
        int downloads;

        JunkServingFetcher(BcKeyStore store) {
            super(store, List.of("hkps://server1"));
        }

        @Override
        PGPPublicKeyRing download(String keyId, String keyserver) {
            downloads++;
            return readServedCopy("<html>not a key</html>".getBytes(StandardCharsets.US_ASCII), keyId, keyserver);
        }
    }

    private static class StubFetcher extends KeyserverFetcher {
        private final Map<String, PGPPublicKeyRing> responses;
        final List<String> queriedServers = new ArrayList<>();

        StubFetcher(BcKeyStore store, Map<String, PGPPublicKeyRing> responses,
                List<String> keyservers) {
            super(store, keyservers);
            this.responses = responses;
        }

        @Override
        PGPPublicKeyRing download(String keyId, String keyserver) {
            queriedServers.add(keyserver);
            return responses.get(keyserver);
        }
    }

    private static PGPPublicKeyRing stripUserIds(PGPPublicKeyRing ring) {
        List<PGPPublicKey> keys = new ArrayList<>();
        Iterator<PGPPublicKey> it = ring.getPublicKeys();
        boolean first = true;
        while (it.hasNext()) {
            PGPPublicKey key = it.next();
            if (first) {
                first = false;
                Iterator<String> uids = key.getUserIDs();
                while (uids.hasNext()) {
                    key = PGPPublicKey.removeCertification(key, uids.next());
                }
            }
            keys.add(key);
        }
        return new PGPPublicKeyRing(keys);
    }
}
