package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
            assertThat(verifyOnly(dir, "true", "hkps://keys.openpgp.org").canFetchKeys()).isTrue();
        }

        @Test
        void falseWhenResolveDisabled(@TempDir Path dir) {
            assertThat(verifyOnly(dir, "false", "hkps://keys.openpgp.org").canFetchKeys()).isFalse();
        }

        @Test
        void falseWhenNoKeyservers(@TempDir Path dir) {
            assertThat(verifyOnly(dir, "true", "").canFetchKeys()).isFalse();
        }

        @Test
        void aFetcherNeedsAKeyserver() {
            assertThatThrownBy(() -> new KeyserverFetcher(createStore(), List.of()))
                    .isInstanceOf(IllegalArgumentException.class);
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
        void keyWithoutUidsReplacedByKeyWithUids() throws Exception {
            BcKeyStore store = createStore();
            BcRunner generator = new BcRunner(store, null, null);

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

        @Test
        void findPublicKeyReturnsKeyWithoutUids() throws Exception {
            BcKeyStore store = createStore();
            BcRunner generator = new BcRunner(store, null, null);

            String fp = generator.generateKey("Test <test@example.com>", "ed25519", null);
            PGPPublicKeyRing fullKey = store.findPublicKey(fp).ring();
            PGPPublicKeyRing strippedKey = stripUserIds(fullKey);

            BcKeyStore verifierStore = createStore();
            verifierStore.addFetched(strippedKey, "hkps://keys.example.org");

            PGPPublicKeyRing found = verifierStore.findPublicKey(fp).ring();
            assertThat(found).as("Key without UIDs should still be findable").isNotNull();
        }
    }

    @Nested
    class FetchKeyLoop {

        @Test
        void continuesToAKeyserverWithUserIdsForDisplay() throws Exception {
            BcKeyStore genStore = createStore();
            BcRunner generator = new BcRunner(genStore, null, null);
            String fp = generator.generateKey("Test User <test@example.com>", "ed25519", null);
            PGPPublicKeyRing fullKey = genStore.findPublicKey(fp).ring();
            PGPPublicKeyRing strippedKey = stripUserIds(fullKey);

            BcKeyStore fetchStore = new BcKeyStore(null,
                    tempDir.resolve("fetch-cd"), tempDir.resolve("fetch-bp"));
            Map<String, PGPPublicKeyRing> responses = new HashMap<>();
            responses.put("hkps://server1", strippedKey);
            responses.put("hkps://server2", fullKey);

            StubFetcher fetcher = new StubFetcher(fetchStore, responses,
                    List.of("hkps://server1", "hkps://server2"));

            assertThat(fetcher.fetch(fp)).isTrue();
            assertThat(fetcher.queriedServers).isEqualTo(List.of("hkps://server1", "hkps://server2"));
            assertThat(fetchStore.findPublicKey(fp).source()).isEqualTo(TrustRootRef.keyserver("hkps://server2"));
        }

        @Test
        void stopsAtTheFirstKeyserverWithUserIds() throws Exception {
            BcKeyStore genStore = createStore();
            BcRunner generator = new BcRunner(genStore, null, null);
            String fp = generator.generateKey("Test User <test@example.com>", "ed25519", null);
            PGPPublicKeyRing fullKey = genStore.findPublicKey(fp).ring();

            BcKeyStore fetchStore = new BcKeyStore(null,
                    tempDir.resolve("fetch-cd"), tempDir.resolve("fetch-bp"));
            StubFetcher fetcher = new StubFetcher(fetchStore,
                    Map.of("hkps://server1", fullKey, "hkps://server2", fullKey),
                    List.of("hkps://server1", "hkps://server2"));

            assertThat(fetcher.fetch(fp)).isTrue();
            assertThat(fetcher.queriedServers).isEqualTo(List.of("hkps://server1"));
        }

        @Test
        void aKeyWithoutUserIdsStillCountsAsFetched() throws Exception {
            BcKeyStore genStore = createStore();
            BcRunner generator = new BcRunner(genStore, null, null);
            String fp = generator.generateKey("Test User <test@example.com>", "ed25519", null);
            PGPPublicKeyRing strippedKey = stripUserIds(genStore.findPublicKey(fp).ring());

            BcKeyStore fetchStore = new BcKeyStore(null,
                    tempDir.resolve("fetch-cd"), tempDir.resolve("fetch-bp"));
            StubFetcher fetcher = new StubFetcher(fetchStore,
                    Map.of("hkps://server1", strippedKey),
                    List.of("hkps://server1", "hkps://server2"));

            assertThat(fetcher.fetch(fp)).isTrue();
        }

        @Test
        void recordsWhichKeyserverSuppliedTheKey() throws Exception {
            BcKeyStore genStore = createStore();
            BcRunner generator = new BcRunner(genStore, null, null);
            String fp = generator.generateKey("Test User <test@example.com>", "ed25519", null);
            PGPPublicKeyRing fullKey = genStore.findPublicKey(fp).ring();

            BcKeyStore fetchStore = new BcKeyStore(null,
                    tempDir.resolve("fetch-cd"), tempDir.resolve("fetch-bp"));
            Map<String, PGPPublicKeyRing> responses = new HashMap<>();
            responses.put("hkps://server2", fullKey);

            StubFetcher fetcher = new StubFetcher(fetchStore, responses,
                    List.of("hkps://server1", "hkps://server2"));

            assertThat(fetcher.fetch(fp)).isTrue();
            assertThat(fetchStore.findPublicKey(fp).source()).isEqualTo(TrustRootRef.keyserver("hkps://server2"));
        }

        @Test
        void returnsFalseWhenNoKeyserverHasKey() throws Exception {
            BcKeyStore fetchStore = new BcKeyStore(null,
                    tempDir.resolve("fetch-cd"), tempDir.resolve("fetch-bp"));

            StubFetcher fetcher = new StubFetcher(fetchStore, Map.of(),
                    List.of("hkps://server1", "hkps://server2"));

            assertThat(fetcher.fetch("AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD")).isFalse();
            assertThat(fetcher.queriedServers).isEqualTo(List.of("hkps://server1", "hkps://server2"));
        }

        @Test
        void skipsKeyserversWhenTheKeyIsAlreadyHeldWithUserIds() throws Exception {
            BcKeyStore genStore = createStore();
            BcRunner generator = new BcRunner(genStore, null, null);
            String fp = generator.generateKey("Test User <test@example.com>", "ed25519", null);

            BcKeyStore fetchStore = new BcKeyStore(null,
                    tempDir.resolve("fetch-cd"), tempDir.resolve("fetch-bp"));
            fetchStore.addFetched(genStore.findPublicKey(fp).ring(), "hkps://keys.example.org");

            StubFetcher fetcher = new StubFetcher(fetchStore, Map.of(),
                    List.of("hkps://server1"));

            assertThat(fetcher.fetch(fp)).isTrue();
            assertThat(fetcher.queriedServers).isEmpty();
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
