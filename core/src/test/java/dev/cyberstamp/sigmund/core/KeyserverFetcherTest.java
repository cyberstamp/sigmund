package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.sig.RevocationReasonTags;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
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
                verifierStore.addFetched(Map.of("hkps://keys.example.org", strippedKey));

                PGPPublicKeyRing cached = verifierStore.findPublicKey(fp).ring();
                assertThat(cached).isNotNull();
                assertThat(cached.getPublicKey().getUserIDs().hasNext())
                        .as("Cached key should have no UIDs initially").isFalse();

                verifierStore.addFetched(Map.of("hkps://keys.example.org", fullKey));
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
                verifierStore.addFetched(Map.of("hkps://keys.example.org", strippedKey));

                PGPPublicKeyRing found = verifierStore.findPublicKey(fp).ring();
                assertThat(found).as("Key without UIDs should still be findable").isNotNull();
            }
        }
    }

    @Nested
    class FetchKeyLoop {

        @Test
        void joinsAStrippedCopyWithOneThatHasUserIds() throws Exception {
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
                    assertThat(fetcher.queriedServers).containsExactlyInAnyOrder("hkps://server1", "hkps://server2");
                    assertThat(fetchStore.findPublicKey(fp).source())
                            .isEqualTo(TrustRootRef.keyservers(List.of("hkps://server1", "hkps://server2")));
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
                assertThat(fetcher.queriedServers).containsExactlyInAnyOrder("hkps://server1", "hkps://server2");
            }
        }

        @Test
        void skipsKeyserversWhenTheKeyIsAlreadyHeldWithUserIds() throws Exception {
            BcKeyStore genStore = createStore();
            try (BcRunner generator = new BcRunner(genStore, null, null)) {
                String fp = generator.generateKey("Test User <test@example.com>", "ed25519", null);

                BcKeyStore fetchStore = new BcKeyStore(null,
                        tempDir.resolve("fetch-cd"), tempDir.resolve("fetch-bp"));
                fetchStore.addFetched(Map.of("hkps://keys.example.org", genStore.findPublicKey(fp).ring()));

                try (StubFetcher fetcher = new StubFetcher(fetchStore, Map.of(),
                        List.of("hkps://server1"))) {

                    assertThat(fetcher.fetch(fp)).isTrue();
                    assertThat(fetcher.queriedServers).isEmpty();
                }
            }
        }
    }

    @Nested
    class MergingCopies {

        private static final String USER_ID = "Alice Example <alice@example.org>";
        private static final String SERVER1 = "hkps://server1";
        private static final String SERVER2 = "hkps://server2";
        private static final List<String> BOTH = List.of(SERVER1, SERVER2);

        private BcKeyStore generated;
        private String fp;
        private PGPPublicKeyRing full;

        @BeforeEach
        void generateKey() {
            generated = createStore();
            fp = BcTestKeys.generate(generated, USER_ID, "ed25519", "pgp4");
            full = generated.findPublicKey(fp).ring();
        }

        private BcKeyStore fetchStore(String name) {
            return new BcKeyStore(null, tempDir.resolve(name + "-cd"), tempDir.resolve(name + "-bp"));
        }

        private PGPPublicKeyRing fetchFrom(BcKeyStore store, String keyId, Map<String, byte[]> bodies) {
            try (StubFetcher fetcher = new StubFetcher(store, BOTH, bodies, Duration.ofSeconds(10))) {
                assertThat(fetcher.fetch(keyId)).isTrue();
            }
            return store.findPublicKey(keyId).ring();
        }

        private Map<String, byte[]> bodies(PGPPublicKeyRing first, PGPPublicKeyRing second) {
            return encoded(Map.of(SERVER1, first, SERVER2, second));
        }

        private PGPSecretKeyRing secret() {
            return generated.findSecretKey(fp);
        }

        private PGPSignature selfSignature(PGPSignatureSubpacketGenerator hashed, int type, Instant at) throws Exception {
            PGPSecretKey signer = secret().getSecretKey();
            PGPSignatureGenerator generator = new PGPSignatureGenerator(
                    new BcPGPContentSignerBuilder(signer.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256),
                    signer.getPublicKey());
            generator.init(type, signer.extractPrivateKey(null));
            hashed.setSignatureCreationTime(true, Date.from(at));
            hashed.setIssuerFingerprint(false, signer.getPublicKey());
            generator.setHashedSubpackets(hashed.generate());
            return type == PGPSignature.KEY_REVOCATION
                    ? generator.generateCertification(signer.getPublicKey())
                    : generator.generateCertification(USER_ID, signer.getPublicKey());
        }

        private PGPPublicKeyRing withRevocation() throws Exception {
            PGPSignatureSubpacketGenerator hashed = new PGPSignatureSubpacketGenerator();
            hashed.setRevocationReason(true, RevocationReasonTags.KEY_COMPROMISED, "compromised");
            PGPSignature revocation = selfSignature(hashed, PGPSignature.KEY_REVOCATION, Instant.now());
            return replacePrimary(full, PGPPublicKey.addCertification(full.getPublicKey(), revocation));
        }

        private PGPPublicKeyRing withNewerExpiry() throws Exception {
            PGPSignatureSubpacketGenerator hashed = new PGPSignatureSubpacketGenerator();
            hashed.setKeyExpirationTime(true, 86400);
            Instant later = full.getPublicKey().getCreationTime().toInstant().plusSeconds(1);
            PGPSignature newer = selfSignature(hashed, PGPSignature.POSITIVE_CERTIFICATION, later);
            return replacePrimary(full, PGPPublicKey.addCertification(full.getPublicKey(), USER_ID, newer));
        }

        private PGPPublicKeyRing replacePrimary(PGPPublicKeyRing ring, PGPPublicKey primary) {
            List<PGPPublicKey> keys = new ArrayList<>(List.of(primary));
            Iterator<PGPPublicKey> rest = ring.getPublicKeys();
            rest.next();
            rest.forEachRemaining(keys::add);
            return new PGPPublicKeyRing(keys);
        }

        private Set<String> signatures(PGPPublicKeyRing ring) {
            Set<String> encodedSignatures = new TreeSet<>();
            ring.getPublicKeys().forEachRemaining(key -> key.getSignatures()
                    .forEachRemaining(signature -> encodedSignatures.add(hex(signature))));
            return encodedSignatures;
        }

        private Set<String> userIds(PGPPublicKeyRing ring) {
            Set<String> ids = new TreeSet<>();
            ring.getPublicKey().getUserIDs().forEachRemaining(ids::add);
            return ids;
        }

        private String hex(PGPSignature signature) {
            try {
                return BcKeyStore.bytesToHex(signature.getEncoded());
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }

        private PGPPublicKeyRing stripped() {
            return stripUserIds(full);
        }

        @Test
        void everyKeyserverIsAsked() {
            BcKeyStore store = fetchStore("fetch");
            try (StubFetcher fetcher = new StubFetcher(store, BOTH, bodies(full, full), Duration.ofSeconds(10))) {
                assertThat(fetcher.fetch(fp)).isTrue();
                assertThat(fetcher.queriedServers).containsExactlyInAnyOrder(SERVER1, SERVER2);
            }
        }

        @Test
        void aStrippedCopyJoinedWithAFullOneKeepsItsUserIds() {
            BcKeyStore store = fetchStore("fetch");
            PGPPublicKeyRing stored = fetchFrom(store, fp, bodies(stripped(), full));

            assertThat(userIds(stored)).containsExactly(USER_ID);
            assertThat(store.findPublicKey(fp).source().identifier()).isEqualTo("hkps://server1, hkps://server2");
        }

        @Test
        void aRevocationOneServerWithholdsStillCounts() throws Exception {
            BcKeyStore store = fetchStore("fetch");
            PGPPublicKeyRing stored = fetchFrom(store, fp, bodies(full, withRevocation()));

            assertThat(stored.getPublicKey().hasRevocation()).isTrue();
        }

        @Test
        void aNewerSelfSignatureOneServerWithholdsIsKept() throws Exception {
            BcKeyStore store = fetchStore("fetch");
            PGPPublicKeyRing stored = fetchFrom(store, fp, bodies(full, withNewerExpiry()));

            assertThat(stored.getPublicKey().getSignaturesForID(USER_ID)).toIterable().hasSize(2);
            Date now = Date.from(Instant.now().plusSeconds(60));
            Date expiry = new OpenPGPCertificate(stored).getPrimaryKey().getKeyExpirationDateAt(now);
            assertThat(expiry).isEqualTo(Date.from(full.getPublicKey().getCreationTime().toInstant()
                    .plusSeconds(86400)));
        }

        @Test
        void theOrderCopiesArriveInDoesNotChangeTheCertificate() throws Exception {
            PGPPublicKeyRing newer = withNewerExpiry();
            PGPPublicKeyRing forward = fetchFrom(fetchStore("forward"), fp, bodies(full, newer));
            PGPPublicKeyRing backward = fetchFrom(fetchStore("backward"), fp, bodies(newer, full));

            assertThat(signatures(backward)).isEqualTo(signatures(forward));
            assertThat(userIds(backward)).isEqualTo(userIds(forward));
        }

        @Test
        void identicalCopiesDoNotDuplicate() {
            PGPPublicKeyRing stored = fetchFrom(fetchStore("fetch"), fp, bodies(full, full));

            assertThat(userIds(stored)).hasSize(1);
            assertThat(stored.getPublicKey().getSignaturesForID(USER_ID)).toIterable().hasSize(1);
        }

        @Test
        void aSubkeyFingerprintLookupJoinsCopiesOfItsCertificate() {
            Iterator<PGPPublicKey> keys = full.getPublicKeys();
            keys.next();
            String subkeyFingerprint = BcKeyStore.bytesToHex(keys.next().getFingerprint());
            PGPPublicKeyRing stored = fetchFrom(fetchStore("fetch"), subkeyFingerprint, bodies(stripped(), full));

            assertThat(userIds(stored)).containsExactly(USER_ID);
        }

        @Test
        void aCopyOfAnotherPrimaryIsSetAside() {
            Iterator<PGPPublicKey> keys = full.getPublicKeys();
            keys.next();
            PGPPublicKey subkey = keys.next();
            String keyId = BcKeyStore.bytesToHex(subkey.getFingerprint()).substring(24);
            BcKeyStore otherStore = createStore();
            String otherFp = BcTestKeys.generate(otherStore, "Mallory <mallory@example.org>", "ed25519", "pgp4");
            PGPPublicKey otherPrimary = otherStore.findPublicKey(otherFp).ring().getPublicKey();
            PGPPublicKeyRing impostor = new PGPPublicKeyRing(List.of(otherPrimary, subkey));

            BcKeyStore store = fetchStore("fetch");
            PGPPublicKeyRing stored = fetchFrom(store, keyId, bodies(full, impostor));

            assertThat(BcKeyStore.bytesToHex(stored.getPublicKey().getFingerprint())).isEqualToIgnoringCase(fp);
            assertThat(store.findPublicKey(keyId).source()).isEqualTo(TrustRootRef.keyserver(SERVER1));
        }

        @Test
        void aCopyOverTheSizeLimitIsNotRead() {
            BcKeyStore store = fetchStore("fetch");
            Map<String, byte[]> bodies = new HashMap<>(encoded(Map.of(SERVER1, full)));
            bodies.put(SERVER2, new byte[KeyserverFetcher.MAX_COPY_BYTES + 1]);
            try (StubFetcher fetcher = new StubFetcher(store, BOTH, bodies, Duration.ofSeconds(10))) {
                assertThat(fetcher.fetch(fp)).isTrue();

                UnreadableCertificate copy = fetcher.unreadableCopyOf(fp);
                assertThat(copy.message()).contains("larger than 1048576 bytes");
                assertThat(copy.cause()).isEqualTo(UnreadableCertificate.Cause.DAMAGED);
            }
            assertThat(store.findPublicKey(fp).source()).isEqualTo(TrustRootRef.keyserver(SERVER1));
        }

        @Test
        void aServerThatNeverAnswersDoesNotHoldBackTheOther() throws Exception {
            CountDownLatch never = new CountDownLatch(1);
            BcKeyStore store = fetchStore("fetch");
            Map<String, byte[]> bodies = encoded(Map.of(SERVER2, full));
            try (StubFetcher fetcher = new StubFetcher(store, BOTH, bodies, Duration.ofMillis(200)) {
                @Override
                byte[] download(String keyId, String keyserver) {
                    if (keyserver.equals(SERVER1)) {
                        try {
                            never.await();
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            return null;
                        }
                    }
                    return super.download(keyId, keyserver);
                }
            }) {
                long started = System.nanoTime();
                boolean fetched = fetcher.fetch(fp);

                assertThat(fetched).isTrue();
                assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(2));
                assertThat(store.findPublicKey(fp).source()).isEqualTo(TrustRootRef.keyserver(SERVER2));
            }
        }

        @Test
        void requestsStartBeforeAnyCompletes() {
            CountDownLatch started = new CountDownLatch(2);
            AtomicBoolean overlapped = new AtomicBoolean(true);
            BcKeyStore store = fetchStore("fetch");
            try (StubFetcher fetcher = new StubFetcher(store, BOTH, bodies(full, full), Duration.ofSeconds(10)) {
                @Override
                byte[] download(String keyId, String keyserver) {
                    started.countDown();
                    try {
                        if (!started.await(5, TimeUnit.SECONDS)) {
                            overlapped.set(false);
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    return super.download(keyId, keyserver);
                }
            }) {
                assertThat(fetcher.fetch(fp)).isTrue();
            }
            assertThat(overlapped).isTrue();
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
        byte[] download(String keyId, String keyserver) {
            downloads++;
            return "<html>not a key</html>".getBytes(StandardCharsets.US_ASCII);
        }
    }

    private static class StubFetcher extends KeyserverFetcher {
        private final Map<String, byte[]> bodies;
        final List<String> queriedServers = new CopyOnWriteArrayList<>();

        StubFetcher(BcKeyStore store, Map<String, PGPPublicKeyRing> responses,
                List<String> keyservers) {
            super(store, keyservers);
            this.bodies = encoded(responses);
        }

        StubFetcher(BcKeyStore store, List<String> keyservers, Map<String, byte[]> bodies,
                Duration requestTimeout) {
            super(store, keyservers, requestTimeout);
            this.bodies = bodies;
        }

        @Override
        byte[] download(String keyId, String keyserver) {
            queriedServers.add(keyserver);
            return bodies.get(keyserver);
        }
    }

    private static Map<String, byte[]> encoded(Map<String, PGPPublicKeyRing> rings) {
        Map<String, byte[]> bodies = new HashMap<>();
        rings.forEach((server, ring) -> {
            try {
                bodies.put(server, ring.getEncoded());
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        });
        return bodies;
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
