package dev.cyberstamp.sigmund.core;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.openpgp.PGPPublicKeyRing;

/**
 * Bouncy Castle keys for tests: generated into a store by a runner that is closed again, as every
 * test closes the runners it opens, or added to a store as if keyservers had served them.
 */
final class BcTestKeys {

    private BcTestKeys() {
    }

    /**
     * Generates a key into {@code store}.
     *
     * @param store the store to write the key to
     * @param userId the key's user ID
     * @param cipherSuite the cipher suite, such as {@code ed25519}
     * @param credentialType {@code pgp4}, {@code pgp6}, or {@code null} for the default
     * @return the key's fingerprint
     */
    static String generate(BcKeyStore store, String userId, String cipherSuite, String credentialType) {
        try (BcRunner runner = new BcRunner(store, null, null)) {
            return runner.generateKey(userId, cipherSuite, credentialType);
        }
    }

    /**
     * Adds a certificate to {@code store} as if it had been fetched by its primary key's
     * fingerprint, each keyserver serving one copy, through the entry point
     * {@link KeyserverFetcher} uses.
     *
     * @param store the store to add the copies to
     * @param copiesByKeyserver the copy each keyserver served, by keyserver URL, in the order the
     *        keyservers are configured; must not be empty, and the first copy's primary key is the
     *        key asked for
     */
    static void addFetched(BcKeyStore store, Map<String, PGPPublicKeyRing> copiesByKeyserver) {
        PGPPublicKeyRing first = copiesByKeyserver.values().iterator().next();
        Map<String, List<PGPPublicKeyRing>> served = new LinkedHashMap<>();
        copiesByKeyserver.forEach((keyserver, copy) -> served.put(keyserver, List.of(copy)));
        store.addFetched(KeyRingFiles.hex(first.getPublicKey().getFingerprint()), served);
    }
}
