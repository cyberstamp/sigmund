package dev.cyberstamp.sigmund.core;

/**
 * Bouncy Castle keys for tests: generated into a store by a runner that is closed again, as every
 * test closes the runners it opens.
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
}
