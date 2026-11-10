package dev.cyberstamp.sigmund.core;

import java.nio.file.Path;
import java.util.Set;

/**
 * A copy of a certificate Bouncy Castle could not read, kept so that a key whose only copy
 * cannot be read is never reported as absent.
 *
 * @param source where the copy is: the store holding it, or the keyserver that served it
 * @param file the file it was read from, or {@code null} for a copy a keyserver served
 * @param keys the uppercase fingerprints of the keys it holds — computed from its packets,
 *        listed in a keybox blob's index, the primary a cert-d file is named after, or the key a
 *        keyserver was asked for; empty when they cannot be told
 * @param cause why it could not be read, decided from its packets
 * @param message what Bouncy Castle reported, for the reason detail
 */
record UnreadableCertificate(TrustRootRef source, Path file, Set<String> keys, Cause cause,
        String message) {

    /**
     * Why a certificate could not be read.
     */
    enum Cause {

        /**
         * A key or signature in it uses a public-key algorithm Bouncy Castle does not implement,
         * such as a post-quantum one; a tool that implements it may read the certificate.
         */
        UNKNOWN_ALGORITHM,

        /**
         * Its packets are malformed or cut short, though every algorithm in them is one Bouncy
         * Castle implements; another copy may serve.
         */
        DAMAGED
    }

    /**
     * Copies the keys.
     */
    UnreadableCertificate {
        keys = Set.copyOf(keys);
    }

    /**
     * Whether this is a copy of a key: one of its keys is the key, or ends with its key ID.
     *
     * @param fingerprint the key's fingerprint, or its 64-bit key ID
     * @return {@code true} when the copy is known to hold the key
     */
    boolean holds(String fingerprint) {
        return keys.stream().anyMatch(key -> BcKeyStore.sameKey(key, fingerprint));
    }
}
