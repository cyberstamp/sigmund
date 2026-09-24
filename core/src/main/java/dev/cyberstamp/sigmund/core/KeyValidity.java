package dev.cyberstamp.sigmund.core;

import java.time.Instant;
import org.bouncycastle.openpgp.PGPPublicKey;

/**
 * Judges whether a signing key was valid at the moment a claim was made.
 *
 * <p>
 * Expiry is evaluated against the claim time, never against the present. A signature made
 * while its key was valid stays valid after the key expires — otherwise every artifact
 * published by anyone who sets an expiry date would eventually stop verifying, and key
 * rotation would silently invalidate history. Conversely, a signature dated after the key's
 * expiry did not come from a valid key and fails.
 *
 * <p>
 * For OpenPGP the claim time is asserted by the signer
 * ({@link ClaimTimeSource#SIGNER}), so this check is only as strong as that
 * assertion: someone holding an expired but unrevoked key can date a signature back into the
 * validity period. That residual risk is the reason revocation matters more than expiry.
 */
final class KeyValidity {

    private KeyValidity() {
    }

    /**
     * Indicates whether a key was valid at a given instant.
     *
     * @param created when the key was created
     * @param validSeconds the key's validity period in seconds, or {@code 0} when it never
     *        expires
     * @param when the instant to judge against — normally the claim time — or {@code null}
     *        when the evidence records none
     * @return {@code true} when the key was valid then, and when no instant is given
     */
    public static boolean isWithinValidity(Instant created, long validSeconds, Instant when) {
        if (when == null || created == null) {
            return true;
        }
        if (when.isBefore(created)) {
            return false;
        }
        if (validSeconds <= 0) {
            return true;
        }
        return !when.isAfter(created.plusSeconds(validSeconds));
    }

    /**
     * Indicates whether an OpenPGP key was valid at a given instant.
     *
     * @param key the signing key
     * @param when the instant to judge against, or {@code null} when unknown
     * @return {@code true} when the key was valid then, and when no instant is given
     */
    public static boolean isValidAt(PGPPublicKey key, Instant when) {
        if (key == null) {
            return true;
        }
        return isWithinValidity(key.getCreationTime().toInstant(), key.getValidSeconds(), when);
    }
}
