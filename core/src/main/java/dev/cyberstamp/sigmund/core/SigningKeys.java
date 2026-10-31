package dev.cyberstamp.sigmund.core;

import java.util.List;

/**
 * The rule every OpenPGP tool applies to the key {@link SignatureTool#sign} is given: it must be
 * one of the keys the tool was configured with, matched by fingerprint ignoring case.
 */
final class SigningKeys {

    private SigningKeys() {
    }

    /**
     * Returns the fingerprint of the key to sign with, after checking it is one the tool names.
     *
     * @param toolName the tool, named in the error
     * @param signingFingerprints the fingerprints the tool was configured to sign with
     * @param key the key the tool was asked to sign with
     * @return the key's fingerprint
     * @throws IllegalArgumentException if the key has no fingerprint or is not one of
     *         {@code signingFingerprints}; the message names the tool and the fingerprint
     */
    static String requireListed(String toolName, List<String> signingFingerprints, SigningInfo key) {
        String fingerprint = key.fingerprint();
        if (fingerprint == null || signingFingerprints.stream().noneMatch(fingerprint::equalsIgnoreCase)) {
            throw new IllegalArgumentException(toolName + " cannot sign with key " + fingerprint
                    + ": it is not one of its signing keys " + signingFingerprints);
        }
        return fingerprint;
    }
}
