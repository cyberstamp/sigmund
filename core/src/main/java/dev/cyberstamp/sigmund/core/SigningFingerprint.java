package dev.cyberstamp.sigmund.core;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The {@code signing-fingerprint} setting of an OpenPGP tool: the full fingerprints of the keys
 * it signs with.
 *
 * <p>
 * A full fingerprint — 40 hex characters for a v4 key, 64 for v6, in either case — names one key.
 * A key ID, an address or a user ID can match several keys in a keyring and leave the tool to
 * choose, so they are rejected: the keys a tool signs with are the ones the setting names, which
 * {@code signing.signer} then holds to the signer's pinned fingerprints.
 */
final class SigningFingerprint {

    private SigningFingerprint() {
    }

    /**
     * Reads the setting, a fingerprint or a list of them, normalized to upper case.
     *
     * @param toolName the tool whose settings these are, named in the error
     * @param setting the tool's {@code signing-fingerprint} setting
     * @param settings the tool's settings
     * @return the fingerprints in written order, empty when the setting is not set
     * @throws PolicyConfigException if the list is empty, an item is not a full v4 or v6
     *         fingerprint, or a fingerprint is listed twice
     */
    static List<String> allFrom(String toolName, ToolSetting setting, Map<String, String> settings) {
        String value = setting.from(settings);
        if (value == null) {
            return List.of();
        }
        String location = "tools." + toolName + "." + setting.key();
        if (value.isEmpty()) {
            throw new PolicyConfigException(location + ": the list is empty");
        }
        List<String> fingerprints = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (String item : setting.listFrom(settings)) {
            String fingerprint = normalize(location, item);
            if (!seen.add(fingerprint)) {
                throw new PolicyConfigException(location + ": '" + fingerprint + "' is listed twice");
            }
            fingerprints.add(fingerprint);
        }
        return List.copyOf(fingerprints);
    }

    private static String normalize(String location, String item) {
        if (!KeyCredential.isOpenPgpFingerprint(item)) {
            throw new PolicyConfigException(location + ": '" + item
                    + "' is not a full fingerprint (40 hex characters for a v4 key, 64 for v6); key IDs,"
                    + " addresses and user IDs are not accepted because they can name more than one key");
        }
        return KeyCredential.openPgp(item).fingerprint();
    }
}
