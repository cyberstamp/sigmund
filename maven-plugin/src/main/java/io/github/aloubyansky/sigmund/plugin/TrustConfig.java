package io.github.aloubyansky.sigmund.plugin;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import java.util.List;
import java.util.Map;

/**
 * Parsed representation of a {@code trust-config.yaml} file.
 * <p>
 * The configuration defines trusted signers, artifact groups, trust mappings,
 * and unsigned artifact patterns for Maven dependency signature verification.
 *
 * @see TrustConfigParser
 */
@JsonDeserialize(using = TrustConfigDeserializer.class)
public record TrustConfig(
        Settings settings,
        Map<String, Signer> signers,
        Map<String, List<String>> artifacts,
        Map<String, List<String>> trust,
        List<String> unsigned) {

    /**
     * Global verification settings.
     */
    public record Settings(
            List<String> keyservers,
            String onUntrusted,
            boolean verifyAllSignatures,
            boolean fetchSignerInfo) {

        /** Default settings applied when the settings section is omitted. */
        public static Settings defaults() {
            return new Settings(List.of(), "fail", true, true);
        }

        /** Returns {@code true} if the given value is a valid on-untrusted policy. */
        public static boolean isValidOnUntrusted(String value) {
            return "fail".equals(value) || "warn".equals(value);
        }
    }

    /**
     * A named signer definition, normalized from any of the three config forms:
     * <ul>
     * <li><b>Minimal:</b> a uid string (e.g. {@code "Jane Doe <jane@example.com>"})</li>
     * <li><b>Short:</b> an object with {@code gpg}/{@code pqc}/{@code uid} directly</li>
     * <li><b>Full:</b> an object with optional {@code name} and a {@code members} array</li>
     * </ul>
     * All forms are normalized to a list of {@link Member} entries.
     */
    public record Signer(String name, List<Member> members) {
    }

    /**
     * A single signer credential with optional GPG fingerprint, PQC fingerprint, and user ID.
     * At least one of the three fields is always present.
     */
    public record Member(String gpg, String pqc, String uid) {
    }
}
