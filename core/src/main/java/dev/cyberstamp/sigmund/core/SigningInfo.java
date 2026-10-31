package dev.cyberstamp.sigmund.core;

/**
 * Describes one signing key that a {@link SignatureTool} will use.
 *
 * @param toolName the tool name (e.g., {@code "bc"}, {@code "gpg"}, {@code "sq"})
 * @param fingerprint full hex fingerprint, or {@code null} if unknown
 * @param algorithm algorithm name (e.g., {@code "RSA"}, {@code "Ed25519"}), or {@code null}
 * @param userId user ID string (e.g., {@code "Alice <alice@example.com>"}), or {@code null}
 * @param credentialType the key's own credential type (e.g., {@code "pgp4"}, {@code "pgp6"},
 *        {@code "sigstore"}), or {@code null} when the key cannot be read
 */
public record SigningInfo(
        String toolName,
        String fingerprint,
        String algorithm,
        String userId,
        String credentialType) {

    private static final String TYPE_UNKNOWN = "type unknown";

    /**
     * Returns a human-readable summary of this signing key: the tool, the credential type (or
     * {@code "type unknown"}), then the algorithm, fingerprint and user ID when present.
     *
     * @return formatted string, e.g. {@code "sq: pgp6 Ed25519 AB12 (Alice <alice@example.com>)"}
     */
    public String display() {
        var sb = new StringBuilder(toolName).append(": ")
                .append(credentialType != null ? credentialType : TYPE_UNKNOWN);
        if (algorithm != null) {
            sb.append(" ").append(algorithm);
        }
        if (fingerprint != null) {
            sb.append(" ").append(fingerprint);
        }
        if (userId != null) {
            sb.append(" (").append(userId).append(")");
        }
        return sb.toString();
    }
}
