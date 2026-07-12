package io.github.aloubyansky.sigmund.core;

/**
 * A typed identity credential that can be used to verify a signer's identity.
 * <p>
 * Credentials form an extensible bag on {@link SignerIdentity} — adding support for a new
 * signing backend (X.509, AWS Signer, Notation) requires only a new credential type string
 * and a new {@code Credential} implementation, with no schema changes.
 *
 * <h3>Matching semantics</h3>
 * <p>
 * {@link #matches(Credential)} performs <strong>same-type matching only</strong>. A
 * {@link FingerprintCredential} never matches an {@link EmailCredential}, even if both
 * refer to the same person. Cross-backend matching works because
 * {@code SignatureTool.extractCredentials()} produces <em>all</em> applicable credential
 * types for a verified signature. For example, a Sigstore verification produces both an
 * {@link OidcCredential} and an {@link EmailCredential} (when the subject is an email),
 * so a signer configured with only an {@code email} credential matches via the
 * {@code EmailCredential} in the proven set — no cross-type matching is needed.
 *
 * <h3>Built-in credential types</h3>
 * <ul>
 * <li>{@code "openpgp4"}, {@code "openpgp6"} — {@link FingerprintCredential},
 * named by key version (not tool or algorithm)</li>
 * <li>{@code "email"} — {@link EmailCredential}</li>
 * <li>{@code "oidc"} — {@link OidcCredential} (issuer + subject)</li>
 * </ul>
 *
 * @see SignerIdentity
 * @see FingerprintCredential
 * @see EmailCredential
 * @see OidcCredential
 */
public interface Credential {

    String TYPE_OPENPGP_V4 = "openpgp4";
    String TYPE_OPENPGP_V6 = "openpgp6";
    String TYPE_EMAIL = "email";
    String TYPE_OIDC = "oidc";

    /**
     * Returns the credential type identifier.
     * <p>
     * Built-in types include {@code "openpgp4"}, {@code "openpgp6"}, {@code "email"},
     * and {@code "oidc"}. Custom types can be introduced for new signing backends.
     *
     * @return the type string, never {@code null}
     */
    String type();

    /**
     * Returns a human-readable representation of this credential for display purposes.
     *
     * @return the display name, never {@code null}
     */
    String displayName();

    /**
     * Checks whether this credential matches another credential.
     * <p>
     * Matching is type-specific — credentials of different types always return {@code false}.
     * Within the same type, matching may apply normalization (e.g., case-insensitive fingerprint
     * suffix matching for {@link FingerprintCredential}).
     *
     * @param other the credential to match against
     * @return {@code true} if this credential matches the other
     */
    boolean matches(Credential other);
}
