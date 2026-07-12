package io.github.aloubyansky.sigmund.core;

/**
 * An OIDC-based identity credential carrying both issuer and subject.
 * <p>
 * Required for CI pipelines, service accounts, and cases where the issuer must be
 * verified. Matching just the subject without the issuer is insecure — different
 * identity providers could issue the same subject string.
 * <p>
 * For simple email-based matching where the issuer doesn't matter, use
 * {@link EmailCredential} instead.
 *
 * <h3>Matching semantics</h3>
 * <p>
 * Both {@code issuer} and {@code subject} must match exactly (case-sensitive).
 * A Sigstore verification produces <em>both</em> an {@code OidcCredential} and,
 * when the subject is an email, an {@link EmailCredential}. This means a signer
 * configured with only an {@code email} credential can match a Sigstore signature
 * via the {@code EmailCredential} in the proven set, while a signer configured
 * with an {@code oidc} credential gets the stricter issuer+subject check.
 *
 * @param issuer the OIDC issuer URL (e.g., {@code "https://token.actions.githubusercontent.com"})
 * @param subject the OIDC subject (e.g., {@code "https://github.com/org/repo"})
 * @see EmailCredential
 */
public record OidcCredential(String issuer, String subject) implements Credential {

    /**
     * Creates a new OIDC credential.
     *
     * @throws IllegalArgumentException if issuer or subject is {@code null} or blank
     */
    public OidcCredential {
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalArgumentException("issuer must not be null or blank");
        }
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("subject must not be null or blank");
        }
    }

    /**
     * Returns the fixed credential type {@code "oidc"}.
     *
     * @return {@code "oidc"}
     */
    @Override
    public String type() {
        return TYPE_OIDC;
    }

    @Override
    public String displayName() {
        return subject + " (via " + issuer + ")";
    }

    /**
     * Checks whether this OIDC credential matches another credential.
     * <p>
     * Returns {@code true} only if the other credential is an {@link OidcCredential}
     * with the same issuer and subject (both case-sensitive).
     *
     * @param other the credential to match against
     * @return {@code true} if both issuer and subject match
     */
    @Override
    public boolean matches(Credential other) {
        return other instanceof OidcCredential oc
                && issuer.equals(oc.issuer())
                && subject.equals(oc.subject());
    }
}
