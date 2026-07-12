package io.github.aloubyansky.sigmund.core;

/**
 * An email-based identity credential.
 * <p>
 * Used for simple identity matching where the OIDC issuer does not matter or is
 * implicitly trusted. Matches OpenPGP UIDs (when combined with a name) and
 * Sigstore email-based subjects.
 * <p>
 * For cases where the issuer must be verified (CI pipelines, service accounts),
 * use {@link OidcCredential} instead.
 *
 * @param email the email address
 * @see OidcCredential
 */
public record EmailCredential(String email) implements Credential {

    /**
     * Creates a new email credential.
     *
     * @throws IllegalArgumentException if email is {@code null} or blank
     */
    public EmailCredential {
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("email must not be null or blank");
        }
    }

    /**
     * Returns the fixed credential type {@code "email"}.
     *
     * @return {@code "email"}
     */
    @Override
    public String type() {
        return TYPE_EMAIL;
    }

    @Override
    public String displayName() {
        return email;
    }

    /**
     * Checks whether this email matches another credential.
     * <p>
     * Returns {@code true} only if the other credential is an {@link EmailCredential}
     * with the same email address (case-sensitive).
     *
     * @param other the credential to match against
     * @return {@code true} if the emails match
     */
    @Override
    public boolean matches(Credential other) {
        return other instanceof EmailCredential ec
                && email.equals(ec.email());
    }
}
