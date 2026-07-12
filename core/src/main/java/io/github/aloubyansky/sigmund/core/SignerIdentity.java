package io.github.aloubyansky.sigmund.core;

import java.util.List;

/**
 * A named entity with an extensible credential bag.
 * <p>
 * A signer identity represents a person, team, or service account that signs artifacts.
 * It carries multiple {@link Credential}s of different types — for example, an OpenPGP v4
 * fingerprint, an OpenPGP v6 fingerprint, and an email address. During verification,
 * identity matching checks for overlap between the signer's credential bag and the
 * proven credentials from evidence verification.
 *
 * <h3>Example</h3>
 *
 * <pre>{@code
 * var alice = new SignerIdentity("alice", "Alice", List.of(
 *         new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23"),
 *         new FingerprintCredential("openpgp6", "ABCD1234..."),
 *         new EmailCredential("alice@example.com")));
 * }</pre>
 *
 * @param id the reference name used in trust configuration (e.g., {@code "alice"})
 * @param displayName a human-readable name for reporting
 * @param credentials the extensible credential bag
 * @see Credential
 * @see TrustPolicy
 */
public record SignerIdentity(
        String id,
        String displayName,
        List<Credential> credentials) {

    /**
     * Creates a new signer identity.
     *
     * @throws IllegalArgumentException if id is {@code null} or blank, or credentials is {@code null}
     */
    public SignerIdentity {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("id must not be null or blank");
        }
        if (credentials == null) {
            throw new IllegalArgumentException("credentials must not be null");
        }
        credentials = List.copyOf(credentials);
    }
}
