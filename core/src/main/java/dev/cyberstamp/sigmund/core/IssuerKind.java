package dev.cyberstamp.sigmund.core;

import java.util.Collection;
import java.util.Locale;
import java.util.Set;

/**
 * The kinds of issuer an {@link IdentityCredential} can come from, and what each can assert.
 *
 * <p>
 * An issuer's kind is known from its name, so policy lists issuers without configuring them:
 * a known directory's URL is a directory, and any other {@code https://} URL is an OIDC issuer;
 * a known directory may be written without the scheme. What each kind can assert is a closed set taken from existing
 * specifications, which is what lets a misspelled attribute be caught at load rather than
 * silently widening a match.
 */
public enum IssuerKind {

    /**
     * An OIDC provider, proven through a Fulcio certificate. Asserts the certificate subject,
     * the subject as {@code email} when it is an address, and the Fulcio certificate
     * extensions named as in Fulcio's OID registry ({@code 1.3.6.1.4.1.57264.1.9} onward;
     * the deprecated GitHub-specific extensions are not included).
     */
    OIDC(Set.of(
            IdentityCredential.SUBJECT,
            IdentityCredential.EMAIL,
            "build-signer-uri",
            "build-signer-digest",
            "runner-environment",
            "source-repository-uri",
            "source-repository-digest",
            "source-repository-ref",
            "source-repository-identifier",
            "source-repository-owner-uri",
            "source-repository-owner-identifier",
            "build-config-uri",
            "build-config-digest",
            "build-trigger",
            "run-invocation-uri",
            "source-repository-visibility-at-signing",
            "deployment-environment",
            "token-subject")),

    /**
     * A directory that verifies an address with its owner before publishing it on a key.
     * Asserts {@code email} only.
     */
    OPENPGP_DIRECTORY(Set.of(IdentityCredential.EMAIL));

    /**
     * The directory Sigmund knows: keys.openpgp.org, publishing only verified addresses. Its
     * URL is both its issuer name and its lookup endpoint.
     */
    public static final String KEYS_OPENPGP_ORG = "https://keys.openpgp.org";

    private static final Set<String> KNOWN_DIRECTORIES = Set.of(KEYS_OPENPGP_ORG);

    private final Set<String> attributes;

    IssuerKind(Set<String> attributes) {
        this.attributes = attributes;
    }

    /**
     * Returns the attributes an issuer of this kind can assert.
     *
     * @return the attribute names
     */
    public Set<String> attributes() {
        return attributes;
    }

    /**
     * Indicates whether an issuer of this kind can assert every one of the given attributes.
     *
     * @param names the attribute names
     * @return {@code true} if all are asserted by this kind
     */
    public boolean asserts(Collection<String> names) {
        return attributes.containsAll(names);
    }

    /**
     * Returns the canonical form of an issuer name.
     *
     * <p>
     * Every issuer is canonically an {@code https://} URL. A known directory may be written
     * without the scheme, and is recognized whatever the case of its host or a trailing
     * slash; any other name is returned as written, apart from surrounding whitespace.
     *
     * @param name the issuer name as written
     * @return the canonical name
     */
    public static String canonicalName(String name) {
        String trimmed = name.trim();
        String url = "https://" + trimmed.toLowerCase(Locale.ROOT)
                .replaceFirst("^https://", "")
                .replaceFirst("/+$", "");
        return KNOWN_DIRECTORIES.contains(url) ? url : trimmed;
    }

    /**
     * Returns the known directory a keyserver URL belongs to.
     *
     * <p>
     * A directory is reached through its keyserver endpoint, which may be written with the
     * {@code hkps://} scheme as keyserver settings do; the scheme, the case of the host and a
     * trailing slash do not matter.
     *
     * @param keyserverUrl the keyserver URL as configured
     * @return the directory's canonical name, or {@code null} when the URL is not a known
     *         directory's
     */
    public static String directoryServing(String keyserverUrl) {
        String canonical = canonicalName(keyserverUrl.trim().replaceFirst("(?i)^hkps://", ""));
        return KNOWN_DIRECTORIES.contains(canonical) ? canonical : null;
    }

    /**
     * Classifies an issuer by its name.
     *
     * @param name the issuer name, in any form {@link #canonicalName(String)} accepts
     * @return the kind, or {@code null} when the name is neither a known directory nor an
     *         {@code https://} URL
     */
    public static IssuerKind of(String name) {
        String canonical = canonicalName(name);
        if (KNOWN_DIRECTORIES.contains(canonical)) {
            return OPENPGP_DIRECTORY;
        }
        return canonical.startsWith("https://") ? OIDC : null;
    }
}
