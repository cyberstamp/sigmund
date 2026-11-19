package dev.cyberstamp.sigmund.core;

import java.nio.file.Path;
import java.util.List;

/**
 * The trust root a claim was verified against.
 *
 * <p>
 * Two runs can reach different outcomes for the same artifact because they trusted different
 * roots — one machine's keyring holds the signer's key, another's does not; one Sigstore
 * verification used the public-good trust root, another a private deployment's. Recording the
 * root is what lets a differing result be explained from the record rather than guessed at.
 *
 * @param kind what sort of root it is
 * @param identifier where it is — a path, a URL, or a deployment name
 */
public record TrustRootRef(String kind, String identifier) {

    /** A GnuPG home directory: its pubring, read by Bouncy Castle, or GnuPG's own keyring. */
    public static final String KIND_GNUPG_KEYRING = "gnupg-keyring";

    /** An OpenPGP cert-d certificate store, shared by Bouncy Castle and Sequoia. */
    public static final String KIND_OPENPGP_CERT_D = "openpgp-cert-d";

    /** Bouncy Castle's store of its own secret keys, whose public parts verify its signatures. */
    public static final String KIND_BC_PRIVATE_STORE = "bc-private-store";

    /** A Sigstore trust root, as distributed by TUF. */
    public static final String KIND_SIGSTORE_TRUST_ROOT = "sigstore-trust-root";

    /** A keyserver an OpenPGP key was fetched from in this session. */
    public static final String KIND_OPENPGP_KEYSERVER = "openpgp-keyserver";

    /** Used where a tool cannot say what it verified against. */
    public static final String KIND_UNKNOWN = "unknown";

    /**
     * Normalizes a missing kind to {@link #KIND_UNKNOWN}, so a result always names something.
     */
    public TrustRootRef {
        kind = kind == null || kind.isBlank() ? KIND_UNKNOWN : kind.trim();
    }

    /**
     * Creates a reference to a GnuPG home directory.
     *
     * @param gnupgHome the GnuPG home
     * @return the reference
     */
    public static TrustRootRef gnupgKeyring(Path gnupgHome) {
        return new TrustRootRef(KIND_GNUPG_KEYRING, pathOrNull(gnupgHome));
    }

    /**
     * Creates a reference to a cert-d certificate store.
     *
     * @param certD the store's location
     * @return the reference
     */
    public static TrustRootRef certD(Path certD) {
        return new TrustRootRef(KIND_OPENPGP_CERT_D, pathOrNull(certD));
    }

    /**
     * Creates a reference to Bouncy Castle's private key store.
     *
     * @param store the store's location
     * @return the reference
     */
    public static TrustRootRef bcPrivateStore(Path store) {
        return new TrustRootRef(KIND_BC_PRIVATE_STORE, pathOrNull(store));
    }

    /**
     * Creates a reference to the keyserver an OpenPGP key was fetched from.
     *
     * @param url the keyserver URL
     * @return the reference
     */
    public static TrustRootRef keyserver(String url) {
        return keyservers(List.of(url));
    }

    /**
     * Creates a reference to several keyservers that together supplied one OpenPGP key, as a
     * merged copy of the key does.
     *
     * <p>
     * The identifier is the URLs joined by {@code ", "} in the order given. It is recorded and
     * displayed for the reader; it is never compared with an issuer or any other identifier.
     *
     * @param urls the keyserver URLs, in the order they were consulted; must not be empty
     * @return the reference
     * @throws IllegalArgumentException if no URL is given
     */
    public static TrustRootRef keyservers(List<String> urls) {
        if (urls.isEmpty()) {
            throw new IllegalArgumentException("at least one keyserver is required");
        }
        return new TrustRootRef(KIND_OPENPGP_KEYSERVER, String.join(", ", urls));
    }

    /**
     * Creates a reference to a Sigstore trust root.
     *
     * @param deployment the deployment it came from, such as {@code public-good}
     * @return the reference
     */
    public static TrustRootRef sigstore(String deployment) {
        return new TrustRootRef(KIND_SIGSTORE_TRUST_ROOT, deployment);
    }

    /**
     * Creates a reference for a tool that cannot report its trust root.
     *
     * @return the reference
     */
    public static TrustRootRef unknown() {
        return new TrustRootRef(KIND_UNKNOWN, null);
    }

    /**
     * Renders the reference for reports: the kind, followed by where it is when known.
     *
     * @return the display form, such as {@code openpgp-cert-d /home/jane/.local/share/pgp.cert.d}
     */
    public String displayName() {
        return identifier == null ? kind : kind + " " + identifier;
    }

    private static String pathOrNull(Path path) {
        return path == null ? null : path.toString();
    }
}
