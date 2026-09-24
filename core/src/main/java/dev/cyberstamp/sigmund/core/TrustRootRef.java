package dev.cyberstamp.sigmund.core;

import java.nio.file.Path;

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

    /** An OpenPGP key store: a cert-d store, a GnuPG keyring, or an in-memory cache. */
    public static final String KIND_OPENPGP_KEYRING = "openpgp-keyring";

    /** A Sigstore trust root, as distributed by TUF. */
    public static final String KIND_SIGSTORE_TRUST_ROOT = "sigstore-trust-root";

    /** Used where a tool cannot say what it verified against. */
    public static final String KIND_UNKNOWN = "unknown";

    /**
     * Normalizes a missing kind to {@link #KIND_UNKNOWN}, so a result always names something.
     */
    public TrustRootRef {
        kind = kind == null || kind.isBlank() ? KIND_UNKNOWN : kind.trim();
    }

    /**
     * Creates a reference to an OpenPGP key store.
     *
     * @param store the store's location
     * @return the reference
     */
    public static TrustRootRef keyring(Path store) {
        return new TrustRootRef(KIND_OPENPGP_KEYRING, store == null ? null : store.toString());
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
}
