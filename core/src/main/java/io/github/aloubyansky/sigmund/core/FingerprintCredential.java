package io.github.aloubyansky.sigmund.core;

/**
 * An OpenPGP fingerprint credential, typed by key version.
 * <p>
 * The credential type is named after the key version ({@code "openpgp4"}, {@code "openpgp6"}),
 * not the algorithm family or the tool. This reflects the LibrePGP / RFC 9580 split in the
 * OpenPGP ecosystem: GnuPG follows LibrePGP and handles v4 keys, while Sequoia follows
 * RFC 9580 and handles v6 keys. The algorithm (e.g., RSA vs ML-DSA-87+Ed448) is a property
 * of the key itself, determined at key generation time.
 *
 * <h3>Matching semantics</h3>
 * <p>
 * Fingerprint matching is <strong>case-insensitive</strong> and supports <strong>suffix matching</strong>:
 * the shorter fingerprint must be a suffix of the longer one, and both must be at least
 * {@value #MIN_FINGERPRINT_LENGTH} hex characters. This accommodates the common case where
 * a configuration specifies a short key ID (16 hex chars) while the signature contains the
 * full fingerprint (40 or 64 hex chars). Two fingerprints of different types (e.g., {@code "openpgp4"}
 * vs {@code "openpgp6"}) never match.
 *
 * @param type the credential type, typically {@code "openpgp4"} or {@code "openpgp6"}
 * @param fingerprint the key fingerprint as a hex string
 */
public record FingerprintCredential(String type, String fingerprint) implements Credential {

    /**
     * The minimum fingerprint length (in hex characters) required for matching.
     * Shorter fingerprints are rejected to avoid accidental collisions.
     */
    public static final int MIN_FINGERPRINT_LENGTH = 16;

    /**
     * Creates a new fingerprint credential.
     *
     * @throws IllegalArgumentException if type or fingerprint is {@code null} or blank
     */
    public FingerprintCredential {
        if (type == null || type.isBlank()) {
            throw new IllegalArgumentException("type must not be null or blank");
        }
        if (fingerprint == null || fingerprint.isBlank()) {
            throw new IllegalArgumentException("fingerprint must not be null or blank");
        }
    }

    @Override
    public String displayName() {
        return fingerprint;
    }

    /**
     * Checks whether this fingerprint matches another credential.
     * <p>
     * Returns {@code false} if the other credential is not a {@link FingerprintCredential}
     * or has a different {@link #type()}. When types match, performs case-insensitive suffix
     * matching: the shorter fingerprint must be a suffix of the longer one, and both must
     * be at least {@value #MIN_FINGERPRINT_LENGTH} characters.
     *
     * @param other the credential to match against
     * @return {@code true} if this fingerprint matches the other
     */
    @Override
    public boolean matches(Credential other) {
        if (!(other instanceof FingerprintCredential fp)) {
            return false;
        }
        if (!type.equals(fp.type())) {
            return false;
        }
        return fingerprintsMatch(fingerprint, fp.fingerprint());
    }

    private static boolean fingerprintsMatch(String a, String b) {
        if (a.length() < MIN_FINGERPRINT_LENGTH || b.length() < MIN_FINGERPRINT_LENGTH) {
            return false;
        }
        String upperA = a.toUpperCase();
        String upperB = b.toUpperCase();
        return upperA.length() >= upperB.length()
                ? upperA.endsWith(upperB)
                : upperB.endsWith(upperA);
    }
}
