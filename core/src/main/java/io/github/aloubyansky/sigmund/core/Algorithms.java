package io.github.aloubyansky.sigmund.core;

import java.util.Map;

/**
 * IANA OpenPGP Public Key Algorithms registry mappings.
 * <p>
 * Provides algorithm ID-to-name lookup and PQC classification. Based on
 * RFC 9580 and RFC 9980. The PQC algorithm IDs are 30–36 (ML-DSA, SLH-DSA,
 * ML-KEM composites).
 * <p>
 * Used by {@link OpenPgpSignatureFormat} (packet inspection),
 * verification reports (display formatting), and the facade (algorithm-based routing).
 */
public final class Algorithms {

    // IANA OpenPGP Public Key Algorithms registry (RFC 9580 + RFC 9980)
    private static final Map<Integer, String> ALGORITHM_NAMES = Map.ofEntries(
            Map.entry(1, "RSA"),
            Map.entry(2, "RSA"),
            Map.entry(3, "RSA"),
            Map.entry(16, "Elgamal"),
            Map.entry(17, "DSA"),
            Map.entry(18, "ECDH"),
            Map.entry(19, "ECDSA"),
            Map.entry(22, "EdDSA"),
            Map.entry(25, "X25519"),
            Map.entry(26, "X448"),
            Map.entry(27, "Ed25519"),
            Map.entry(28, "Ed448"),
            Map.entry(30, "ML-DSA-65+Ed25519"),
            Map.entry(31, "ML-DSA-87+Ed448"),
            Map.entry(32, "SLH-DSA-SHAKE-128s"),
            Map.entry(33, "SLH-DSA-SHAKE-128f"),
            Map.entry(34, "SLH-DSA-SHAKE-256s"),
            Map.entry(35, "ML-KEM-768+X25519"),
            Map.entry(36, "ML-KEM-1024+X448"));

    private Algorithms() {
    }

    /**
     * Returns a human-readable label for an OpenPGP signature packet version.
     *
     * @param pgpVersion the signature packet version (4, 6, etc.)
     * @return {@code "PGP4"} for v4, {@code "PGP6"} for v6, {@code "PGPN"} for
     *         other positive versions, or {@code "-"} for non-positive values
     */
    public static String versionLabel(int pgpVersion) {
        return switch (pgpVersion) {
            case 4 -> "PGP4";
            case 6 -> "PGP6";
            default -> pgpVersion > 0 ? "PGP" + pgpVersion : "-";
        };
    }

    /**
     * Returns the human-readable name for an OpenPGP public-key algorithm ID.
     *
     * @param algorithmId the IANA-registered algorithm ID
     * @return the algorithm name, or {@code null} if the ID is not recognized
     */
    public static String algorithmName(int algorithmId) {
        return ALGORITHM_NAMES.get(algorithmId);
    }

    /**
     * Checks whether an OpenPGP public-key algorithm ID designates a
     * post-quantum composite or standalone algorithm.
     * <p>
     * PQC algorithm IDs are 30–36 per RFC 9980. This range may need updating
     * as new PQC algorithms are registered with IANA.
     *
     * @param algorithmId the IANA-registered algorithm ID
     * @return {@code true} if the algorithm is PQC
     */
    public static boolean isPqcAlgorithm(int algorithmId) {
        return algorithmId >= 30 && algorithmId <= 36;
    }

    /**
     * Checks whether an algorithm name corresponds to a PQC algorithm.
     *
     * @param algorithmName the algorithm name to check
     * @return {@code true} if the name matches a known PQC algorithm
     */
    public static boolean isPqcAlgorithmName(String algorithmName) {
        if (algorithmName == null) {
            return false;
        }
        for (var entry : ALGORITHM_NAMES.entrySet()) {
            if (algorithmName.equals(entry.getValue())) {
                return isPqcAlgorithm(entry.getKey());
            }
        }
        return false;
    }
}
