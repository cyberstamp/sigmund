package io.github.aloubyansky.pqc.maven.core;

import java.nio.file.Path;

/**
 * Identifies a PQC key for signature verification, either by fingerprint
 * or by certificate file path.
 * <p>
 * Use the factory methods {@link #fingerprint(String)} or {@link #certFile(Path)}
 * to create instances — exactly one of the two fields will be non-null.
 *
 * @param fingerprint the PQC key fingerprint, or null if using a certificate file
 * @param certFilePath the path to a PQC certificate file, or null if using a fingerprint
 * @see HybridVerifier#verify(Path, Path, PqcKeyConfig)
 */
public record PqcKeyConfig(String fingerprint, Path certFilePath) {

    public static PqcKeyConfig fingerprint(String fingerprint) {
        if (fingerprint == null) {
            throw new IllegalArgumentException("fingerprint cannot be null");
        }
        return new PqcKeyConfig(fingerprint, null);
    }

    public static PqcKeyConfig certFile(Path certFilePath) {
        if (certFilePath == null) {
            throw new IllegalArgumentException("certFilePath cannot be null");
        }
        return new PqcKeyConfig(null, certFilePath);
    }

    public boolean isFingerprint() {
        return fingerprint != null;
    }

    public boolean isCertFile() {
        return certFilePath != null;
    }
}
