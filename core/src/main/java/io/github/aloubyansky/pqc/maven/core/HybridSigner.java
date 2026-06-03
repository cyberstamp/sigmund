package io.github.aloubyansky.pqc.maven.core;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Orchestrates hybrid signing combining classical GPG (v4 packet) and
 * post-quantum cryptography via Sequoia (v6 packet) into a single .asc file.
 * <p>
 * The two ASCII-armored signatures are combined using {@link AscCombiner},
 * resulting in a hybrid signature that provides both classical and
 * post-quantum security.
 *
 * <pre>{@code
 * GpgRunner gpg = new GpgRunner();
 * SqRunner sq = new SqRunner(Path.of("/tmp/sq-keys"));
 * String pqcFingerprint = sq.generateKey("Alice <alice@example.com>");
 *
 * HybridSigner signer = new HybridSigner(gpg, sq, pqcFingerprint);
 * signer.sign(Path.of("artifact.jar"), Path.of("artifact.jar.asc"));
 * }</pre>
 *
 * @see AscCombiner
 * @see GpgRunner
 * @see SqRunner
 */
public class HybridSigner {

    private final GpgRunner gpg;
    private final SqRunner sq;
    private final String pqcFingerprint;

    /**
     * Constructs a HybridSigner with the specified GPG and Sequoia runners.
     *
     * @param gpg the GpgRunner instance for classical signing
     * @param sq the SqRunner instance for PQC signing
     * @param pqcFingerprint the PQC key fingerprint to use for signing
     * @throws IllegalArgumentException if any parameter is null or pqcFingerprint is empty
     */
    public HybridSigner(GpgRunner gpg, SqRunner sq, String pqcFingerprint) {
        if (gpg == null) {
            throw new IllegalArgumentException("gpg cannot be null");
        }
        if (sq == null) {
            throw new IllegalArgumentException("sq cannot be null");
        }
        if (pqcFingerprint == null || pqcFingerprint.isEmpty()) {
            throw new IllegalArgumentException("pqcFingerprint cannot be null or empty");
        }
        this.gpg = gpg;
        this.sq = sq;
        this.pqcFingerprint = pqcFingerprint;
    }

    /**
     * Creates a hybrid signature combining classical and post-quantum signatures.
     *
     * @param artifactFile the file to sign
     * @param outputAsc the path where the combined .asc signature will be written
     * @throws IllegalArgumentException if artifactFile or outputAsc is null
     * @throws IOException if an I/O error occurs
     */
    public void sign(Path artifactFile, Path outputAsc) throws IOException {
        if (artifactFile == null) {
            throw new IllegalArgumentException("artifactFile cannot be null");
        }
        if (outputAsc == null) {
            throw new IllegalArgumentException("outputAsc cannot be null");
        }

        Path tempClassicSig = null;
        Path tempPqcSig = null;

        try {
            tempClassicSig = Files.createTempFile("classic-sig", ".asc");
            tempPqcSig = Files.createTempFile("pqc-sig", ".asc");

            String classicAsc = gpg.sign(artifactFile, tempClassicSig);
            String pqcAsc = sq.sign(artifactFile, tempPqcSig, pqcFingerprint);
            String combinedAsc = AscCombiner.combine(classicAsc, pqcAsc);

            Files.writeString(outputAsc, combinedAsc);
        } finally {
            deleteSilently(tempClassicSig);
            deleteSilently(tempPqcSig);
        }
    }

    private void deleteSilently(Path file) {
        if (file != null) {
            try {
                Files.deleteIfExists(file);
            } catch (IOException ignored) {
            }
        }
    }
}
