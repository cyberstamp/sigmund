package io.github.aloubyansky.pqc.maven.core;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.BiPredicate;

/**
 * Verifies hybrid signatures containing both classic GPG and PQC components.
 * <p>
 * This class delegates verification to both GPG (for classic signatures) and
 * Sequoia (for PQC signatures), then combines the results into a
 * {@link VerificationReport}. It supports both hybrid signatures (containing
 * both components) and classic-only signatures (for backward compatibility).
 *
 * <p>
 * Example usage:
 *
 * <pre>
 * {
 *     &#64;code
 *     // Create verifier with both GPG and PQC support
 *     GpgRunner gpg = new GpgRunner();
 *     SqRunner sq = new SqRunner(Path.of("/tmp/sq-keys"));
 *     HybridVerifier verifier = new HybridVerifier(gpg, sq);
 *
 *     // Verify with a specific PQC key fingerprint
 *     PqcKeyConfig config = PqcKeyConfig.fingerprint("ABC123...");
 *     VerificationReport report = verifier.verify(
 *             Path.of("artifact.jar"),
 *             Path.of("artifact.jar.asc"),
 *             config);
 *
 *     // Or verify with a certificate file
 *     PqcKeyConfig certConfig = PqcKeyConfig.certFile(Path.of("signer.cert"));
 *     VerificationReport report2 = verifier.verify(
 *             Path.of("artifact.jar"),
 *             Path.of("artifact.jar.asc"),
 *             certConfig);
 *
 *     // Pass null to skip PQC verification
 *     VerificationReport report3 = verifier.verify(
 *             Path.of("old-artifact.jar"),
 *             Path.of("old-artifact.jar.asc"),
 *             null);
 *     // report3.pqcResult() will be NOT_PRESENT
 * }
 * </pre>
 * <p>
 * Note: This class requires both {@code gpg} and {@code sq} executables to be
 * available on the system PATH for full functionality. If {@code sq} is not
 * available or {@link #sq} is null, PQC verification will return
 * {@link VerificationResult#NOT_PRESENT}.
 *
 *
 * @see HybridSigner
 * @see VerificationReport
 * @see VerificationResult
 */
public class HybridVerifier {

    private final GpgRunner gpg;
    private final SqRunner sq;

    /**
     * Constructs a HybridVerifier with specified GPG and PQC configuration.
     *
     * @param gpg the GPG runner instance for classic signature verification
     * @param sq the Sequoia runner instance for PQC verification, or null to
     *        skip PQC verification
     * @throws IllegalArgumentException if gpg is null
     */
    public HybridVerifier(GpgRunner gpg, SqRunner sq) {
        if (gpg == null) {
            throw new IllegalArgumentException("gpg cannot be null");
        }
        this.gpg = gpg;
        this.sq = sq;
    }

    /**
     * Verifies both classic and PQC signatures for the specified artifact.
     * <p>
     * This method performs the following steps:
     * <ol>
     * <li>Verifies the classic GPG signature using {@code gpg --verify}</li>
     * <li>Verifies the PQC signature using the provided PQC key configuration (if {@link #sq} is not null)</li>
     * <li>Combines the results into a {@link VerificationReport}</li>
     * </ol>
     *
     * <p>
     * The PQC key configuration can specify either a fingerprint or a certificate file path.
     *
     * @param artifactFile the file that was signed
     * @param signatureFile the detached signature file (may contain classic-only or
     *        hybrid signature)
     * @param pqcKeyConfig the PQC key configuration (cert file or fingerprint), or null to skip PQC verification
     * @return a {@link VerificationReport} containing both classic and PQC results
     * @throws IllegalArgumentException if artifactFile or signatureFile is null
     */
    public VerificationReport verify(Path artifactFile, Path signatureFile, PqcKeyConfig pqcKeyConfig) {
        if (artifactFile == null) {
            throw new IllegalArgumentException("artifactFile cannot be null");
        }
        if (signatureFile == null) {
            throw new IllegalArgumentException("signatureFile cannot be null");
        }

        GpgRunner.VerifyResult classic = verifyClassic(artifactFile, signatureFile);

        VerificationResult pqcResult;
        String pqcAlgorithm = null;
        String pqcKeyFp = null;

        if (sq != null && pqcKeyConfig != null) {
            pqcResult = verifyPqc(artifactFile, signatureFile, pqcKeyConfig);
            if (pqcResult == VerificationResult.PASS || pqcResult == VerificationResult.FAIL) {
                pqcAlgorithm = SqRunner.DEFAULT_PQC_ALGORITHM;
                pqcKeyFp = pqcKeyConfig.isFingerprint() ? pqcKeyConfig.fingerprint() : null;
            }
        } else {
            pqcResult = VerificationResult.NOT_PRESENT;
        }

        return new VerificationReport(
                classic.goodSignature() ? VerificationResult.PASS : VerificationResult.FAIL,
                classic.keyId(),
                pqcResult,
                pqcAlgorithm,
                pqcKeyFp);
    }

    private GpgRunner.VerifyResult verifyClassic(Path artifactFile, Path signatureFile) {
        return gpg.verify(artifactFile, signatureFile);
    }

    /**
     * Verifies the PQC signature using the Sequoia command-line tool with the given key configuration.
     *
     * @param artifactFile the file that was signed
     * @param signatureFile the signature file to verify
     * @param config the PQC key configuration (cert file or fingerprint)
     * @return {@link VerificationResult#PASS} if verification succeeds,
     *         {@link VerificationResult#FAIL} otherwise
     */
    private VerificationResult verifyPqc(Path artifactFile, Path signatureFile, PqcKeyConfig config) {
        return verifyPqcBlock(artifactFile, signatureFile,
                (artifact, sig) -> config.isCertFile()
                        ? sq.verifyCertFile(artifact, sig, config.certFilePath())
                        : sq.verify(artifact, sig, config.fingerprint()));
    }

    /**
     * Extracts the PQC block from a combined signature file and verifies it.
     * <p>
     * When the signature file contains multiple armored blocks (classic + PQC),
     * extracts the PQC block (second block) into a temporary file for Sequoia,
     * which only processes the first armored block in a file.
     */
    private VerificationResult verifyPqcBlock(Path artifactFile, Path signatureFile,
            BiPredicate<Path, Path> verifyFn) {
        Path pqcSigFile = null;
        try {
            String content = Files.readString(signatureFile);
            String pqcBlock = AscCombiner.extractBlock(content, 1);
            if (pqcBlock != null) {
                pqcSigFile = Files.createTempFile("pqc-verify-", ".asc");
                Files.writeString(pqcSigFile, pqcBlock);
                signatureFile = pqcSigFile;
            }
            boolean verified = verifyFn.test(artifactFile, signatureFile);
            return verified ? VerificationResult.PASS : VerificationResult.FAIL;
        } catch (IOException e) {
            return VerificationResult.FAIL;
        } finally {
            if (pqcSigFile != null) {
                try {
                    Files.deleteIfExists(pqcSigFile);
                } catch (IOException ignored) {
                }
            }
        }
    }
}
