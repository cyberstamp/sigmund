package io.github.aloubyansky.pqc.maven.core;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Verifies hybrid signatures containing both classic GPG and PQC components.
 * <p>
 * This class reads the signature file, classifies each armored block by its
 * OpenPGP packet version (v4 = classical, v6 = PQC), and dispatches each
 * block to the appropriate verifier.
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
     * Reads the signature file, classifies each armored block by OpenPGP version,
     * and dispatches:
     * <ul>
     * <li>v4 blocks to GPG for classical verification</li>
     * <li>v6 blocks to Sequoia for PQC verification</li>
     * </ul>
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

        String ascContent;
        try {
            ascContent = Files.readString(signatureFile);
        } catch (IOException e) {
            return new VerificationReport(
                    VerificationResult.FAIL, null,
                    VerificationResult.FAIL, null, null);
        }

        List<String> blocks = AscCombiner.extractAllBlocks(ascContent);

        String classicBlock = null;
        String pqcBlock = null;
        for (String block : blocks) {
            int version = AscCombiner.detectSignatureVersion(block);
            if (version > 0 && version <= 4 && classicBlock == null) {
                classicBlock = block;
            } else if (version > 4 && pqcBlock == null) {
                pqcBlock = block;
            } else if (version <= 0 && pqcBlock == null) {
                pqcBlock = block;
            }
        }

        GpgRunner.VerifyResult classicResult = verifyClassicBlock(artifactFile, signatureFile, classicBlock);

        VerificationResult pqcResult;
        String pqcAlgorithm = null;
        String pqcKeyFp = null;

        if (pqcBlock != null && sq != null && pqcKeyConfig != null) {
            pqcResult = verifyPqcBlock(artifactFile, pqcBlock, pqcKeyConfig);
            if (pqcResult == VerificationResult.PASS || pqcResult == VerificationResult.FAIL) {
                pqcAlgorithm = SqRunner.DEFAULT_PQC_ALGORITHM;
                pqcKeyFp = pqcKeyConfig.isFingerprint() ? pqcKeyConfig.fingerprint() : null;
            }
        } else if (pqcBlock == null) {
            pqcResult = VerificationResult.NOT_PRESENT;
        } else {
            pqcResult = VerificationResult.SKIPPED;
        }

        return new VerificationReport(
                classicResult != null ? classicResult.result() : VerificationResult.NOT_PRESENT,
                classicResult != null ? classicResult.keyId() : null,
                pqcResult,
                pqcAlgorithm,
                pqcKeyFp);
    }

    /**
     * Verifies a classical signature block. If a v4 block was found, GPG is invoked
     * against the original signature file (GPG reads the first compatible block).
     * If no v4 block was found, returns null.
     */
    private GpgRunner.VerifyResult verifyClassicBlock(Path artifactFile, Path signatureFile, String classicBlock) {
        if (classicBlock == null) {
            return null;
        }
        return gpg.verify(artifactFile, signatureFile);
    }

    /**
     * Writes the PQC block to a temporary file and verifies it with Sequoia.
     */
    private VerificationResult verifyPqcBlock(Path artifactFile, String pqcBlock, PqcKeyConfig config) {
        Path pqcSigFile = null;
        try {
            pqcSigFile = Files.createTempFile("pqc-verify-", ".asc");
            Files.writeString(pqcSigFile, pqcBlock);

            boolean verified = config.isCertFile()
                    ? sq.verifyCertFile(artifactFile, pqcSigFile, config.certFilePath())
                    : sq.verify(artifactFile, pqcSigFile, config.fingerprint());

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
