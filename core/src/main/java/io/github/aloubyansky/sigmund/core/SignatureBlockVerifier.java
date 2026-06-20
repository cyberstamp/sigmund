package io.github.aloubyansky.sigmund.core;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Verifies individual OpenPGP signature blocks against their respective
 * tools and key stores.
 * <p>
 * Classical (v1-v4) blocks are verified via GPG against the local keyring.
 * v5+ blocks are verified via Sequoia by resolving the issuer certificate
 * from the Sequoia cert store.
 *
 * @see HybridVerifier
 */
public class SignatureBlockVerifier {

    private final GpgRunner gpg;
    private final SqRunner sq;

    public SignatureBlockVerifier(GpgRunner gpg, SqRunner sq) {
        this.gpg = gpg;
        this.sq = sq;
    }

    /**
     * Verifies a signature block by routing it to the appropriate tool
     * based on the OpenPGP version: v1-v4 to GPG, v5+ to Sequoia,
     * undetectable versions to FAIL.
     *
     * @param artifactFile the file that was signed
     * @param block the armored signature block
     * @param pktInfo the pre-inspected packet metadata
     * @return the verification result
     * @throws IOException if a temp file cannot be created
     */
    public SignatureInfo verify(Path artifactFile, String block,
            AscCombiner.SignaturePacketInfo pktInfo) throws IOException {
        int version = pktInfo.version();
        if (version <= 0) {
            return new SignatureInfo(version, null, null, null, VerificationResult.FAIL);
        }
        if (version <= 4) {
            return verifyGpgBlock(artifactFile, block, version);
        }
        return verifySequoiaBlock(artifactFile, block, version,
                pktInfo.issuerFingerprint(), pktInfo.algorithmId());
    }

    /**
     * Verifies a classical GPG signature block.
     *
     * @param artifactFile the file that was signed
     * @param block the armored signature block
     * @param version the OpenPGP signature version
     * @return the verification result
     * @throws IOException if a temp file cannot be created
     */
    public SignatureInfo verifyGpgBlock(Path artifactFile, String block, int version)
            throws IOException {
        return withTempSigFile(block, sigFile -> verifyGpgBlock(artifactFile, sigFile, version));
    }

    /**
     * Verifies a classical GPG signature block using an already-written signature file.
     */
    public SignatureInfo verifyGpgBlock(Path artifactFile, Path sigFile, int version) {
        GpgRunner.VerifyResult result = gpg.verify(artifactFile, sigFile);
        return new SignatureInfo(
                version,
                result.keyId(),
                result.algorithm(),
                result.signerUserId(),
                result.result());
    }

    /**
     * Verifies a v5+ signature block by resolving the issuer certificate
     * from the Sequoia cert store.
     *
     * @param artifactFile the file that was signed
     * @param block the armored signature block
     * @param version the OpenPGP signature version
     * @param fingerprint the issuer fingerprint extracted from the packet, or null
     * @param algoId the public-key algorithm ID from the packet, or -1 if unknown
     * @return the verification result
     * @throws IOException if a temp file cannot be created
     */
    public SignatureInfo verifySequoiaBlock(Path artifactFile, String block, int version,
            String fingerprint, int algoId) throws IOException {
        String algorithm = AscCombiner.algorithmName(algoId);
        if (algorithm == null) {
            algorithm = algoId >= 0 ? "unknown(" + algoId + ")" : null;
        }

        if (sq == null || fingerprint == null) {
            return new SignatureInfo(version, fingerprint, algorithm, null, VerificationResult.SKIPPED);
        }

        SqRunner.CertInfo certInfo = sq.inspectCert(fingerprint);
        if (certInfo == null) {
            return new SignatureInfo(version, fingerprint, algorithm, null, VerificationResult.NO_KEY);
        }

        if (certInfo.algorithm() != null) {
            algorithm = certInfo.algorithm();
        }

        Path certFile = certInfo.certFile();
        if (certFile == null) {
            certFile = sq.findCertFile(fingerprint);
        }
        if (certFile == null) {
            return new SignatureInfo(version, fingerprint, algorithm,
                    certInfo.userId(), VerificationResult.NO_KEY);
        }

        final String algo = algorithm;
        final String userId = certInfo.userId();
        final Path cert = certFile;
        return withTempSigFile(block, sigFile -> {
            boolean verified = sq.verifyCertFile(artifactFile, sigFile, cert);
            return new SignatureInfo(version, fingerprint, algo,
                    userId, verified ? VerificationResult.PASS : VerificationResult.FAIL);
        });
    }

    @FunctionalInterface
    private interface TempFileAction<T> {
        T apply(Path sigFile) throws IOException;
    }

    private static <T> T withTempSigFile(String block, TempFileAction<T> action) throws IOException {
        Path sigFile = null;
        try {
            sigFile = Files.createTempFile("sig-verify-", ".asc");
            Files.writeString(sigFile, block);
            return action.apply(sigFile);
        } finally {
            if (sigFile != null) {
                try {
                    Files.deleteIfExists(sigFile);
                } catch (IOException ignored) {
                }
            }
        }
    }
}
