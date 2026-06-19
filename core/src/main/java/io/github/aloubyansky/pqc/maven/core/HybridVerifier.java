package io.github.aloubyansky.pqc.maven.core;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Verifies signatures in an ASC file containing one or more OpenPGP signature blocks.
 * <p>
 * Each armored block is parsed to determine its OpenPGP version and dispatched
 * to the appropriate verifier: GPG for classical signatures (v1-v4) and
 * Sequoia for v5+ signatures (both PQC and non-PQC).
 *
 * @see HybridSigner
 * @see VerificationReport
 * @see SignatureBlockVerifier
 */
public class HybridVerifier {

    private final SignatureBlockVerifier blockVerifier;

    /**
     * Constructs a HybridVerifier with specified GPG and Sequoia configuration.
     *
     * @param gpg the GPG runner instance for classic signature verification
     * @param sq the Sequoia runner instance for v5+ verification, or null to skip
     * @throws IllegalArgumentException if gpg is null
     */
    public HybridVerifier(GpgRunner gpg, SqRunner sq) {
        if (gpg == null) {
            throw new IllegalArgumentException("gpg cannot be null");
        }
        this.blockVerifier = new SignatureBlockVerifier(gpg, sq);
    }

    /**
     * Verifies all signature blocks in the specified signature file.
     *
     * @param artifactFile the file that was signed
     * @param signatureFile the detached signature file (may contain any number of signature blocks)
     * @return a {@link VerificationReport} containing results for each signature block
     * @throws IllegalArgumentException if artifactFile or signatureFile is null
     * @throws IOException if the signature file cannot be read
     */
    public VerificationReport verify(Path artifactFile, Path signatureFile) throws IOException {
        if (artifactFile == null) {
            throw new IllegalArgumentException("artifactFile cannot be null");
        }
        if (signatureFile == null) {
            throw new IllegalArgumentException("signatureFile cannot be null");
        }

        String ascContent = Files.readString(signatureFile);
        if (ascContent.isBlank()) {
            return new VerificationReport(List.of());
        }

        List<String> blocks = AscCombiner.extractAllBlocks(ascContent);
        List<SignatureInfo> signatures = new ArrayList<>();

        for (String block : blocks) {
            AscCombiner.SignaturePacketInfo pktInfo = AscCombiner.inspectSignaturePacket(block);
            signatures.add(blockVerifier.verify(artifactFile, block, pktInfo));
        }

        return new VerificationReport(signatures);
    }
}
