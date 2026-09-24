package dev.cyberstamp.sigmund.core;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * OpenPGP ASCII-armored signature format handler.
 * <p>
 * Wraps {@link AscCombiner} for block extraction, packet inspection, and combining.
 * Shared by all OpenPGP tools (GPG, Sequoia, future Bouncy Castle backend).
 * <p>
 * A single {@code .asc} file may contain multiple armored blocks (e.g., a classical
 * v4 signature followed by a PQC v6 signature). Each block is parsed into a separate
 * {@link OpenPgpClaim} with metadata extracted from the signature packet.
 *
 * @see AscCombiner
 */
public class OpenPgpSignatureFormat implements SignatureFormat {

    private static final String BEGIN_PGP = "-----BEGIN PGP ";

    /**
     * Creates a new OpenPGP signature format handler.
     */
    public OpenPgpSignatureFormat() {
    }

    @Override
    public String name() {
        return FORMAT_OPENPGP;
    }

    @Override
    public String fileExtension() {
        return ".asc";
    }

    /**
     * Checks whether the evidence contains ASCII-armored OpenPGP data.
     *
     * <p>
     * Looks for a {@code -----BEGIN PGP } marker in content that was already read. Called by
     * {@link SignatureFormat#canHandle(Evidence)} when the file extension does not match.
     *
     * @param evidence the evidence to check
     * @return {@code true} if it contains OpenPGP armored data
     */
    @Override
    public boolean canHandleByContent(Evidence evidence) {
        return evidence.text().contains(BEGIN_PGP);
    }

    /**
     * Parses ASCII-armored evidence into individually verifiable claims.
     *
     * <p>
     * Extracts all armored blocks, inspects each block's signature packet for version,
     * algorithm ID, issuer fingerprint and creation time, and wraps each into an
     * {@link OpenPgpClaim}. A hybrid {@code .asc} carrying a classic and a post-quantum
     * block therefore yields two claims, verified independently.
     *
     * @param evidence the evidence to parse
     * @return the parsed claims, one per armored block
     */
    @Override
    public List<Claim> parse(Evidence evidence) {
        List<String> blocks = AscCombiner.extractAllBlocks(evidence.text());
        List<Claim> claims = new ArrayList<>(blocks.size());
        for (String block : blocks) {
            claims.add(parseBlock(block));
        }
        return claims;
    }

    @Override
    public boolean supportsCombining() {
        return true;
    }

    /**
     * Combines multiple OpenPGP signature files into a single output file
     * by concatenating their armored blocks.
     *
     * @param signatures the signature files to combine
     * @param output the output file to write
     * @throws ToolExecutionException if files cannot be read or written
     */
    @Override
    public void combine(List<Path> signatures, Path output) {
        try {
            var sb = new StringBuilder();
            for (Path sig : signatures) {
                String content = Files.readString(sig);
                if (!sb.isEmpty()) {
                    sb.append('\n');
                }
                sb.append(content.stripTrailing());
            }
            sb.append('\n');
            Files.writeString(output, sb.toString());
        } catch (IOException e) {
            throw new ToolExecutionException("Failed to combine OpenPGP signatures", e);
        }
    }

    private OpenPgpClaim parseBlock(String block) {
        OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(block);
        return new OpenPgpClaim(
                block,
                info.version(),
                info.issuerFingerprint(),
                info.algorithmId(),
                info.creationTime());
    }

}
