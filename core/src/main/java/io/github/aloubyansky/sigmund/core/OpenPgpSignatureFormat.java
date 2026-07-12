package io.github.aloubyansky.sigmund.core;

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
 * {@link OpenPgpVerificationUnit} with metadata extracted from the signature packet.
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
     * Checks whether the file contains ASCII-armored OpenPGP data.
     * <p>
     * Reads the file and checks for the presence of a {@code -----BEGIN PGP } marker.
     *
     * @param signatureFile the path to the signature file
     * @return {@code true} if the file contains OpenPGP armored data
     */
    @Override
    public boolean canHandle(Path signatureFile) {
        try {
            String content = Files.readString(signatureFile);
            return content.contains(BEGIN_PGP);
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Parses an ASCII-armored signature file into individually verifiable units.
     * <p>
     * Extracts all armored blocks, inspects each block's signature packet for
     * version, algorithm ID, and issuer fingerprint, and wraps each into an
     * {@link OpenPgpVerificationUnit}.
     *
     * @param signatureFile the path to the {@code .asc} file
     * @return the parsed verification units, one per armored block
     * @throws ToolExecutionException if the file cannot be read
     */
    @Override
    public List<VerificationUnit> parse(Path signatureFile) {
        String content = readFile(signatureFile);
        List<String> blocks = AscCombiner.extractAllBlocks(content);
        List<VerificationUnit> units = new ArrayList<>(blocks.size());
        for (String block : blocks) {
            units.add(parseBlock(block));
        }
        return units;
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

    private OpenPgpVerificationUnit parseBlock(String block) {
        OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(block);
        return new OpenPgpVerificationUnit(
                block,
                info.version(),
                info.issuerFingerprint(),
                info.algorithmId());
    }

    private String readFile(Path file) {
        try {
            return Files.readString(file);
        } catch (IOException e) {
            throw new ToolExecutionException("Failed to read signature file: " + file, e);
        }
    }
}
