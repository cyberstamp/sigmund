package dev.cyberstamp.sigmund.core;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;

/**
 * Encapsulates a signature file format's detection, parsing, and combining logic.
 * <p>
 * Each signature format (OpenPGP, Sigstore, etc.) has its own file format, detection
 * rules, and combining semantics. {@code SignatureFormat} keeps the facade and tools
 * format-agnostic — they work with {@link Claim}s parsed from files,
 * not with raw file content.
 *
 * <h2>Format vs tool distinction</h2>
 * <p>
 * A format owns file structure (parsing, detection, combining). A {@link SignatureTool}
 * owns cryptographic operations (signing, verification). Multiple tools can share the
 * same format — for example, GPG and Sequoia both use {@link OpenPgpSignatureFormat}.
 *
 * <h2>Content-based detection</h2>
 * <p>
 * {@link #canHandle(Evidence)} inspects content to detect the format, not just
 * by file extension. This handles cases where file extensions are missing or incorrect.
 *
 * @see SignatureTool#signatureFormat()
 * @see OpenPgpSignatureFormat
 */
public interface SignatureFormat {

    /** Format identifier for OpenPGP signatures. */
    String FORMAT_OPENPGP = "openpgp";

    /**
     * Returns the format name.
     *
     * @return the name (e.g., {@code "openpgp"}, {@code "sigstore"})
     */
    String name();

    /**
     * Returns the conventional file extension for this format.
     *
     * @return the extension including the leading dot (e.g., {@code ".asc"}, {@code ".sigstore.json"})
     */
    String fileExtension();

    /**
     * Checks whether this format can handle the given signature file.
     * <p>
     * Detection is extension-first for performance: if the file name matches
     * {@link #fileExtension()}, returns {@code true} immediately. Otherwise,
     * delegates to {@link #canHandleByContent(Evidence)} for content-based detection.
     *
     * @param evidence the evidence to check
     * @return {@code true} if this format can parse it
     */
    default boolean canHandle(Evidence evidence) {
        if (evidence.file().getFileName().toString().endsWith(fileExtension())) {
            return true;
        }
        return canHandleByContent(evidence);
    }

    /**
     * Checks whether this format can handle the given signature file by inspecting its content.
     * <p>
     * Called by {@link #canHandle(Evidence)} when the file extension does not match.
     * Implementations read the file and inspect its structure.
     *
     * @param evidence the evidence to check
     * @return {@code true} if this format can parse it, judged from its content
     */
    boolean canHandleByContent(Evidence evidence);

    /**
     * Parses a signature file into individually verifiable claims.
     * <p>
     * A single file may produce multiple claims — for example, an OpenPGP {@code .asc}
     * file may contain two armored blocks (classical and PQC), each parsed into a
     * separate {@link OpenPgpClaim}.
     *
     * @param evidence the evidence to parse
     * @return the parsed claims
     * @throws ToolExecutionException if the file cannot be read or parsed
     */
    List<Claim> parse(Evidence evidence);

    /**
     * Returns whether this format supports combining multiple signatures into a single file.
     * <p>
     * OpenPGP supports combining (concatenated armored blocks). Sigstore does not
     * (each signing produces a standalone bundle).
     *
     * @return {@code true} if combining is supported
     */
    default boolean supportsCombining() {
        return false;
    }

    /**
     * Combines multiple signature files into a single output file.
     * <p>
     * Only supported when {@link #supportsCombining()} returns {@code true}.
     * The default implementation accepts a single input (copied unchanged) and
     * rejects multiple inputs.
     *
     * @param signatures the signature files to combine
     * @param output the output file to write
     * @throws UnsupportedOperationException if combining is not supported and
     *         more than one signature is provided
     * @throws ToolExecutionException if the files cannot be read or written
     */
    default void combine(List<Path> signatures, Path output) {
        if (signatures.size() == 1) {
            try {
                Files.copy(signatures.get(0), output, StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException e) {
                throw new ToolExecutionException("Failed to copy signature file", e);
            }
            return;
        }
        throw new UnsupportedOperationException(name() + " format does not support combining signatures");
    }
}
