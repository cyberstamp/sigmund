package io.github.aloubyansky.pqc.maven.cli;

import io.github.aloubyansky.pqc.maven.core.GpgRunner;
import io.github.aloubyansky.pqc.maven.core.HybridSigner;
import io.github.aloubyansky.pqc.maven.core.SqRunner;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.Callable;
import picocli.CommandLine;

/**
 * Command-line interface for creating hybrid signatures.
 * <p>
 * This command creates a hybrid signature that combines classical GPG (v4 packet)
 * and post-quantum cryptography (v6 packet using a PQC hybrid cipher suite) into a
 * single ASCII-armored signature file. The resulting signature provides both
 * classical and quantum-resistant security.
 *
 * <p>
 * Example usage:
 *
 * <pre>
 * # Sign with PQC only (using default GPG key)
 * pqc-sign sign --file artifact.jar --pqc-fingerprint ABC123DEF456...
 *
 * # Sign with specific GPG key and PQC key
 * pqc-sign sign --file artifact.jar \
 *               --pqc-fingerprint ABC123DEF456... \
 *               --gpg-key user@example.org
 *
 * # Sign with custom output path and Sequoia home
 * pqc-sign sign --file artifact.jar \
 *               --pqc-fingerprint ABC123DEF456... \
 *               --output custom-signature.asc \
 *               --sq-home /path/to/sq-home
 * </pre>
 *
 * <p>
 * The command outputs the path to the generated signature file on success.
 *
 * <p>
 * Requirements:
 * <ul>
 * <li>{@code gpg} executable must be available on the system PATH</li>
 * <li>{@code sq} executable must be available on the system PATH</li>
 * <li>A GPG key must be configured (either default or specified via --gpg-key)</li>
 * <li>The PQC key must exist in the Sequoia home directory</li>
 * </ul>
 *
 *
 * @see HybridSigner
 * @see GpgRunner
 * @see SqRunner
 */
@CommandLine.Command(name = "sign", description = "Create a hybrid signature combining GPG and PQC", mixinStandardHelpOptions = true)
public class SignCommand implements Callable<Integer> {

    /**
     * The artifact file to sign.
     * <p>
     * This is typically a Maven artifact (e.g., {@code artifact.jar}), but can be
     * any file that needs to be signed.
     *
     */
    @CommandLine.Option(names = { "--file" }, required = true, description = "Artifact file to sign")
    private String file;

    /**
     * The PQC key fingerprint to use for signing.
     * <p>
     * This should be the 64-character hexadecimal fingerprint returned by the
     * {@code keygen} command. The key must exist in the Sequoia home directory.
     *
     */
    @CommandLine.Option(names = { "--pqc-fingerprint" }, required = true, description = "PQC key fingerprint (64-char hex)")
    private String pqcFingerprint;

    /**
     * The GPG key identifier to use for signing.
     * <p>
     * This can be a key ID, fingerprint, or email address associated with the GPG
     * key. If not specified, GPG will use the default key configured in the user's
     * GPG keyring.
     *
     */
    @CommandLine.Option(names = { "--gpg-key" }, description = "GPG key ID/email (default: use GPG's default key)")
    private String gpgKey;

    @CommandLine.Mixin
    private SqHomeMixin sqHomeMixin;

    /**
     * The output path for the generated signature file.
     * <p>
     * If not specified, the signature will be written to {@code <file>.asc}
     * (e.g., {@code artifact.jar.asc} for {@code artifact.jar}).
     *
     */
    @CommandLine.Option(names = { "--output" }, description = "Output signature file path (default: <file>.asc)")
    private String output;

    /**
     * Executes the signing command.
     * <p>
     * This method performs the following steps:
     * <ol>
     * <li>Resolves file paths (artifact, output, Sequoia home)</li>
     * <li>Creates {@link GpgRunner} and {@link SqRunner} instances</li>
     * <li>Creates a {@link HybridSigner} using the factory method</li>
     * <li>Generates the hybrid signature</li>
     * <li>Prints the output file path</li>
     * </ol>
     *
     * <p>
     * On error, catches all exceptions, prints a user-friendly error message to
     * stderr, and returns exit code 1.
     *
     *
     * @return 0 on success, 1 on error
     */
    @Override
    public Integer call() {
        try {
            Path artifactFile = resolveArtifactFile();
            Path outputFile = resolveOutputFile(artifactFile);

            GpgRunner gpgSigner = createGpgRunner();
            SqRunner sqRunner = createSqRunner();
            HybridSigner signer = new HybridSigner(gpgSigner, sqRunner, pqcFingerprint);
            signer.sign(artifactFile, outputFile);

            printSuccessMessage(outputFile);
            return 0;
        } catch (Exception e) {
            printErrorMessage(e);
            return 1;
        }
    }

    /**
     * Resolves the artifact file path from the --file option.
     *
     * @return the artifact file path
     */
    private Path resolveArtifactFile() {
        return Paths.get(file);
    }

    /**
     * Resolves the output signature file path.
     * <p>
     * If {@link #output} is specified, it is used as-is. Otherwise, the default
     * path is {@code <artifactFile>.asc}.
     *
     *
     * @param artifactFile the artifact file being signed
     * @return the output signature file path
     */
    private Path resolveOutputFile(Path artifactFile) {
        if (output != null && !output.isEmpty()) {
            return Paths.get(output);
        }
        return Paths.get(artifactFile.toString() + ".asc");
    }

    /**
     * Creates a {@link GpgRunner} instance with the configured GPG key.
     * <p>
     * If {@link #gpgKey} is specified, it is used as the key identifier. Otherwise,
     * {@code null} is passed, which causes GPG to use its default key.
     *
     *
     * @return a configured GpgRunner instance
     */
    private GpgRunner createGpgRunner() {
        return new GpgRunner(gpgKey);
    }

    /**
     * Creates an {@link SqRunner} instance with the configured Sequoia home directory.
     *
     * @return a configured SqRunner instance
     */
    private SqRunner createSqRunner() {
        Path sqHomeDir = sqHomeMixin.resolveSequoiaHome();
        return new SqRunner(sqHomeDir);
    }

    /**
     * Prints a success message with the output signature file path.
     * <p>
     * Example output:
     *
     * <pre>
     * Hybrid signature created successfully!
     *
     * Signature file: /path/to/artifact.jar.asc
     * </pre>
     *
     *
     * @param outputFile the path to the generated signature file
     */
    private void printSuccessMessage(Path outputFile) {
        System.out.println("Hybrid signature created successfully!");
        System.out.println();
        System.out.println("Signature file: " + outputFile.toAbsolutePath());
    }

    /**
     * Prints a user-friendly error message to stderr.
     * <p>
     * This method extracts the most relevant error message from the exception
     * chain and displays it in a clear format.
     *
     *
     * @param e the exception that occurred during signing
     */
    private void printErrorMessage(Exception e) {
        System.err.println("Error creating signature:");
        System.err.println("  " + extractErrorMessage(e));
        System.err.println();
        System.err.println("Ensure that:");
        System.err.println("  - The 'gpg' and 'sq' commands are installed and available");
        System.err.println("  - You have a valid GPG key configured");
        System.err.println("  - The PQC key exists in the Sequoia home directory");
        System.err.println("  - The artifact file exists and is readable");
    }

    /**
     * Extracts a user-friendly error message from an exception.
     * <p>
     * If the exception has a message, it is returned. Otherwise, the simple
     * class name of the exception is returned.
     *
     *
     * @param e the exception to extract the message from
     * @return a user-friendly error message
     */
    private String extractErrorMessage(Exception e) {
        String message = e.getMessage();
        if (message != null && !message.isEmpty()) {
            return message;
        }
        return e.getClass().getSimpleName();
    }
}
