package io.github.aloubyansky.pqc.maven.cli;

import io.github.aloubyansky.pqc.maven.core.GpgRunner;
import io.github.aloubyansky.pqc.maven.core.HybridVerifier;
import io.github.aloubyansky.pqc.maven.core.PqcKeyConfig;
import io.github.aloubyansky.pqc.maven.core.SqRunner;
import io.github.aloubyansky.pqc.maven.core.VerificationReport;
import io.github.aloubyansky.pqc.maven.core.VerificationResult;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.Callable;
import picocli.CommandLine;

/**
 * Command-line interface for verifying hybrid signatures.
 * <p>
 * This command verifies both classical GPG and post-quantum cryptographic
 * signatures in a hybrid signature file. It supports two verification modes:
 * <ul>
 * <li><b>Transitional mode</b> (default): Only the classical GPG signature must
 * pass. PQC signature is optional.</li>
 * <li><b>Strict mode</b> (--strict flag): Both GPG and PQC signatures must pass.</li>
 * </ul>
 *
 * <p>
 * Example usage:
 *
 * <pre>
 * # Verify with transitional mode (classic signature sufficient)
 * pqc-sign verify --file artifact.jar --signature artifact.jar.asc
 *
 * # Verify with strict mode (both signatures required)
 * pqc-sign verify --file artifact.jar --signature artifact.jar.asc --strict
 *
 * # Verify against a specific PQC key
 * pqc-sign verify --file artifact.jar \
 *                 --signature artifact.jar.asc \
 *                 --pqc-fingerprint ABC123DEF456...
 *
 * # Verify with custom Sequoia home
 * pqc-sign verify --file artifact.jar \
 *                 --signature artifact.jar.asc \
 *                 --sq-home /path/to/sq-home
 * </pre>
 *
 * <p>
 * The command outputs a detailed verification report showing the status of both
 * classical and PQC signatures, and exits with:
 * <ul>
 * <li>Exit code 0: Verification passed (according to the selected mode)</li>
 * <li>Exit code 1: Verification failed</li>
 * </ul>
 *
 * <p>
 * Requirements:
 * <ul>
 * <li>{@code gpg} executable must be available on the system PATH</li>
 * <li>{@code sq} executable must be available for PQC verification (optional in
 * transitional mode)</li>
 * <li>The signer's public keys must be available in the respective keystores</li>
 * </ul>
 *
 *
 * @see HybridVerifier
 * @see VerificationReport
 */
@CommandLine.Command(name = "verify", description = "Verify a hybrid signature", mixinStandardHelpOptions = true)
public class VerifyCommand implements Callable<Integer> {

    /**
     * The artifact file to verify.
     * <p>
     * This is the file that was originally signed and whose signature will be
     * verified.
     *
     */
    @CommandLine.Option(names = { "--file" }, required = true, description = "Artifact file to verify")
    private String file;

    /**
     * The detached signature file to verify against.
     * <p>
     * This is typically an ASCII-armored signature file with the {@code .asc}
     * extension (e.g., {@code artifact.jar.asc}).
     *
     */
    @CommandLine.Option(names = { "--signature" }, required = true, description = "Signature file (.asc)")
    private String signature;

    /**
     * The expected PQC key fingerprint for signature verification.
     * <p>
     * If specified, the PQC signature will be verified against this specific key.
     * If not specified, PQC verification will succeed as long as any valid PQC
     * signature is present (without checking the signer identity).
     *
     */
    @CommandLine.Option(names = { "--pqc-fingerprint" }, description = "Expected PQC key fingerprint (optional)")
    private String pqcFingerprint;

    /**
     * Path to a PQC certificate file for signature verification.
     * <p>
     * When set, PQC verification uses this certificate file directly instead of
     * looking up a key by fingerprint in the Sequoia keystore.
     * Takes precedence over {@link #pqcFingerprint}.
     *
     */
    @CommandLine.Option(names = { "--pqc-cert-file" }, description = "PQC certificate file for verification (optional)")
    private String pqcCertFile;

    @CommandLine.Mixin
    private SqHomeMixin sqHomeMixin;

    /**
     * Whether to require both signatures to pass (strict mode).
     * <p>
     * In strict mode, both the classical GPG signature and the PQC signature must
     * pass verification. This provides quantum-resistant security guarantees.
     *
     * <p>
     * In transitional mode (default), only the classical GPG signature is required
     * to pass. This allows for gradual migration to PQC signatures while maintaining
     * backward compatibility.
     *
     */
    @CommandLine.Option(names = { "--strict" }, description = "Require both GPG and PQC signatures to pass (default: false)")
    private boolean strict;

    /**
     * Executes the verification command.
     * <p>
     * This method performs the following steps:
     * <ol>
     * <li>Resolves file paths (artifact, signature, Sequoia home)</li>
     * <li>Creates an {@link SqRunner} instance (if available)</li>
     * <li>Creates a {@link HybridVerifier}</li>
     * <li>Performs verification and generates a report</li>
     * <li>Prints the verification report</li>
     * <li>Determines the exit code based on the verification mode</li>
     * </ol>
     *
     * <p>
     * On error, catches all exceptions, prints a user-friendly error message to
     * stderr, and returns exit code 1.
     *
     *
     * @return 0 if verification passes, 1 if verification fails or an error occurs
     */
    @Override
    public Integer call() {
        try {
            Path artifactFile = resolveArtifactFile();
            Path signatureFile = resolveSignatureFile();

            GpgRunner gpgRunner = new GpgRunner();
            SqRunner sqRunner = createSqRunnerIfAvailable();
            HybridVerifier verifier = new HybridVerifier(gpgRunner, sqRunner);

            VerificationReport report = verifier.verify(artifactFile, signatureFile, buildPqcKeyConfig());

            printVerificationReport(report);

            return determineExitCode(report);
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
     * Resolves the signature file path from the --signature option.
     *
     * @return the signature file path
     */
    private Path resolveSignatureFile() {
        return Paths.get(signature);
    }

    /**
     * Builds the PQC key configuration from the command-line options.
     * <p>
     * {@code --pqc-cert-file} takes precedence over {@code --pqc-fingerprint}.
     *
     * @return the PQC key configuration, or null if neither option is specified
     */
    private PqcKeyConfig buildPqcKeyConfig() {
        if (pqcCertFile != null && !pqcCertFile.isEmpty()) {
            return PqcKeyConfig.certFile(sqHomeMixin.expandTilde(pqcCertFile));
        }
        if (pqcFingerprint != null && !pqcFingerprint.isEmpty()) {
            return PqcKeyConfig.fingerprint(pqcFingerprint);
        }
        return null;
    }

    /**
     * Creates an {@link SqRunner} instance if the sq executable is available.
     * <p>
     * This method checks if {@code sq} is available using {@link SqRunner#isAvailable()}.
     * If it is not available, {@code null} is returned, which will cause the
     * {@link HybridVerifier} to skip PQC verification and report
     * {@link VerificationResult#NOT_PRESENT} for the PQC component.
     *
     *
     * @return a configured SqRunner instance, or null if sq is not available
     */
    private SqRunner createSqRunnerIfAvailable() {
        if (!SqRunner.isAvailable()) {
            return null;
        }
        Path sqHomeDir = sqHomeMixin.resolveSequoiaHome();
        return new SqRunner(sqHomeDir);
    }

    /**
     * Prints the verification report to stdout.
     * <p>
     * The report includes:
     * <ul>
     * <li>Classic (GPG) signature verification result</li>
     * <li>PQC signature verification result</li>
     * <li>Overall assessment based on the verification mode</li>
     * </ul>
     *
     *
     * @param report the verification report to print
     */
    private void printVerificationReport(VerificationReport report) {
        System.out.println(report.format());
    }

    /**
     * Determines the exit code based on the verification report and mode.
     * <p>
     * In strict mode, both signatures must pass (exit code 0 only if
     * {@link VerificationReport#isStrictPass()} returns true).
     *
     * <p>
     * In transitional mode, only the classical signature must pass (exit code 0 if
     * {@link VerificationReport#isTransitionalPass()} returns true).
     *
     *
     * @param report the verification report
     * @return 0 if verification passed according to the mode, 1 otherwise
     */
    private int determineExitCode(VerificationReport report) {
        if (strict) {
            return report.isStrictPass() ? 0 : 1;
        } else {
            return report.isTransitionalPass() ? 0 : 1;
        }
    }

    /**
     * Prints a user-friendly error message to stderr.
     * <p>
     * This method extracts the most relevant error message from the exception
     * chain and displays it in a clear format.
     *
     *
     * @param e the exception that occurred during verification
     */
    private void printErrorMessage(Exception e) {
        System.err.println("Error verifying signature:");
        System.err.println("  " + extractErrorMessage(e));
        System.err.println();
        System.err.println("Ensure that:");
        System.err.println("  - The 'gpg' command is installed and available");
        System.err.println("  - The signer's public GPG key is in your keyring");
        System.err.println("  - For PQC verification: the 'sq' command is installed");
        System.err.println("  - The artifact and signature files exist and are readable");
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
