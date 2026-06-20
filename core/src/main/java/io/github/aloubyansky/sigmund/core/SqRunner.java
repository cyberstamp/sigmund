package io.github.aloubyansky.sigmund.core;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Wrapper for the Sequoia (sq) command-line tool for PQC key generation,
 * signing, verification, and certificate export.
 * <p>
 * This class provides a Java interface to Sequoia's post-quantum cryptography
 * capabilities, using hybrid cipher suites as defined in RFC 9580. The default
 * cipher suite is {@value #DEFAULT_CIPHER_SUITE} (configurable via
 * {@link #generateKey(String, String)}). All operations are isolated to a
 * specific Sequoia home directory via the SEQUOIA_HOME environment variable.
 *
 * <p>
 * Example usage:
 *
 * <pre>
 * {
 *     &#64;code
 *     // Initialize with a dedicated Sequoia home directory
 *     Path sqHome = Path.of("/tmp/my-sq-keys");
 *     SqRunner sq = new SqRunner(sqHome);
 *
 *     // Generate a PQC key
 *     String fingerprint = sq.generateKey("Alice &lt;alice@example.com&gt;");
 *
 *     // Sign an artifact
 *     String signature = sq.sign(
 *             Path.of("artifact.jar"),
 *             Path.of("artifact.jar.sig"),
 *             fingerprint);
 *
 *     // Verify the signature
 *     boolean valid = sq.verify(
 *             Path.of("artifact.jar"),
 *             Path.of("artifact.jar.sig"),
 *             fingerprint);
 *
 *     // Export the certificate for distribution
 *     String cert = sq.exportCert(fingerprint);
 * }
 * </pre>
 * <p>
 * Note: This class requires the {@code sq} executable to be available on the
 * system PATH or at the location specified via the constructor.
 *
 *
 * @see #isAvailable()
 */
public class SqRunner {

    public static final String DEFAULT_CIPHER_SUITE = "mldsa87-ed448";
    public static final String DEFAULT_PQC_ALGORITHM = "ML-DSA-87+Ed448";

    private static final Pattern FINGERPRINT_PATTERN = Pattern.compile("(?i)(?:fingerprint:?\\s*)?([0-9A-F]{64})");
    private static final Pattern INSPECT_ALGO_PATTERN = Pattern.compile("Public-key algo:\\s+(.+)");
    private static final Pattern INSPECT_USERID_PATTERN = Pattern.compile("UserID:\\s+(.+)");
    private static final String SEQUOIA_HOME = "SEQUOIA_HOME";

    private final String sqExecutable;
    private final Path sequoiaHome;

    /**
     * Returns the default Sequoia home directory ({@code ~/.local/share/sequoia}).
     *
     * @return the default path, or null if {@code user.home} is not set
     */
    public static Path defaultHome() {
        String userHome = System.getProperty("user.home");
        if (userHome == null || userHome.isEmpty()) {
            return null;
        }
        return Path.of(userHome, ".local", "share", "sequoia");
    }

    /**
     * Constructs an SqRunner using the default "sq" executable.
     *
     * @param sequoiaHome the directory to use as SEQUOIA_HOME for key/cert storage
     * @throws IllegalArgumentException if sequoiaHome is null
     */
    public SqRunner(Path sequoiaHome) {
        this("sq", sequoiaHome);
    }

    /**
     * Constructs an SqRunner with a custom sq executable path.
     *
     * @param sqExecutable the path to the sq executable (e.g., "sq" or "/usr/local/bin/sq")
     * @param sequoiaHome the directory to use as SEQUOIA_HOME for key/cert storage
     * @throws IllegalArgumentException if sqExecutable or sequoiaHome is null, or if
     *         sqExecutable is empty
     */
    public SqRunner(String sqExecutable, Path sequoiaHome) {
        if (sqExecutable == null || sqExecutable.isEmpty()) {
            throw new IllegalArgumentException("sqExecutable cannot be null or empty");
        }
        if (sequoiaHome == null) {
            throw new IllegalArgumentException("sequoiaHome cannot be null");
        }
        this.sqExecutable = sqExecutable;
        this.sequoiaHome = sequoiaHome;
    }

    /**
     * Generates a new PQC key using the default cipher suite ({@value #DEFAULT_CIPHER_SUITE}).
     *
     * @param userId the user ID for the key (e.g., "Alice &lt;alice@example.com&gt;")
     * @return the 64-character hexadecimal fingerprint of the generated key
     * @throws IllegalArgumentException if userId is null or empty
     * @throws RuntimeException if the sq command fails
     * @throws IllegalStateException if the fingerprint cannot be parsed from the output
     * @see #generateKey(String, String)
     */
    public String generateKey(String userId) {
        return generateKey(userId, DEFAULT_CIPHER_SUITE);
    }

    /**
     * Generates a new PQC key using the specified cipher suite.
     * <p>
     * This method runs:
     * {@code sq key generate --userid <userId> --cipher-suite <cipherSuite>
     * --profile rfc9580 --own-key}
     *
     * <p>
     * The key is stored in the SEQUOIA_HOME directory and can be used for signing
     * operations via the returned fingerprint.
     *
     * @param userId the user ID for the key (e.g., "Alice &lt;alice@example.com&gt;")
     * @param cipherSuite the Sequoia cipher suite identifier
     *        (e.g., {@value #DEFAULT_CIPHER_SUITE})
     * @return the 64-character hexadecimal fingerprint of the generated key
     * @throws IllegalArgumentException if userId or cipherSuite is null or empty
     * @throws RuntimeException if the sq command fails
     * @throws IllegalStateException if the fingerprint cannot be parsed from the output
     */
    public String generateKey(String userId, String cipherSuite) {
        if (userId == null || userId.isEmpty()) {
            throw new IllegalArgumentException("userId cannot be null or empty");
        }
        if (cipherSuite == null || cipherSuite.isEmpty()) {
            throw new IllegalArgumentException("cipherSuite cannot be null or empty");
        }

        String[] args = {
                "key", "generate",
                "--userid", userId,
                "--cipher-suite", cipherSuite,
                "--profile", "rfc9580",
                "--own-key",
                "--without-password"
        };

        CliTool.Result result = runSq(args);
        if (result.exitCode() != 0) {
            throw new RuntimeException("'" + formatCommand(args)
                    + "' failed with exit code " + result.exitCode()
                    + (result.stderr().isEmpty() ? "" : ": " + result.stderr().trim()));
        }
        String combinedOutput = result.stdout() + "\n" + result.stderr();
        return extractFingerprint(combinedOutput);
    }

    /**
     * Creates a detached signature for the specified artifact file.
     * <p>
     * This method runs:
     * {@code sq sign --detached --signer <fingerprint> --signature-file <outputSig>
     * <artifactFile>}
     *
     *
     * @param artifactFile the file to sign
     * @param outputSig the path where the signature file will be written
     * @param fingerprint the fingerprint of the signing key
     * @return the armored signature content as a String
     * @throws IllegalArgumentException if any parameter is null or if fingerprint is empty
     * @throws RuntimeException if the sq command fails
     * @throws java.io.UncheckedIOException if reading the signature file fails
     */
    public String sign(Path artifactFile, Path outputSig, String fingerprint) {
        if (artifactFile == null) {
            throw new IllegalArgumentException("artifactFile cannot be null");
        }
        if (outputSig == null) {
            throw new IllegalArgumentException("outputSig cannot be null");
        }
        if (fingerprint == null || fingerprint.isEmpty()) {
            throw new IllegalArgumentException("fingerprint cannot be null or empty");
        }

        // --signature-file implies detached signing (no --detached flag needed)
        String[] args = {
                "sign",
                "--signer", fingerprint,
                "--signature-file", outputSig.toString(),
                artifactFile.toString()
        };

        CliTool.Result result = runSq(args);
        if (result.exitCode() != 0) {
            throw new RuntimeException("'" + formatCommand(args)
                    + "' failed with exit code " + result.exitCode()
                    + (result.stderr().isEmpty() ? "" : ": " + result.stderr().trim()));
        }
        return readSignatureFile(outputSig);
    }

    /**
     * Verifies a detached signature for the specified artifact file.
     * <p>
     * This method runs:
     * {@code sq verify --signer <fingerprint> --signature-file <signatureFile>
     * <artifactFile>}
     *
     *
     * @param artifactFile the file that was signed
     * @param signatureFile the detached signature file
     * @param signerFingerprint the expected signer's fingerprint, or null to skip
     *        signer verification
     * @return true if the signature is valid, false otherwise
     * @throws IllegalArgumentException if artifactFile or signatureFile is null
     */
    public boolean verify(Path artifactFile, Path signatureFile, String signerFingerprint) {
        if (artifactFile == null) {
            throw new IllegalArgumentException("artifactFile cannot be null");
        }
        if (signatureFile == null) {
            throw new IllegalArgumentException("signatureFile cannot be null");
        }

        String[] args = buildVerifyCommand(artifactFile, signatureFile, signerFingerprint);
        return runSq(args).exitCode() == 0;
    }

    /**
     * Verifies a detached signature for the specified artifact file using a certificate file.
     * <p>
     * This method runs:
     * {@code sq verify --signer-file <certFile> --signature-file <signatureFile>
     * <artifactFile>}
     *
     *
     * @param artifactFile the file that was signed
     * @param signatureFile the detached signature file
     * @param certFile the certificate file containing the signer's public key
     * @return true if the signature is valid, false otherwise
     * @throws IllegalArgumentException if artifactFile, signatureFile, or certFile is null
     */
    public boolean verifyCertFile(Path artifactFile, Path signatureFile, Path certFile) {
        if (artifactFile == null) {
            throw new IllegalArgumentException("artifactFile cannot be null");
        }
        if (signatureFile == null) {
            throw new IllegalArgumentException("signatureFile cannot be null");
        }
        if (certFile == null) {
            throw new IllegalArgumentException("certFile cannot be null");
        }

        String[] args = {
                "verify",
                "--signer-file", certFile.toString(),
                "--signature-file", signatureFile.toString(),
                artifactFile.toString()
        };

        return runSq(args).exitCode() == 0;
    }

    /**
     * Exports the certificate for the specified key fingerprint.
     * <p>
     * This method runs:
     * {@code sq cert export --cert <fingerprint>}
     *
     * <p>
     * The exported certificate can be distributed to others for signature verification.
     *
     *
     * @param fingerprint the fingerprint of the certificate to export
     * @return the armored certificate as a String
     * @throws IllegalArgumentException if fingerprint is null or empty
     * @throws RuntimeException if the sq command fails
     */
    public String exportCert(String fingerprint) {
        if (fingerprint == null || fingerprint.isEmpty()) {
            throw new IllegalArgumentException("fingerprint cannot be null or empty");
        }

        String[] args = {
                "cert", "export",
                "--cert", fingerprint
        };

        CliTool.Result result = runSq(args);
        if (result.exitCode() != 0) {
            throw new RuntimeException("'" + formatCommand(args)
                    + "' failed with exit code " + result.exitCode()
                    + (result.stderr().isEmpty() ? "" : ": " + result.stderr().trim()));
        }
        return result.stdout();
    }

    /**
     * Information extracted from a certificate in the Sequoia store.
     *
     * @param algorithm the public-key algorithm (e.g., "ML-DSA-65+Ed25519", "RSA")
     * @param userId the primary user ID (e.g., "Name &lt;email&gt;"), or null if not present
     * @param certFile the cert file in the cert-d store, or null if resolved via {@code --cert}
     */
    public record CertInfo(String algorithm, String userId, Path certFile) {
    }

    /**
     * Inspects a certificate in the Sequoia store by fingerprint (primary key or
     * subkey) and returns its algorithm and user ID.
     * <p>
     * First tries {@code sq inspect --cert <fingerprint>}. If that fails (e.g. PQC
     * certs that sq considers "unusable"), falls back to scanning the cert-d
     * directory for a cert file containing the fingerprint as a primary key or subkey.
     *
     * @param fingerprint the hex fingerprint to look up (primary key or subkey)
     * @return certificate info, or null if the certificate is not in the store
     */
    public CertInfo inspectCert(String fingerprint) {
        if (fingerprint == null || fingerprint.isEmpty()) {
            return null;
        }
        // Fast path: direct --cert lookup
        String[] args = { "inspect", "--cert", fingerprint };
        CliTool.Result result = runSq(args);
        if (result.exitCode() == 0) {
            CertInfo info = parseCertInfo(result.stdout(), null);
            if (info != null) {
                return info;
            }
        }
        // Fallback: scan cert-d for a cert containing this fingerprint
        return scanCertStore(fingerprint);
    }

    /**
     * Finds the cert file in the cert-d store that contains the given fingerprint
     * (as primary key or subkey).
     *
     * @param fingerprint the hex fingerprint to search for
     * @return the path to the cert file, or null if not found
     */
    public Path findCertFile(String fingerprint) {
        if (fingerprint == null || fingerprint.isEmpty()) {
            return null;
        }
        // Try the cert-d path derived from the fingerprint (works for primary keys)
        String lower = fingerprint.toLowerCase();
        if (lower.length() >= 3) {
            Path direct = certDDir().resolve(lower.substring(0, 2)).resolve(lower.substring(2));
            if (Files.isRegularFile(direct)) {
                return direct;
            }
        }
        // Scan for subkey match
        CertInfo info = scanCertStore(fingerprint);
        return info != null ? info.certFile() : null;
    }

    private CertInfo scanCertStore(String fingerprint) {
        Path certD = certDDir();
        if (!Files.isDirectory(certD)) {
            return null;
        }
        String upperFp = fingerprint.toUpperCase();
        try (DirectoryStream<Path> dirs = Files.newDirectoryStream(certD, Files::isDirectory)) {
            for (Path dir : dirs) {
                try (DirectoryStream<Path> files = Files.newDirectoryStream(dir, Files::isRegularFile)) {
                    for (Path file : files) {
                        CliTool.Result result = runSq("inspect", file.toString());
                        if (result.exitCode() == 0
                                && result.stdout().toUpperCase().contains(upperFp)) {
                            CertInfo info = parseCertInfo(result.stdout(), file);
                            if (info != null) {
                                return info;
                            }
                        }
                    }
                }
            }
        } catch (IOException e) {
            // cert-d not accessible
        }
        return null;
    }

    private Path certDDir() {
        return sequoiaHome.resolve("data").resolve("pgp.cert.d");
    }

    static CertInfo parseCertInfo(String output, Path certFile) {
        if (output == null || output.isEmpty()) {
            return null;
        }
        String algorithm = null;
        String userId = null;
        for (String line : output.split("\\R")) {
            String trimmed = line.trim();
            if (algorithm == null) {
                Matcher m = INSPECT_ALGO_PATTERN.matcher(trimmed);
                if (m.matches()) {
                    algorithm = m.group(1).trim();
                }
            }
            if (userId == null) {
                Matcher m = INSPECT_USERID_PATTERN.matcher(trimmed);
                if (m.matches()) {
                    userId = m.group(1).trim();
                }
            }
        }
        if (algorithm == null && userId == null) {
            return null;
        }
        return new CertInfo(algorithm, userId, certFile);
    }

    /**
     * Checks if the sq executable is available and functional.
     * <p>
     * This method runs {@code sq version} and returns true if the command
     * succeeds (exit code 0). This can be used to verify that Sequoia is properly
     * installed before attempting to use the runner.
     *
     *
     * @return true if sq is available and responds to version command, false otherwise
     */
    public static boolean isAvailable() {
        try {
            CliTool.Result result = CliTool.run("sq", "version");
            return result.exitCode() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Runs an sq command with the SEQUOIA_HOME environment variable set.
     * <p>
     * This is a specialized version of CliTool.run() that sets the SEQUOIA_HOME
     * environment variable to isolate key storage and configuration.
     *
     *
     * @param args the sq command arguments (without the executable name)
     * @return the result of the command execution
     * @throws UncheckedIOException if an I/O error occurs during execution
     * @throws RuntimeException if the process is interrupted or times out
     */
    private CliTool.Result runSq(String... args) {
        String[] command = buildCommand(args);
        return CliTool.run(Map.of(SEQUOIA_HOME, sequoiaHome.toString()), command);
    }

    private String formatCommand(String... args) {
        return String.join(" ", buildCommand(args));
    }

    private String[] buildCommand(String... args) {
        List<String> command = new ArrayList<>(args.length + 2);
        command.add(sqExecutable);
        command.add("--overwrite");
        for (String arg : args) {
            command.add(arg);
        }
        return command.toArray(new String[0]);
    }

    /**
     * Builds the verify command array, optionally including the signer fingerprint.
     *
     * @param artifactFile the file that was signed
     * @param signatureFile the signature file
     * @param signerFingerprint the expected signer's fingerprint, or null
     * @return the verify command arguments
     */
    private String[] buildVerifyCommand(Path artifactFile, Path signatureFile,
            String signerFingerprint) {
        List<String> args = new ArrayList<>();
        args.add("verify");

        if (signerFingerprint != null && !signerFingerprint.isEmpty()) {
            args.add("--signer");
            args.add(signerFingerprint);
        }

        args.add("--signature-file");
        args.add(signatureFile.toString());
        args.add(artifactFile.toString());

        return args.toArray(new String[0]);
    }

    /**
     * Extracts the key fingerprint from sq key generate output.
     * <p>
     * This method tries multiple patterns to handle different output formats:
     * <ul>
     * <li>"Fingerprint: ABCD..." (with label)</li>
     * <li>"fingerprint: abcd..." (case-insensitive)</li>
     * <li>Bare 64-character hex string on its own line</li>
     * </ul>
     *
     *
     * @param output the stdout from sq key generate
     * @return the extracted fingerprint
     * @throws IllegalStateException if no valid fingerprint is found
     */
    private String extractFingerprint(String output) {
        if (output == null || output.isEmpty()) {
            throw new IllegalStateException("Cannot extract fingerprint from empty output");
        }

        String[] lines = output.split("\\r?\\n");
        for (String line : lines) {
            Matcher matcher = FINGERPRINT_PATTERN.matcher(line.trim());
            if (matcher.find()) {
                return matcher.group(1).toUpperCase();
            }
        }

        throw new IllegalStateException(
                "Failed to extract fingerprint from sq output: " + output);
    }

    /**
     * Reads the signature file content and returns it as a string.
     *
     * @param signatureFile the signature file to read
     * @return the signature content
     * @throws UncheckedIOException if reading fails
     */
    private String readSignatureFile(Path signatureFile) {
        try {
            return Files.readString(signatureFile);
        } catch (IOException e) {
            throw new UncheckedIOException(
                    "Failed to read signature file: " + signatureFile,
                    e);
        }
    }
}
