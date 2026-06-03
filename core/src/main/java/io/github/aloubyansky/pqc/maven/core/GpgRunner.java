package io.github.aloubyansky.pqc.maven.core;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Wrapper for the GnuPG (gpg) command-line tool for signing and verification.
 * <p>
 * This class provides a Java interface to GPG's signing and verification
 * functionality, specifically for creating and verifying detached ASCII-armored
 * signatures.
 *
 * <p>
 * Example usage:
 *
 * <pre>
 * {
 *     &#64;code
 *     // Using the default GPG key
 *     GpgRunner gpg = new GpgRunner();
 *     String signature = gpg.sign(
 *             Path.of("artifact.jar"),
 *             Path.of("artifact.jar.asc"));
 *
 *     // Verify a signature
 *     GpgRunner.VerifyResult result = gpg.verify(
 *             Path.of("artifact.jar"),
 *             Path.of("artifact.jar.asc"));
 * }
 * </pre>
 * <p>
 * Note: This class requires the {@code gpg} executable to be available on the
 * system PATH or at the location specified via the constructor.
 *
 * @see #isAvailable()
 */
public class GpgRunner {

    private static final Pattern GPG_KEY_PATTERN = Pattern.compile(
            "using \\w+ key\\s+([0-9A-Fa-f]{16,40})", Pattern.MULTILINE);

    /**
     * Checks if the GPG executable is available and functional.
     *
     * @return true if GPG is available and responds to --version, false otherwise
     */
    public static boolean isAvailable() {
        try {
            CliTool.Result result = CliTool.run("gpg", "--version");
            return result.exitCode() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Extracts the GPG key ID from gpg --verify stderr output.
     * <p>
     * Parses stderr output looking for lines like:
     * {@code gpg:                using RSA key 4AEE18F83AFDEB23}
     *
     * @param gpgStderr the stderr output from gpg --verify command
     * @return the extracted key ID in uppercase, or null if not found
     */
    static String extractGpgKeyId(String gpgStderr) {
        if (gpgStderr == null) {
            return null;
        }
        Matcher matcher = GPG_KEY_PATTERN.matcher(gpgStderr);
        if (matcher.find()) {
            return matcher.group(1).toUpperCase();
        }
        return null;
    }

    private final String gpgExecutable;
    private final String keyName;

    /**
     * Constructs a GpgRunner using the default "gpg" executable and default key.
     */
    public GpgRunner() {
        this("gpg", null);
    }

    /**
     * Constructs a GpgRunner using the default "gpg" executable.
     *
     * @param keyName the key name/ID to use with --local-user, or null to use
     *        GPG's default key
     */
    public GpgRunner(String keyName) {
        this("gpg", keyName);
    }

    /**
     * Constructs a GpgRunner with a custom GPG executable path.
     *
     * @param gpgExecutable the path to the gpg executable (e.g., "gpg" or "/usr/bin/gpg")
     * @param keyName the key name/ID to use with --local-user, or null to use
     *        GPG's default key
     * @throws IllegalArgumentException if gpgExecutable is null or empty
     */
    public GpgRunner(String gpgExecutable, String keyName) {
        if (gpgExecutable == null || gpgExecutable.isEmpty()) {
            throw new IllegalArgumentException("gpgExecutable cannot be null or empty");
        }
        this.gpgExecutable = gpgExecutable;
        this.keyName = keyName;
    }

    /**
     * Result of a GPG signature verification.
     *
     * @param goodSignature true if the signature is valid
     * @param keyId the signing key ID extracted from GPG output, or null if not found
     */
    public record VerifyResult(boolean goodSignature, String keyId) {
    }

    /**
     * Creates a detached ASCII-armored signature for the specified artifact file.
     * <p>
     * This method invokes GPG with the following options:
     * <ul>
     * <li>--batch: Non-interactive mode</li>
     * <li>--yes: Assume "yes" for prompts (e.g., overwrite existing signature)</li>
     * <li>--armor: Create ASCII-armored output</li>
     * <li>--detach-sign: Create a detached signature</li>
     * <li>--local-user: Specify signing key (if keyName is set)</li>
     * <li>--output: Specify output signature file path</li>
     * </ul>
     *
     * @param artifactFile the file to sign
     * @param outputSig the path where the signature file will be written
     * @return the ASCII-armored signature content as a String
     * @throws IllegalArgumentException if artifactFile or outputSig is null
     * @throws RuntimeException if the GPG command fails
     * @throws java.io.UncheckedIOException if reading the signature file fails
     */
    public String sign(Path artifactFile, Path outputSig) {
        if (artifactFile == null) {
            throw new IllegalArgumentException("artifactFile cannot be null");
        }
        if (outputSig == null) {
            throw new IllegalArgumentException("outputSig cannot be null");
        }

        String[] command = buildSignCommand(artifactFile, outputSig);
        CliTool.Result result = CliTool.run(command);
        if (result.exitCode() != 0) {
            throw new RuntimeException("'" + String.join(" ", command)
                    + "' failed with exit code " + result.exitCode()
                    + (result.stderr().isEmpty() ? "" : ": " + result.stderr().trim()));
        }

        return readSignatureFile(outputSig);
    }

    /**
     * Verifies a detached signature for the specified artifact file.
     * <p>
     * This method runs {@code gpg --verify <signatureFile> <artifactFile>}
     * and interprets the result.
     *
     * @param artifactFile the file that was signed
     * @param signatureFile the detached signature file to verify
     * @return a {@link VerifyResult} with the verification outcome and extracted key ID
     * @throws IllegalArgumentException if artifactFile or signatureFile is null
     */
    public VerifyResult verify(Path artifactFile, Path signatureFile) {
        if (artifactFile == null) {
            throw new IllegalArgumentException("artifactFile cannot be null");
        }
        if (signatureFile == null) {
            throw new IllegalArgumentException("signatureFile cannot be null");
        }

        CliTool.Result result = CliTool.run(
                gpgExecutable,
                "--verify",
                signatureFile.toString(),
                artifactFile.toString());

        // Exit code 2 means warnings (e.g. unknown packet versions); treat as
        // valid if GPG still reports "Good signature"
        boolean goodSignature = result.exitCode() == 0
                || (result.exitCode() == 2 && result.stderr().contains("Good signature"));
        String keyId = extractGpgKeyId(result.stderr());
        return new VerifyResult(goodSignature, keyId);
    }

    private String[] buildSignCommand(Path artifactFile, Path outputSig) {
        List<String> command = new ArrayList<>();
        command.add(gpgExecutable);
        command.add("--batch");
        command.add("--yes");
        command.add("--armor");
        command.add("--detach-sign");

        if (keyName != null && !keyName.isEmpty()) {
            command.add("--local-user");
            command.add(keyName);
        }

        command.add("--output");
        command.add(outputSig.toString());
        command.add(artifactFile.toString());

        return command.toArray(new String[0]);
    }

    private String readSignatureFile(Path signatureFile) {
        try {
            return Files.readString(signatureFile);
        } catch (IOException e) {
            throw new java.io.UncheckedIOException(
                    "Failed to read signature file: " + signatureFile,
                    e);
        }
    }
}
