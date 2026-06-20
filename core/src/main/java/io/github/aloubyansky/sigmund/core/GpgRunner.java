package io.github.aloubyansky.sigmund.core;

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
            "using (\\w+) key\\s+([0-9A-Fa-f]{16,40})", Pattern.MULTILINE);

    private static final Pattern GPG_SIGNER_PATTERN = Pattern.compile(
            "Good signature from \"([^\"]+)\"", Pattern.MULTILINE);

    private static final int GPG_COLONS_UID_FIELD = 9;

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
            return matcher.group(2).toUpperCase();
        }
        return null;
    }

    /**
     * Extracts the key algorithm (e.g., "RSA", "EDDSA") from gpg --verify stderr output.
     *
     * @param gpgStderr the stderr output from gpg --verify command
     * @return the algorithm name in uppercase, or null if not found
     */
    static String extractAlgorithm(String gpgStderr) {
        if (gpgStderr == null) {
            return null;
        }
        Matcher matcher = GPG_KEY_PATTERN.matcher(gpgStderr);
        if (matcher.find()) {
            return matcher.group(1).toUpperCase();
        }
        return null;
    }

    /**
     * Extracts the signer's user ID from gpg --verify stderr output.
     * <p>
     * Parses stderr output looking for lines like:
     * {@code gpg: Good signature from "Name <email@example.com>" [ultimate]}
     *
     * @param gpgStderr the stderr output from gpg --verify command
     * @return the signer's user ID (e.g., "Name &lt;email@example.com&gt;"), or null if not found
     */
    static String extractSignerUserId(String gpgStderr) {
        if (gpgStderr == null) {
            return null;
        }
        Matcher matcher = GPG_SIGNER_PATTERN.matcher(gpgStderr);
        if (matcher.find()) {
            return matcher.group(1);
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
     * @param result the verification outcome: {@link VerificationResult#PASS} if the signature is valid,
     *        {@link VerificationResult#FAIL} if the signature does not match,
     *        {@link VerificationResult#NO_KEY} if the signing key is not in the keyring
     * @param keyId the signing key ID extracted from GPG output, or null if not found
     * @param algorithm the key algorithm (e.g., "RSA", "EDDSA"), or null if not found
     * @param signerUserId the signer's user ID (e.g., "Name &lt;email&gt;"), or null if the key is not in the keyring
     */
    public record VerifyResult(VerificationResult result, String keyId, String algorithm, String signerUserId) {
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

        String keyId = extractGpgKeyId(result.stderr());
        String algorithm = extractAlgorithm(result.stderr());
        String signerUserId = extractSignerUserId(result.stderr());

        // Exit code 2 means warnings (e.g. unknown packet versions); treat as
        // valid only if GPG still reports "Good signature"
        VerificationResult verificationResult;
        if (result.exitCode() == 0
                || (result.exitCode() == 2 && result.stderr().contains("Good signature"))) {
            verificationResult = VerificationResult.PASS;
        } else if (result.stderr().contains("No public key")) {
            verificationResult = VerificationResult.NO_KEY;
        } else {
            verificationResult = VerificationResult.FAIL;
        }
        return new VerifyResult(verificationResult, keyId, algorithm, signerUserId);
    }

    /**
     * Receives a public key from a keyserver and imports it into the local keyring.
     *
     * @param keyId the key ID to receive
     * @param keyserver the keyserver URL (e.g., "hkps://keys.openpgp.org")
     * @return true if the key was successfully received, false otherwise
     */
    public boolean receiveKey(String keyId, String keyserver) {
        CliTool.Result result = CliTool.run(
                gpgExecutable,
                "--keyserver", keyserver,
                "--recv-keys", keyId);
        return result.exitCode() == 0;
    }

    /**
     * Looks up the user ID (UID) for a key in the local keyring.
     * <p>
     * Parses the {@code --with-colons} output format where the user ID is at field index 9
     * on lines starting with {@code uid:}.
     *
     * @param keyId the key ID to look up
     * @return the user ID string (e.g., "Name &lt;email@example.com&gt;"), or null if not found
     */
    public String listKeyUserId(String keyId) {
        CliTool.Result result = CliTool.run(
                gpgExecutable,
                "--list-keys",
                "--with-colons",
                keyId);
        if (result.exitCode() != 0) {
            return null;
        }
        for (String line : result.stdout().split("\\R")) {
            if (line.startsWith("uid:")) {
                String[] fields = line.split(":", -1);
                if (fields.length > GPG_COLONS_UID_FIELD && !fields[GPG_COLONS_UID_FIELD].isEmpty()) {
                    return fields[GPG_COLONS_UID_FIELD];
                }
            }
        }
        return null;
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
