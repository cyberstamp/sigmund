package dev.cyberstamp.sigmund.core;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Wrapper for the Sequoia (sq) command-line tool for PQC key generation,
 * signing, verification, and certificate export.
 * <p>
 * This class provides a Java interface to Sequoia's post-quantum cryptography
 * capabilities, using hybrid cipher suites as defined in RFC 9580. The default
 * cipher suite is {@value #DEFAULT_CIPHER_SUITE} (configurable via
 * {@link #generateKey(String, String)}). When a Sequoia home directory is
 * provided, operations are isolated via the SEQUOIA_HOME environment variable;
 * otherwise sq uses its own defaults.
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
public class SqRunner implements SignatureTool, KeyGenerator, CertExporter {

    /** Default cipher suite for PQC key generation (ML-DSA-87 + Ed448 hybrid). */
    public static final String DEFAULT_CIPHER_SUITE = "mldsa87-ed448";

    private static final Set<String> SUPPORTED_CREDENTIAL_TYPES = Set.of(Credential.TYPE_OPENPGP_V4,
            Credential.TYPE_OPENPGP_V6);
    private static final Pattern FINGERPRINT_PATTERN = Pattern.compile("(?i)(?:fingerprint:?\\s*)?([0-9A-F]{64})");
    private static final Pattern SIGNER_SELF_PATTERN = Pattern.compile("(?i)[0-9A-F]{40,64}");
    private static final Pattern INSPECT_ALGO_PATTERN = Pattern.compile("Public-key algo:\\s+(.+)");
    private static final Pattern INSPECT_USERID_PATTERN = Pattern.compile("UserID:\\s+(.+)");
    private static final String SEQUOIA_HOME = "SEQUOIA_HOME";

    private final String sqExecutable;
    private final Map<String, String> sqEnv;
    private volatile Path certDDir;
    private volatile boolean certDDirResolved;
    private final String signingFingerprint;
    private final String defaultSignerFingerprint;
    private final OpenPgpSignatureFormat format;
    private volatile String detectedAlgorithm;

    /**
     * Constructs a verify-only SqRunner using the default "sq" executable.
     *
     * @param sequoiaHome the directory to use as SEQUOIA_HOME, or {@code null} to let sq
     *        use its own defaults
     */
    public SqRunner(Path sequoiaHome) {
        this("sq", sequoiaHome, null);
    }

    /**
     * Constructs an SqRunner with a custom sq executable path (verify-only).
     *
     * @param sqExecutable the path to the sq executable (e.g., "sq" or "/usr/local/bin/sq")
     * @param sequoiaHome the directory to use as SEQUOIA_HOME, or {@code null} to let sq
     *        use its own defaults
     * @throws IllegalArgumentException if sqExecutable is null or empty
     */
    public SqRunner(String sqExecutable, Path sequoiaHome) {
        this(sqExecutable, sequoiaHome, null);
    }

    /**
     * Constructs an SqRunner with a signing fingerprint.
     * <p>
     * When {@code signingFingerprint} is non-null, {@link #canSign()} returns {@code true}
     * and the SPI {@link #sign(Path, Path)} method uses this fingerprint.
     *
     * @param sqExecutable the path to the sq executable
     * @param sequoiaHome the directory to use as SEQUOIA_HOME, or {@code null} to let sq
     *        use its own defaults
     * @param signingFingerprint the fingerprint to sign with, or {@code null} for verify-only
     * @throws IllegalArgumentException if sqExecutable is null or empty
     */
    public SqRunner(String sqExecutable, Path sequoiaHome, String signingFingerprint) {
        this(sqExecutable, sequoiaHome, signingFingerprint, null);
    }

    /**
     * Constructs an SqRunner with an explicit signing fingerprint or a default signer.
     * <p>
     * When {@code signingFingerprint} is non-null, signing uses {@code --signer <fingerprint>}.
     * When {@code signingFingerprint} is null but {@code defaultSignerFingerprint} is non-null,
     * signing uses {@code --signer-self} (sq's configured default signer) and
     * {@code defaultSignerFingerprint} is used for {@link #signingInfo()} display.
     *
     * @param sqExecutable the path to the sq executable
     * @param sequoiaHome the directory to use as SEQUOIA_HOME, or {@code null} to let sq
     *        use its own defaults (or the existing SEQUOIA_HOME from the environment)
     * @param signingFingerprint the explicit fingerprint to sign with, or {@code null}
     * @param defaultSignerFingerprint the fingerprint resolved from sq's {@code sign.signer-self}
     *        config, or {@code null}
     * @throws IllegalArgumentException if sqExecutable is null or empty
     */
    SqRunner(String sqExecutable, Path sequoiaHome, String signingFingerprint,
            String defaultSignerFingerprint) {
        if (sqExecutable == null || sqExecutable.isEmpty()) {
            throw new IllegalArgumentException("sqExecutable cannot be null or empty");
        }
        this.sqExecutable = sqExecutable;
        this.sqEnv = envFor(sequoiaHome);
        this.signingFingerprint = signingFingerprint;
        this.defaultSignerFingerprint = signingFingerprint == null ? defaultSignerFingerprint : null;
        this.format = new OpenPgpSignatureFormat();
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
        Path certD = certDDir();
        return certD != null ? scanCertStore(fingerprint, certD) : null;
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
        Path certD = certDDir();
        if (certD == null) {
            return null;
        }
        // Try the cert-d path derived from the fingerprint (works for primary keys)
        String lower = fingerprint.toLowerCase();
        if (lower.length() >= 3) {
            Path direct = certD.resolve(lower.substring(0, 2)).resolve(lower.substring(2));
            if (Files.isRegularFile(direct)) {
                return direct;
            }
        }
        // Scan for subkey match
        CertInfo info = scanCertStore(fingerprint, certD);
        return info != null ? info.certFile() : null;
    }

    private CertInfo scanCertStore(String fingerprint, Path certD) {
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

    // Racy lazy init — safe because re-computation is benign and certDDir is written before the flag
    private Path certDDir() {
        if (!certDDirResolved) {
            certDDir = queryCertDDir(sqExecutable, sqEnv);
            certDDirResolved = true;
        }
        return certDDir;
    }

    // Parses "certificate store\n   - /path/to/cert-d" from `sq config inspect paths` (sq 1.4.0-pqc.1)
    private static final Pattern CERT_STORE_PATH_PATTERN = Pattern.compile(
            "certificate store\\s*\\R\\s*-\\s*(.+)", Pattern.MULTILINE);

    /**
     * Queries the actual certificate store path by running
     * {@code sq config inspect paths} and parsing the "certificate store" entry.
     * <p>
     * This avoids hardcoding the cert-d location, which varies depending on
     * whether {@code SEQUOIA_HOME} is set and which XDG directories are in effect.
     *
     * @param sqExecutable the path to the sq executable
     * @param env environment variables for the sq process (typically from {@link #envFor}),
     *        or {@code null} to inherit the current environment
     * @return the certificate store directory, or {@code null} if sq is unavailable
     *         or the path cannot be determined
     */
    static Path queryCertDDir(String sqExecutable, Map<String, String> env) {
        try {
            CliTool.Result result = CliTool.run(env,
                    sqExecutable, "config", "inspect", "paths");
            if (result.exitCode() == 0) {
                return parseCertStorePath(result.stdout());
            }
        } catch (UncheckedIOException ignored) {
            // sq not available
        }
        return null;
    }

    /**
     * Parses the certificate store path from {@code sq config inspect paths} output.
     * <p>
     * Looks for a "certificate store" section followed by a line starting with
     * {@code " - "} and extracts the path. Returns {@code null} if the section
     * is absent or the path is empty.
     *
     * @param output the stdout from {@code sq config inspect paths}
     * @return the parsed path, or {@code null}
     */
    static Path parseCertStorePath(String output) {
        if (output == null) {
            return null;
        }
        Matcher m = CERT_STORE_PATH_PATTERN.matcher(output);
        if (m.find()) {
            String path = m.group(1).trim();
            if (!path.isEmpty()) {
                return Path.of(path);
            }
        }
        return null;
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
     * @return true if sq is available and responds to version command, false otherwise
     */
    public static boolean isToolAvailable() {
        try {
            CliTool.Result result = CliTool.run("sq", "version");
            return result.exitCode() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public String name() {
        return "sq";
    }

    /**
     * {@inheritDoc}
     * <p>
     * Checks availability by running {@code sq version}.
     */
    @Override
    public boolean isAvailable() {
        return SqRunner.isToolAvailable();
    }

    @Override
    public boolean canSign() {
        return (signingFingerprint != null && !signingFingerprint.isEmpty())
                || (defaultSignerFingerprint != null && !defaultSignerFingerprint.isEmpty());
    }

    /**
     * Queries sq's configured default signer fingerprint ({@code sign.signer-self.0}).
     * <p>
     * Runs {@code sq config get sign.signer-self.0} and parses the output format
     * {@code sign.signer-self.0 = "FINGERPRINT"}. Returns the fingerprint only if
     * it looks like a valid hex fingerprint (40 or 64 characters).
     *
     * @param sqExecutable the path to the sq executable
     * @param env the environment to pass to the sq process, or {@code null}
     * @return the default signer fingerprint in uppercase, or {@code null} if not configured
     */
    static String querySignerSelf(String sqExecutable, Map<String, String> env) {
        try {
            String[] command = { sqExecutable, "config", "get", "sign.signer-self.0" };
            CliTool.Result result = CliTool.run(env, command);
            if (result.exitCode() != 0) {
                return null;
            }
            return parseSignerSelfOutput(result.stdout());
        } catch (Exception e) {
            return null;
        }
    }

    static String parseSignerSelfOutput(String output) {
        if (output == null || output.isEmpty()) {
            return null;
        }
        String line = output.lines().findFirst().orElse("").trim();
        int eq = line.indexOf('=');
        if (eq < 0) {
            return null;
        }
        String value = line.substring(eq + 1).trim();
        if (value.startsWith("\"") && value.endsWith("\"") && value.length() > 1) {
            value = value.substring(1, value.length() - 1);
        }
        value = value.trim();
        if (value.isEmpty() || !SIGNER_SELF_PATTERN.matcher(value).matches()) {
            return null;
        }
        return value.toUpperCase();
    }

    @Override
    public List<SigningInfo> signingInfo() {
        if (!canSign()) {
            return List.of();
        }
        String effectiveFingerprint = signingFingerprint != null ? signingFingerprint : defaultSignerFingerprint;
        try {
            CertInfo info = inspectCert(effectiveFingerprint);
            if (info == null) {
                return List.of(new SigningInfo("sq", effectiveFingerprint,
                        null, null, Set.copyOf(SUPPORTED_CREDENTIAL_TYPES)));
            }
            return List.of(new SigningInfo("sq", effectiveFingerprint,
                    info.algorithm(), info.userId(),
                    Set.copyOf(SUPPORTED_CREDENTIAL_TYPES)));
        } catch (RuntimeException e) {
            return List.of(new SigningInfo("sq", effectiveFingerprint,
                    null, null, Set.copyOf(SUPPORTED_CREDENTIAL_TYPES)));
        }
    }

    @Override
    public SignatureFormat signatureFormat() {
        return format;
    }

    @Override
    public Set<String> supportedCredentialTypes() {
        return SUPPORTED_CREDENTIAL_TYPES;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Accepts {@link OpenPgpClaim}s with {@code packetVersion >= 5}.
     */
    @Override
    public boolean canVerify(Claim claim) {
        return claim instanceof OpenPgpClaim opgu
                && opgu.packetVersion() >= 5;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Signs using the stored fingerprint (provided at construction time).
     *
     * @throws IllegalStateException if no signing fingerprint was configured
     */
    @Override
    public SignResult sign(Path artifactFile, Path outputSig) {
        if (!canSign()) {
            throw new IllegalStateException("No signing fingerprint configured");
        }
        if (signingFingerprint != null) {
            sign(artifactFile, outputSig, signingFingerprint);
        } else {
            signWithSignerSelf(artifactFile, outputSig);
        }
        if (detectedAlgorithm == null) {
            try {
                String armored = java.nio.file.Files.readString(outputSig);
                OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);
                String name = Algorithms.algorithmName(info.algorithmId());
                detectedAlgorithm = name != null ? name : "unknown";
            } catch (java.io.IOException e) {
                detectedAlgorithm = "unknown";
            }
        }
        return new SignResult(detectedAlgorithm);
    }

    private void signWithSignerSelf(Path artifactFile, Path outputSig) {
        String[] args = {
                "sign",
                "--signer-self",
                "--signature-file", outputSig.toString(),
                artifactFile.toString()
        };

        CliTool.Result result = runSq(args);
        if (result.exitCode() != 0) {
            throw new RuntimeException("'" + formatCommand(args)
                    + "' failed with exit code " + result.exitCode()
                    + (result.stderr().isEmpty() ? "" : ": " + result.stderr().trim()));
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * Sequoia verifies against its certificate store, which is the configured
     * {@code SEQUOIA_HOME} when operations are isolated and sq's own default store otherwise.
     */
    @Override
    public TrustRootRef trustRoot() {
        String home = sqEnv.get(SEQUOIA_HOME);
        return new TrustRootRef(TrustRootRef.KIND_OPENPGP_KEYRING,
                home != null ? home : "sq default store");
    }

    /**
     * {@inheritDoc}
     * <p>
     * Verifies an OpenPGP v5+ signature block by resolving the issuer certificate
     * from the Sequoia cert store.
     */
    @Override
    public VerifyResult verify(Path artifactFile, Claim claim) {
        if (!(claim instanceof OpenPgpClaim opgu)) {
            return OpenPgpVerifyResult.indeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM);
        }
        return verifyOpenPgpClaim(artifactFile, opgu);
    }

    @Override
    public List<Credential> extractCredentials(VerifyResult result) {
        return OpenPgpCredentials.from(result);
    }

    private OpenPgpVerifyResult verifyOpenPgpClaim(Path artifactFile, OpenPgpClaim opgu) {
        int version = opgu.packetVersion();
        String fingerprint = opgu.issuerFingerprint();
        int algoId = opgu.algorithmId();
        String algorithm = resolveAlgorithm(algoId);

        if (fingerprint == null) {
            return OpenPgpVerifyResult.indeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM, null, algorithm, version,
                    fingerprint, fingerprint);
        }

        CertInfo certInfo = inspectCert(fingerprint);
        if (certInfo == null) {
            return OpenPgpVerifyResult.indeterminate(IndeterminateReason.KEY_UNAVAILABLE, null, algorithm, version, fingerprint,
                    fingerprint);
        }

        if (certInfo.algorithm() != null) {
            algorithm = certInfo.algorithm();
        }

        Path certFile = resolveCertFile(certInfo, fingerprint);
        if (certFile == null) {
            return OpenPgpVerifyResult.indeterminate(IndeterminateReason.KEY_UNAVAILABLE, certInfo.userId(), algorithm, version,
                    fingerprint, fingerprint);
        }

        return verifyWithCertFile(artifactFile, opgu.armoredBlock(), certFile,
                version, fingerprint, algorithm, certInfo.userId());
    }

    private String resolveAlgorithm(int algoId) {
        String algorithm = Algorithms.algorithmName(algoId);
        if (algorithm == null && algoId >= 0) {
            algorithm = "unknown(" + algoId + ")";
        }
        return algorithm;
    }

    private Path resolveCertFile(CertInfo certInfo, String fingerprint) {
        Path certFile = certInfo.certFile();
        if (certFile == null) {
            certFile = findCertFile(fingerprint);
        }
        return certFile;
    }

    private OpenPgpVerifyResult verifyWithCertFile(Path artifactFile, String armoredBlock,
            Path certFile, int version, String fingerprint, String algorithm, String userId) {
        Path sigFile = null;
        try {
            sigFile = Files.createTempFile("sq-verify-", ".asc");
            Files.writeString(sigFile, armoredBlock);
            boolean verified = verifyCertFile(artifactFile, sigFile, certFile);
            return new OpenPgpVerifyResult(
                    verified ? ClaimOutcome.VERIFIED : ClaimOutcome.FAILED, null,
                    userId, algorithm, version, fingerprint, fingerprint);
        } catch (IOException e) {
            throw new ToolExecutionException("Failed to create temp file for SQ verification", e);
        } finally {
            deleteSilently(sigFile);
        }
    }

    private static void deleteSilently(Path file) {
        if (file != null) {
            try {
                Files.deleteIfExists(file);
            } catch (IOException ignored) {
            }
        }
    }

    /**
     * Builds the environment map for sq commands from an optional Sequoia home directory.
     *
     * @param sequoiaHome the directory to use as {@code SEQUOIA_HOME}, or {@code null}
     *        to inherit the current environment (letting sq use its own defaults)
     * @return a single-entry map setting {@code SEQUOIA_HOME}, or an empty map when sq is
     *         left to its own defaults — adding nothing to the inherited environment
     */
    static Map<String, String> envFor(Path sequoiaHome) {
        return sequoiaHome != null
                ? Map.of(SEQUOIA_HOME, sequoiaHome.toString())
                : Map.of();
    }

    private CliTool.Result runSq(String... args) {
        String[] command = buildCommand(args);
        return CliTool.run(sqEnv, command);
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
