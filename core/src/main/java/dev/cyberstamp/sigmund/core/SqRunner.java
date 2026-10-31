package dev.cyberstamp.sigmund.core;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.openpgp.PGPPublicKeyRing;

/**
 * Wrapper for the Sequoia (sq) command-line tool for signing, verification, and certificate
 * export, including post-quantum hybrid signatures (RFC 9980). Keys are generated with sq
 * itself ({@code sq key generate}), not through Sigmund. When a Sequoia home directory is
 * provided, operations are isolated via the SEQUOIA_HOME environment variable; otherwise sq
 * uses its own defaults.
 *
 * <p>
 * Note: This class requires the {@code sq} executable to be available on the
 * system PATH or at the location specified via the constructor.
 *
 *
 * @see #isAvailable()
 */
public class SqRunner implements SignatureTool, CertExporter {

    /** Default cipher suite for PQC key generation (ML-DSA-87 + Ed448 hybrid). */
    static final String DEFAULT_CIPHER_SUITE = "mldsa87-ed448";

    private static final Set<String> SUPPORTED_CREDENTIAL_TYPES = Set.of(Credential.TYPE_PGP4,
            Credential.TYPE_PGP6);
    private static final Pattern FINGERPRINT_PATTERN = Pattern
            .compile("(?i)(?:fingerprint:?\\s*)?\\b([0-9A-F]{64}|[0-9A-F]{40})\\b");
    private static final Pattern SIGNER_SELF_PATTERN = Pattern.compile("(?i)[0-9A-F]{40,64}");
    private static final Pattern INSPECT_ALGO_PATTERN = Pattern.compile("Public-key algo:\\s+(.+)");
    private static final Pattern INSPECT_USERID_PATTERN = Pattern.compile("UserID:\\s+(.+)");
    private static final String SEQUOIA_HOME = "SEQUOIA_HOME";
    private static final String SEQUOIA_CRYPTO_POLICY = "SEQUOIA_CRYPTO_POLICY";
    private static final Pattern BAD_SIGNATURES = Pattern.compile("\\b[1-9]\\d*\\h+bad\\h+signatures?\\b");
    private static final Pattern BAD_KEYS = Pattern.compile("\\b[1-9]\\d*\\h+bad\\h+keys?\\b");
    private static final Pattern KEY_NOT_LIVE = Pattern.compile("(?i)\\b(revoked|expired)\\b");

    private final String sqExecutable;
    private final Map<String, String> sqEnv;
    private volatile Path certDDir;
    private volatile boolean certDDirResolved;
    private final List<String> signingFingerprints;
    private final OpenPgpSignatureFormat format;

    /**
     * Constructs a verify-only SqRunner using the default "sq" executable.
     *
     * @param sequoiaHome the directory to use as SEQUOIA_HOME, or {@code null} to let sq
     *        use its own defaults
     */
    public SqRunner(Path sequoiaHome) {
        this("sq", sequoiaHome, List.of());
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
        this(sqExecutable, sequoiaHome, List.of());
    }

    /**
     * Constructs an SqRunner with a signing fingerprint.
     * <p>
     * When {@code signingFingerprint} is non-null, {@link #canSign()} returns {@code true}
     * and {@link #sign(Path, Path, SigningInfo)} signs with this key.
     *
     * @param sqExecutable the path to the sq executable
     * @param sequoiaHome the directory to use as SEQUOIA_HOME, or {@code null} to let sq
     *        use its own defaults
     * @param signingFingerprint the fingerprint to sign with, or {@code null} for verify-only
     * @throws IllegalArgumentException if sqExecutable is null or empty
     */
    public SqRunner(String sqExecutable, Path sequoiaHome, String signingFingerprint) {
        this(sqExecutable, sequoiaHome, signingFingerprint == null ? List.of() : List.of(signingFingerprint));
    }

    /**
     * Constructs an SqRunner that signs with the given keys.
     * <p>
     * Every key signs with {@code sq sign --signer <fingerprint>}. sq's own default signer
     * ({@code sign.signer-self}) is resolved to its fingerprint by the caller and passed here
     * like any other key, so the key that signs is always the one {@link #signingInfo()}
     * reports.
     *
     * @param sqExecutable the path to the sq executable
     * @param sequoiaHome the directory to use as SEQUOIA_HOME, or {@code null} to let sq
     *        use its own defaults (or the existing SEQUOIA_HOME from the environment)
     * @param signingFingerprints the fingerprints of the keys to sign with, in order; empty for
     *        a verify-only runner
     * @throws IllegalArgumentException if sqExecutable is null or empty
     */
    SqRunner(String sqExecutable, Path sequoiaHome, List<String> signingFingerprints) {
        if (sqExecutable == null || sqExecutable.isEmpty()) {
            throw new IllegalArgumentException("sqExecutable cannot be null or empty");
        }
        this.sqExecutable = sqExecutable;
        this.sqEnv = envFor(sequoiaHome);
        this.signingFingerprints = List.copyOf(signingFingerprints);
        this.format = new OpenPgpSignatureFormat();
    }

    /**
     * Generates a new key in sq's store, for tests that need sq to hold a key.
     * <p>
     * Sigmund does not generate keys for sq: sq's own {@code sq key generate} covers
     * passphrases, expiry and profiles. This runs
     * {@code sq key generate --userid <userId> --cipher-suite <cipherSuite> --profile <profile>
     * --own-key --without-password}, so the key is unprotected, and v4 under {@code rfc4880} or
     * v6 under {@code rfc9580}.
     *
     * @param userId the user ID for the key (e.g., "Alice &lt;alice@example.com&gt;")
     * @param cipherSuite the Sequoia cipher suite identifier
     *        (e.g., {@value #DEFAULT_CIPHER_SUITE})
     * @param profile the OpenPGP profile, {@code rfc4880} (v4) or {@code rfc9580} (v6)
     * @return the 40- or 64-character hexadecimal fingerprint of the generated key
     * @throws IllegalArgumentException if userId, cipherSuite or profile is null or empty
     * @throws RuntimeException if the sq command fails
     * @throws IllegalStateException if the fingerprint cannot be parsed from the output
     */
    String generateKey(String userId, String cipherSuite, String profile) {
        if (userId == null || userId.isEmpty()) {
            throw new IllegalArgumentException("userId cannot be null or empty");
        }
        if (cipherSuite == null || cipherSuite.isEmpty()) {
            throw new IllegalArgumentException("cipherSuite cannot be null or empty");
        }
        if (profile == null || profile.isEmpty()) {
            throw new IllegalArgumentException("profile cannot be null or empty");
        }

        String[] args = {
                "key", "generate",
                "--userid", userId,
                "--cipher-suite", cipherSuite,
                "--profile", profile,
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

        return runVerifyCertFile(artifactFile, signatureFile, certFile).exitCode() == 0;
    }

    private CliTool.Result runVerifyCertFile(Path artifactFile, Path signatureFile, Path certFile) {
        return runSq("verify",
                "--signer-file", certFile.toString(),
                "--signature-file", signatureFile.toString(),
                artifactFile.toString());
    }

    private static ToolVerdict verdict(CliTool.Result result) {
        return verdict(result.exitCode(), result.stderr());
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
        return !signingFingerprints.isEmpty();
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

    /**
     * {@inheritDoc}
     *
     * <p>
     * Gives one entry per key, in order, typed from the fingerprint's length; the algorithm and
     * user ID come from the key's certificate when sq can inspect it.
     */
    @Override
    public List<SigningInfo> signingInfo() {
        return signingFingerprints.stream().map(this::describe).toList();
    }

    private SigningInfo describe(String fingerprint) {
        String type = KeyCredential.openPgp(fingerprint).type();
        CertInfo info = inspectCertOrNull(fingerprint);
        return info == null
                ? new SigningInfo("sq", fingerprint, null, null, type)
                : new SigningInfo("sq", fingerprint, info.algorithm(), info.userId(), type);
    }

    private CertInfo inspectCertOrNull(String fingerprint) {
        try {
            return inspectCert(fingerprint);
        } catch (RuntimeException e) {
            return null;
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
     * Accepts {@link OpenPgpClaim}s with the signature versions RFC 9580 defines, which
     * Sequoia implements: v4, and v6 including RFC 9980 post-quantum signatures. Version 5 is
     * LibrePGP's format, which Sequoia does not implement, so a v5 claim is left to a tool that
     * can read it, or set aside when none can.
     */
    @Override
    public boolean canVerify(Claim claim) {
        return claim instanceof OpenPgpClaim opgu
                && (opgu.packetVersion() == 4 || opgu.packetVersion() == 6);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Signs with {@code sq sign --signer <fingerprint>}, where the fingerprint is the one
     * {@code key} names, and reads the algorithm from the signature written.
     *
     * @throws IllegalStateException if no signing fingerprint was configured
     * @throws IllegalArgumentException if {@code key} is not one of this runner's keys
     */
    @Override
    public SignResult sign(Path artifactFile, Path outputSig, SigningInfo key) {
        if (!canSign()) {
            throw new IllegalStateException("No signing fingerprint configured");
        }
        String fingerprint = SigningKeys.requireListed(name(), signingFingerprints, key);
        return new SignResult(algorithmOf(sign(artifactFile, outputSig, fingerprint)));
    }

    private static String algorithmOf(String armoredSignature) {
        OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armoredSignature);
        String name = Algorithms.algorithmName(info.algorithmId());
        return name != null ? name : "unknown";
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
        return new TrustRootRef(TrustRootRef.KIND_OPENPGP_CERT_D,
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
            ToolVerdict verdict = verdict(runVerifyCertFile(artifactFile, sigFile, certFile));
            return new OpenPgpVerifyResult(verdict.outcome(), verdict.reason(),
                    userId, algorithm, version, fingerprint, fingerprint)
                    .withKeyFingerprints(fingerprint, primaryFingerprintOf(certFile, fingerprint));
        } catch (IOException e) {
            throw new ToolExecutionException("Failed to create temp file for SQ verification", e);
        } finally {
            deleteSilently(sigFile);
        }
    }

    /**
     * Reads the primary fingerprint of the certificate that verified a signature, so that
     * policy naming the primary key matches a signature made by one of its subkeys, as it
     * does under the other backends.
     *
     * @param certFile the certificate file sq verified against
     * @param signingFingerprint the fingerprint of the signing key
     * @return the primary fingerprint, or {@code null} when it is the signing key itself or
     *         the certificate cannot be read
     */
    static String primaryFingerprintOf(Path certFile, String signingFingerprint) {
        PGPPublicKeyRing ring = certFile == null ? null : BcKeyStore.readPublicKeyRing(certFile);
        if (ring == null) {
            return null;
        }
        String primary = HexFormat.of().withUpperCase().formatHex(ring.getPublicKey().getFingerprint());
        return primary.equalsIgnoreCase(signingFingerprint) ? null : primary;
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
     * <p>
     * sq always runs under Sigmund's crypto policy ({@link VerificationAlgorithms}) through
     * {@code SEQUOIA_CRYPTO_POLICY}, which replaces the host's system policy; otherwise which
     * algorithms are accepted would depend on the machine sq runs on.
     *
     * @param sequoiaHome the directory to use as {@code SEQUOIA_HOME}, or {@code null}
     *        to inherit the current environment (letting sq use its own store)
     * @return the policy setting, plus {@code SEQUOIA_HOME} when a home is given
     */
    static Map<String, String> envFor(Path sequoiaHome) {
        String policy = VerificationAlgorithms.sequoiaPolicyFile().toString();
        return sequoiaHome != null
                ? Map.of(SEQUOIA_HOME, sequoiaHome.toString(), SEQUOIA_CRYPTO_POLICY, policy)
                : Map.of(SEQUOIA_CRYPTO_POLICY, policy);
    }

    /**
     * Reads the verdict of a {@code sq verify} run.
     *
     * <p>
     * sq exits non-zero whenever it could not authenticate a signature, for reasons as
     * different as tampered bytes and a key it will not use; its report's closing tally says
     * which; sq separates its counts from their nouns with a no-break space, so any horizontal
     * space is matched. Only a <em>bad signature</em> — the bytes do not match — or a key that was revoked
     * or had expired is {@link ClaimOutcome#FAILED}. A <em>bad key</em> rejected by the crypto
     * policy is {@link IndeterminateReason#UNSUPPORTED_ALGORITHM}; any other bad key, such as a
     * certificate served without the self-signatures that bind it, is
     * {@link IndeterminateReason#KEY_UNAVAILABLE}, since a fuller copy may resolve it. A report
     * with no tally means sq itself did not run as expected.
     *
     * @param exitCode sq's exit code
     * @param stderr sq's report
     * @return the verdict
     */
    static ToolVerdict verdict(int exitCode, String stderr) {
        if (exitCode == 0) {
            return ToolVerdict.verified();
        }
        String report = stderr == null ? "" : stderr;
        if (BAD_SIGNATURES.matcher(report).find()) {
            return ToolVerdict.failed();
        }
        if (!BAD_KEYS.matcher(report).find()) {
            return ToolVerdict.indeterminate(IndeterminateReason.TOOL_UNAVAILABLE);
        }
        if (KEY_NOT_LIVE.matcher(report).find()) {
            return ToolVerdict.failed();
        }
        if (report.contains("Policy rejected")) {
            return ToolVerdict.indeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM);
        }
        return ToolVerdict.indeterminate(IndeterminateReason.KEY_UNAVAILABLE);
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
