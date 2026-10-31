package dev.cyberstamp.sigmund.core;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Wrapper for the GnuPG (gpg) command-line tool.
 * <p>
 * Implements {@link SignatureTool} (signing and verification of detached
 * ASCII-armored signatures), {@link KeyImporter} (importing public keys
 * into the GPG keyring), and {@link SignerIdentityResolver} (resolving
 * signer identities from the keyring).
 * <p>
 * Requires the {@code gpg} executable to be available on the system PATH
 * or at the location specified via the constructor.
 *
 * @see #isAvailable()
 */
class GpgRunner implements SignatureTool, KeyImporter, SignerIdentityResolver {

    private static final Pattern GPG_KEY_PATTERN = Pattern.compile(
            "using (\\w+) key\\s+([0-9A-Fa-f]{16,40})", Pattern.MULTILINE);

    private static final Pattern GPG_SIGNER_PATTERN = Pattern.compile(
            "Good signature from \"([^\"]+)\"", Pattern.MULTILINE);

    // --with-colons field index 9: user ID in uid: records, fingerprint in fpr: records
    private static final int GPG_COLONS_FIELD_9 = 9;

    /**
     * Checks if the GPG executable is available and functional.
     *
     * @return true if GPG is available and responds to --version, false otherwise
     */
    public static boolean isToolAvailable() {
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

    private static final Set<String> SUPPORTED_CREDENTIAL_TYPES = Set.of(Credential.TYPE_PGP4);

    /**
     * Result of a GPG signature verification.
     *
     * @param outcome what verification established: {@link ClaimOutcome#VERIFIED} if the
     *        signature is valid, {@link ClaimOutcome#FAILED} if it does not match, and
     *        {@link ClaimOutcome#INDETERMINATE} if GPG could not decide
     * @param reason why verification could not complete —
     *        {@link IndeterminateReason#KEY_UNAVAILABLE} when the signing key is not in the
     *        keyring — or {@code null} when the outcome is conclusive
     * @param keyId the signing key ID extracted from GPG output, or null if not found
     * @param algorithm the key algorithm (e.g., "RSA", "EDDSA"), or null if not found
     * @param signerUserId the signer's user ID (e.g., "Name &lt;email&gt;"), or null if the key is not in the keyring
     * @param signingFingerprint the full fingerprint of the signing key, from the
     *        {@code VALIDSIG} status line, or {@code null} when the signature was not good
     * @param primaryFingerprint the full fingerprint of its primary key, from the same line,
     *        or {@code null} when GnuPG did not report one
     */
    private record GpgVerifyResult(ClaimOutcome outcome, IndeterminateReason reason, String keyId,
            String algorithm, String signerUserId, String signingFingerprint,
            String primaryFingerprint) {
    }

    static final int VALIDSIG_SIGNING_FINGERPRINT = 2;
    static final int VALIDSIG_PRIMARY_FINGERPRINT = 11;

    /**
     * Finds the {@code [GNUPG:] VALIDSIG} status line, as written with {@code --status-fd},
     * and splits it into its fields.
     *
     * <p>
     * GnuPG writes the line only for a good signature. Field {@value #VALIDSIG_SIGNING_FINGERPRINT}
     * is the full fingerprint of the signing key and field
     * {@value #VALIDSIG_PRIMARY_FINGERPRINT}, when present, that of its primary key.
     *
     * @param statusOutput the status output
     * @return the fields of the line, or {@code null} when there is none
     */
    static String[] validSigFields(String statusOutput) {
        if (statusOutput == null) {
            return null;
        }
        for (String line : statusOutput.split("\\R")) {
            String[] fields = line.trim().split("\\s+");
            if (fields.length > 1 && "[GNUPG:]".equals(fields[0]) && "VALIDSIG".equals(fields[1])) {
                return fields;
            }
        }
        return null;
    }

    private static final int VALIDSIG_TIMESTAMP = 4;
    private static final int ERRSIG_RETURN_CODE = 7;
    private static final String ERRSIG_NO_PUBLIC_KEY = "9";
    private static final String ERRSIG_UNSUPPORTED_ALGORITHM = "4";

    /**
     * Reads the verdict of a {@code gpg --status-fd 1 --verify} run from its status lines.
     *
     * <p>
     * The exit code cannot be used: GnuPG exits 0 for a good signature by a revoked key, and by
     * a key that had expired when it signed, warning only in text written for people. The status
     * lines name the case. {@code BADSIG} and {@code REVKEYSIG} are {@link ClaimOutcome#FAILED};
     * {@code EXPKEYSIG} is {@code FAILED} only when the key's {@code KEYEXPIRED} time is not after
     * the signature's own time, since a signature made while the key was valid stays valid after
     * it expires (§3.8); {@code GOODSIG} is verified. {@code ERRSIG} is indeterminate — a missing
     * public key ({@code NO_PUBKEY}, which is also how GnuPG answers for a certificate it refused
     * to import, such as one without user IDs) is {@link IndeterminateReason#KEY_UNAVAILABLE}, an
     * algorithm it does not support {@link IndeterminateReason#UNSUPPORTED_ALGORITHM} — and status
     * with none of these means GnuPG itself did not run as expected.
     *
     * @param statusOutput the status lines
     * @return the verdict
     */
    static ToolVerdict verdict(String statusOutput) {
        Map<String, List<String[]>> status = statusLines(statusOutput);
        if (status.containsKey("BADSIG") || status.containsKey("REVKEYSIG")) {
            return ToolVerdict.failed();
        }
        if (status.containsKey("EXPKEYSIG")) {
            return expiredBeforeSigning(status) ? ToolVerdict.failed() : ToolVerdict.verified();
        }
        if (status.containsKey("GOODSIG")) {
            return ToolVerdict.verified();
        }
        return errSigVerdict(status);
    }

    private static ToolVerdict errSigVerdict(Map<String, List<String[]>> status) {
        String returnCode = status.getOrDefault("ERRSIG", List.of()).stream()
                .filter(fields -> fields.length > ERRSIG_RETURN_CODE)
                .map(fields -> fields[ERRSIG_RETURN_CODE])
                .findFirst().orElse(null);
        if (status.containsKey("NO_PUBKEY") || ERRSIG_NO_PUBLIC_KEY.equals(returnCode)) {
            return ToolVerdict.indeterminate(IndeterminateReason.KEY_UNAVAILABLE);
        }
        if (ERRSIG_UNSUPPORTED_ALGORITHM.equals(returnCode)) {
            return ToolVerdict.indeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM);
        }
        return ToolVerdict.indeterminate(IndeterminateReason.TOOL_UNAVAILABLE);
    }

    private static boolean expiredBeforeSigning(Map<String, List<String[]>> status) {
        List<String[]> validSig = status.getOrDefault("VALIDSIG", List.of());
        if (validSig.isEmpty() || validSig.get(0).length <= VALIDSIG_TIMESTAMP) {
            return true;
        }
        long signedAt = Long.parseLong(validSig.get(0)[VALIDSIG_TIMESTAMP]);
        return status.getOrDefault("KEYEXPIRED", List.of()).stream()
                .filter(fields -> fields.length > 2)
                .anyMatch(fields -> Long.parseLong(fields[2]) <= signedAt);
    }

    private static Map<String, List<String[]>> statusLines(String statusOutput) {
        Map<String, List<String[]>> lines = new HashMap<>();
        if (statusOutput == null) {
            return lines;
        }
        for (String line : statusOutput.split("\\R")) {
            String[] fields = line.trim().split("\\s+");
            if (fields.length > 1 && "[GNUPG:]".equals(fields[0])) {
                lines.computeIfAbsent(fields[1], keyword -> new ArrayList<>()).add(fields);
            }
        }
        return lines;
    }

    /**
     * Returns a fingerprint field of a {@code VALIDSIG} line in upper case.
     *
     * @param validSig the fields of the line, or {@code null} when there was none
     * @param index the field to return
     * @return the fingerprint, or {@code null} when there is no line or no such field
     */
    static String fingerprintField(String[] validSig, int index) {
        return validSig != null && validSig.length > index ? validSig[index].toUpperCase() : null;
    }

    private final String gpgExecutable;
    private final List<String> signingFingerprints;
    private final String passphrase;
    private final Map<String, String> env;
    private final Path gpgHome;
    private final OpenPgpSignatureFormat format;
    private final boolean signingCapable;
    private final boolean resolveSigners;
    private final boolean importToKeyring;
    private final List<String> keyservers;
    private final KeyFetchCache fetchCache;

    /**
     * Constructs a GpgRunner using the default "gpg" executable and default key.
     */
    GpgRunner() {
        this("gpg", null, null);
    }

    /**
     * Constructs a GpgRunner using the default "gpg" executable.
     *
     * @param signingFingerprint the full fingerprint of the key to sign with, passed to
     *        {@code --local-user}, or null to use GPG's default key
     */
    GpgRunner(String signingFingerprint) {
        this("gpg", signingFingerprint, null);
    }

    /**
     * Constructs a GpgRunner with a custom GPG executable path.
     *
     * @param gpgExecutable the path to the gpg executable (e.g., "gpg" or "/usr/bin/gpg")
     * @param signingFingerprint the full fingerprint of the key to sign with, passed to
     *        {@code --local-user}, or null to use GPG's default key
     * @throws IllegalArgumentException if gpgExecutable is null or empty
     */
    GpgRunner(String gpgExecutable, String signingFingerprint) {
        this(gpgExecutable, signingFingerprint, null);
    }

    /**
     * Constructs a GpgRunner with a custom GPG executable path and home directory.
     *
     * @param gpgExecutable the path to the gpg executable (e.g., "gpg" or "/usr/bin/gpg")
     * @param signingFingerprint the full fingerprint of the key to sign with, passed to
     *        {@code --local-user}, or null to use GPG's default key
     * @param home the GPG home directory, or null to use the default
     * @throws IllegalArgumentException if gpgExecutable is null or empty
     */
    GpgRunner(String gpgExecutable, String signingFingerprint, String home) {
        this(gpgExecutable, signingFingerprint == null ? List.of() : List.of(signingFingerprint), home, null,
                false, false, List.of());
    }

    /**
     * Constructs a GpgRunner with full configuration.
     *
     * @param gpgExecutable the path to the gpg executable
     * @param signingFingerprints the full fingerprints of the keys to sign with, each passed to
     *        {@code --local-user}, in order; empty to sign with GPG's default key
     * @param home the GPG home directory, or null to use the default
     * @param passphrase the GPG passphrase, or null to rely on gpg-agent
     * @param resolveSigners whether to fetch missing keys from keyservers
     * @param importToKeyring whether to persist fetched keys (GPG always persists, so
     *        this must be {@code true} for fetching to work)
     * @param keyservers keyserver URLs to fetch from
     * @throws IllegalArgumentException if gpgExecutable is null or empty
     */
    GpgRunner(String gpgExecutable, List<String> signingFingerprints, String home,
            String passphrase,
            boolean resolveSigners, boolean importToKeyring, List<String> keyservers) {
        this(gpgExecutable, signingFingerprints, home, passphrase, true, resolveSigners, importToKeyring, keyservers);
    }

    GpgRunner(String gpgExecutable, List<String> signingFingerprints, String home,
            String passphrase, boolean signingCapable,
            boolean resolveSigners, boolean importToKeyring, List<String> keyservers) {
        if (gpgExecutable == null || gpgExecutable.isEmpty()) {
            throw new IllegalArgumentException("gpgExecutable cannot be null or empty");
        }
        this.gpgExecutable = gpgExecutable;
        this.signingFingerprints = List.copyOf(signingFingerprints);
        this.passphrase = passphrase;
        this.signingCapable = signingCapable;
        this.env = home != null ? Map.of("GNUPGHOME", home) : null;
        this.gpgHome = home != null ? Path.of(home) : Path.of(System.getProperty("user.home"), ".gnupg");
        this.format = new OpenPgpSignatureFormat();
        this.resolveSigners = resolveSigners;
        this.importToKeyring = importToKeyring;
        this.keyservers = keyservers != null ? List.copyOf(keyservers) : List.of();
        this.fetchCache = new KeyFetchCache();
    }

    /**
     * {@inheritDoc}
     * <p>
     * Creates a detached ASCII-armored signature using GPG with options:
     * {@code --batch --yes --armor --detach-sign [--local-user <fingerprint>] --output outputSig artifactFile}.
     * With named keys, {@code key} must be one of them and is passed to {@code --local-user};
     * without, GPG signs with its default key whatever {@code key} names.
     *
     * @param artifactFile the file to sign
     * @param outputSig the path where the signature file will be written
     * @param key the key to sign with
     * @return a {@link SignResult} with the algorithm used
     * @throws IllegalArgumentException if artifactFile or outputSig is null, or {@code key} is
     *         not one of the named keys
     * @throws ToolExecutionException if the GPG command fails
     */
    @Override
    public SignResult sign(Path artifactFile, Path outputSig, SigningInfo key) {
        if (artifactFile == null) {
            throw new IllegalArgumentException("artifactFile cannot be null");
        }
        if (outputSig == null) {
            throw new IllegalArgumentException("outputSig cannot be null");
        }

        String[] command = buildSignCommand(artifactFile, outputSig, localUser(key));
        CliTool.Result result = passphrase != null
                ? CliTool.runWithStdin(env, passphrase + "\n", command)
                : CliTool.run(env, command);
        if (result.exitCode() != 0) {
            throw new ToolExecutionException("'" + String.join(" ", command)
                    + "' failed with exit code " + result.exitCode()
                    + (result.stderr().isEmpty() ? "" : ": " + result.stderr().trim()));
        }
        return new SignResult(algorithmOf(outputSig));
    }

    /**
     * Returns the fingerprint to pass to {@code --local-user}: the named key {@code key}
     * selects, or {@code null} for GPG's default key when no key is named.
     */
    private String localUser(SigningInfo key) {
        if (signingFingerprints.isEmpty()) {
            return null;
        }
        return SigningKeys.requireListed("gpg", signingFingerprints, key);
    }

    private static String algorithmOf(Path signature) {
        try {
            OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(Files.readString(signature));
            String name = Algorithms.algorithmName(info.algorithmId());
            return name != null ? name : "unknown";
        } catch (IOException e) {
            return "unknown";
        }
    }

    /**
     * Verifies a detached signature file for the specified artifact.
     * <p>
     * This method runs {@code gpg --status-fd 1 --verify <signatureFile> <artifactFile>}
     * and interprets the result. The human-readable report on stderr gives the outcome, key
     * ID, algorithm and user ID; the machine-readable status lines on stdout give, through
     * {@code VALIDSIG}, the full fingerprints of the signing key and its primary key, which a
     * signature carrying only a 64-bit key ID does not.
     * <p>
     * The outcome comes from the status lines, not the exit code: see {@link #verdict(String)}.
     * A missing public key is reported as {@link IndeterminateReason#KEY_UNAVAILABLE} rather
     * than as a failure: nothing about the artifact has been established, and the key may be
     * available on a later run.
     *
     * @param artifactFile the file that was signed
     * @param signatureFile the detached signature file to verify
     * @return a {@link GpgVerifyResult} carrying the outcome, any indeterminate reason, the
     *         extracted key ID and, for a good signature, the full fingerprints
     * @throws IllegalArgumentException if artifactFile or signatureFile is null
     */
    private GpgVerifyResult verifyFile(Path artifactFile, Path signatureFile) {
        if (artifactFile == null) {
            throw new IllegalArgumentException("artifactFile cannot be null");
        }
        if (signatureFile == null) {
            throw new IllegalArgumentException("signatureFile cannot be null");
        }

        CliTool.Result result = CliTool.run(env,
                gpgExecutable,
                "--status-fd", "1",
                "--verify",
                signatureFile.toString(),
                artifactFile.toString());

        String keyId = extractGpgKeyId(result.stderr());
        String algorithm = extractAlgorithm(result.stderr());
        String signerUserId = extractSignerUserId(result.stderr());

        ToolVerdict verdict = verdict(result.stdout());
        String[] validSig = validSigFields(result.stdout());
        return new GpgVerifyResult(verdict.outcome(), verdict.reason(), keyId, algorithm, signerUserId,
                fingerprintField(validSig, VALIDSIG_SIGNING_FINGERPRINT),
                fingerprintField(validSig, VALIDSIG_PRIMARY_FINGERPRINT));
    }

    /**
     * Receives a public key from a keyserver and imports it into the local keyring.
     *
     * @param keyId the key ID to receive
     * @param keyserver the keyserver URL (e.g., "hkps://keys.openpgp.org")
     * @return true if the key was successfully received, false otherwise
     */
    public boolean receiveKey(String keyId, String keyserver) {
        CliTool.Result result = CliTool.run(env,
                gpgExecutable,
                "--keyserver", keyserver,
                "--recv-keys", keyId);
        return result.exitCode() == 0;
    }

    /**
     * Checks whether a key is already present in the local GPG keyring.
     *
     * @param keyId the key ID or fingerprint to check
     * @return {@code true} if the key is in the keyring
     */
    private boolean hasKey(String keyId) {
        CliTool.Result result = CliTool.run(env,
                gpgExecutable, "--list-keys", keyId);
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
        CliTool.Result result = CliTool.run(env,
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
                if (fields.length > GPG_COLONS_FIELD_9 && !fields[GPG_COLONS_FIELD_9].isEmpty()) {
                    return fields[GPG_COLONS_FIELD_9];
                }
            }
        }
        return null;
    }

    @Override
    public String name() {
        return "gpg";
    }

    /**
     * {@inheritDoc}
     * <p>
     * Checks availability by running {@code gpg --version}.
     */
    @Override
    public boolean isAvailable() {
        return isToolAvailable();
    }

    /**
     * {@inheritDoc}
     * <p>
     * Returns {@code true} for a runner built for signing, whether it signs with a configured
     * fingerprint or, without one, with GPG's default key.
     */
    @Override
    public boolean canSign() {
        return signingCapable;
    }

    /**
     * Returns the fingerprints of the keys this runner signs with.
     *
     * @return the fingerprints passed to {@code --local-user}, in order; empty when gpg's
     *         default key is used
     */
    List<String> signingFingerprints() {
        return signingFingerprints;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Gives one entry per named key, in order, typed from its fingerprint's length when
     * {@code --list-secret-keys} cannot describe it. Without named keys, gives one entry for
     * GPG's default key — the {@code default-key} of {@code gpg.conf}, else the first secret
     * key — of unknown type when it cannot be listed.
     */
    @Override
    public List<SigningInfo> signingInfo() {
        if (signingFingerprints.isEmpty()) {
            return List.of(describeDefaultKey());
        }
        return signingFingerprints.stream().map(this::describeNamedKey).toList();
    }

    private SigningInfo describeNamedKey(String fingerprint) {
        CliTool.Result result = CliTool.run(env, gpgExecutable, "--list-secret-keys", "--with-colons", fingerprint);
        if (result.exitCode() != 0) {
            return new SigningInfo("gpg", fingerprint, null, null, KeyCredential.openPgp(fingerprint).type());
        }
        return namedSigningInfo(fingerprint, result.stdout());
    }

    /**
     * Describes a key the user named: the named fingerprint is kept, because the listing of a
     * subkey starts with its primary key's {@code fpr:} record. The algorithm is that of the
     * key record whose {@code fpr:} is the named fingerprint — a subkey's own, not its
     * primary's — falling back to the primary's when no record matches; the user ID is the
     * primary's.
     *
     * @param fingerprint the configured fingerprint
     * @param colonsOutput the output of {@code gpg --list-secret-keys --with-colons}
     * @return signing info carrying {@code fingerprint}
     */
    static SigningInfo namedSigningInfo(String fingerprint, String colonsOutput) {
        SigningInfo listed = parseColonsSigningInfo(colonsOutput);
        String algorithm = algorithmOfKeyRecord(fingerprint, colonsOutput);
        return new SigningInfo("gpg", fingerprint, algorithm != null ? algorithm : listed.algorithm(),
                listed.userId(), KeyCredential.openPgp(fingerprint).type());
    }

    /**
     * Finds the algorithm of the key record ({@code pub}, {@code sec}, {@code sub} or
     * {@code ssb}) that the {@code fpr:} record carrying {@code fingerprint} follows.
     *
     * @param fingerprint the fingerprint to find, in any case
     * @param colonsOutput the output of {@code gpg --with-colons}
     * @return the algorithm name, or {@code null} if no record carries the fingerprint
     */
    private static String algorithmOfKeyRecord(String fingerprint, String colonsOutput) {
        String recordAlgorithm = null;
        for (String line : colonsOutput.split("\\R")) {
            String[] fields = line.split(":", -1);
            if (isKeyRecord(fields[0])) {
                recordAlgorithm = fields.length > 4 ? algorithmName(fields[3]) : null;
            } else if ("fpr".equals(fields[0]) && fields.length > GPG_COLONS_FIELD_9
                    && fingerprint.equalsIgnoreCase(fields[GPG_COLONS_FIELD_9])) {
                return recordAlgorithm;
            }
        }
        return null;
    }

    private static boolean isKeyRecord(String recordType) {
        return switch (recordType) {
            case "pub", "sec", "sub", "ssb" -> true;
            default -> false;
        };
    }

    private static String algorithmName(String algorithmId) {
        try {
            return Algorithms.algorithmName(Integer.parseInt(algorithmId));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private SigningInfo describeDefaultKey() {
        String defaultKey = parseDefaultKey(gpgConfPath());
        CliTool.Result result = defaultKey != null
                ? CliTool.run(env, gpgExecutable, "--list-secret-keys", "--with-colons", defaultKey)
                : CliTool.run(env, gpgExecutable, "--list-secret-keys", "--with-colons");
        if (result.exitCode() != 0) {
            return new SigningInfo("gpg", defaultKey, null, null, null);
        }
        return parseColonsSigningInfo(result.stdout());
    }

    /**
     * Returns the path to the GPG configuration file ({@code gpg.conf})
     * in the effective GPG home directory.
     *
     * @return the path to {@code gpg.conf}
     */
    private Path gpgConfPath() {
        return gpgHome.resolve("gpg.conf");
    }

    /**
     * Parses the {@code default-key} directive from a {@code gpg.conf} file.
     * <p>
     * Scans the file line by line, skipping comments and blank lines.
     * If multiple {@code default-key} directives are present, the last one wins
     * (matching GPG's own behavior). Values are stripped of quotes, {@code 0x}
     * prefix, and {@code !} exact-subkey marker via {@link #stripKeyDecorations(String)}.
     *
     * @param gpgConfPath the path to the {@code gpg.conf} file
     * @return the default key identifier, or {@code null} if the file does not exist,
     *         is unreadable, or contains no {@code default-key} directive
     */
    static String parseDefaultKey(Path gpgConfPath) {
        if (gpgConfPath == null || !Files.isRegularFile(gpgConfPath)) {
            return null;
        }
        try {
            String result = null;
            for (String line : Files.readAllLines(gpgConfPath)) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    continue;
                }
                String[] parts = trimmed.split("\\s+", 2);
                if (parts.length == 2 && "default-key".equals(parts[0])) {
                    String value = stripKeyDecorations(parts[1]);
                    if (!value.isEmpty()) {
                        result = value;
                    }
                }
            }
            return result;
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * Strips syntactic decorations from a GPG key identifier.
     * <p>
     * Removes surrounding double quotes, leading {@code 0x}/{@code 0X} hex prefix,
     * and trailing {@code !} (exact-subkey marker), then trims whitespace.
     *
     * @param value the raw key identifier from {@code gpg.conf}
     * @return the cleaned key identifier
     */
    private static String stripKeyDecorations(String value) {
        if (value.startsWith("\"") && value.endsWith("\"") && value.length() > 1) {
            value = value.substring(1, value.length() - 1);
        }
        if (value.startsWith("0x") || value.startsWith("0X")) {
            value = value.substring(2);
        }
        if (value.endsWith("!")) {
            value = value.substring(0, value.length() - 1);
        }
        return value.trim();
    }

    /**
     * Parses GPG {@code --with-colons} output to extract signing identity information.
     * <p>
     * Extracts the algorithm from the first {@code pub:} or {@code sec:} record (field 3),
     * the fingerprint from the first {@code fpr:} record (field 9), and the user ID from
     * the first {@code uid:} record (field 9).
     *
     * @param colonsOutput the raw output from {@code gpg --list-keys --with-colons}
     * @return signing info with whatever fields could be parsed (nulls for missing fields)
     */
    static SigningInfo parseColonsSigningInfo(String colonsOutput) {
        String fingerprint = null;
        String algorithm = null;
        String userId = null;
        for (String line : colonsOutput.split("\\R")) {
            if (algorithm == null && (line.startsWith("pub:") || line.startsWith("sec:"))) {
                String[] fields = line.split(":", -1);
                if (fields.length > 4) {
                    try {
                        algorithm = Algorithms.algorithmName(Integer.parseInt(fields[3]));
                    } catch (NumberFormatException ignored) {
                    }
                }
            } else if (fingerprint == null && line.startsWith("fpr:")) {
                String[] fields = line.split(":", -1);
                if (fields.length > GPG_COLONS_FIELD_9) {
                    fingerprint = fields[GPG_COLONS_FIELD_9];
                }
            } else if (userId == null && line.startsWith("uid:")) {
                String[] fields = line.split(":", -1);
                if (fields.length > GPG_COLONS_FIELD_9
                        && !fields[GPG_COLONS_FIELD_9].isEmpty()) {
                    userId = fields[GPG_COLONS_FIELD_9];
                }
            }
            if (fingerprint != null && algorithm != null && userId != null) {
                break;
            }
        }
        return new SigningInfo("gpg", fingerprint, algorithm, userId, Credential.TYPE_PGP4);
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
     * Accepts {@link OpenPgpClaim}s with {@code packetVersion <= 4}.
     */
    @Override
    public boolean canVerify(Claim claim) {
        return claim instanceof OpenPgpClaim opgu
                && opgu.packetVersion() > 0
                && opgu.packetVersion() <= 4;
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * GnuPG verifies against the keyring in its home directory, which is the default home
     * when none was configured.
     */
    @Override
    public TrustRootRef trustRoot() {
        return TrustRootRef.gnupgKeyring(gpgHome);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Writes the armored block to a temp file, verifies via GPG, and wraps
     * the result into an {@link OpenPgpVerifyResult}.
     */
    @Override
    public VerifyResult verify(Path artifactFile, Claim claim) {
        if (!(claim instanceof OpenPgpClaim opgu)) {
            return OpenPgpVerifyResult.indeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM);
        }
        return verifyArmoredBlock(artifactFile, opgu);
    }

    @Override
    public List<Credential> extractCredentials(VerifyResult result) {
        return OpenPgpCredentials.from(result);
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * GPG requires keys in its on-disk keyring — ephemeral imports are not possible.
     * Returns {@code true} only when all three conditions are met:
     * {@code resolveSigners} is enabled, {@code importToKeyring} is {@code true}
     * (GPG always persists), and at least one keyserver is configured.
     */
    @Override
    public boolean canFetchKeys() {
        return resolveSigners && importToKeyring && !keyservers.isEmpty();
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * Checks the {@link KeyFetchCache} first to avoid unnecessary work for
     * keys already known to be missing. If the cache allows an attempt, checks
     * the local GPG keyring before hitting keyservers. Then runs
     * {@code gpg --keyserver <server> --recv-keys <keyId>} for each configured
     * keyserver. Connection-level failures (detected from GPG's stderr output)
     * trip the per-keyserver circuit breaker. If the key is not found on any
     * healthy server, it is added to the negative cache.
     */
    @Override
    public boolean fetchKey(String keyId) {
        if (!canFetchKeys()) {
            return false;
        }
        if (!fetchCache.shouldAttemptKey(keyId)) {
            return false;
        }
        if (hasKey(keyId)) {
            return true;
        }
        for (String keyserver : keyservers) {
            if (!fetchCache.shouldAttempt(keyserver, keyId)) {
                continue;
            }
            CliTool.Result result = CliTool.run(env,
                    gpgExecutable,
                    "--keyserver", keyserver,
                    "--recv-keys", keyId);
            if (result.exitCode() == 0) {
                fetchCache.recordSuccess(keyserver, keyId);
                return true;
            }
            if (isConnectionFailure(result)) {
                fetchCache.recordConnectionFailure(keyserver);
            }
        }
        fetchCache.recordKeyNotFound(keyId);
        return false;
    }

    private static boolean isConnectionFailure(CliTool.Result result) {
        String stderr = result.stderr();
        if (stderr == null) {
            return false;
        }
        return stderr.contains("no keyserver available")
                || stderr.contains("keyserver send failed")
                || stderr.contains("keyserver receive failed")
                || stderr.contains("Connection timed out")
                || stderr.contains("Network is unreachable");
    }

    /**
     * {@inheritDoc}
     * <p>
     * Delegates to {@link #listKeyUserId(String)}.
     */
    @Override
    public String lookupKeyUserId(String keyId) {
        return listKeyUserId(keyId);
    }

    private OpenPgpVerifyResult verifyArmoredBlock(Path artifactFile, OpenPgpClaim opgu) {
        Path sigFile = null;
        try {
            sigFile = Files.createTempFile("gpg-verify-", ".asc");
            Files.writeString(sigFile, opgu.armoredBlock());
            GpgVerifyResult gpgResult = verifyFile(artifactFile, sigFile);
            return toOpenPgpVerifyResult(gpgResult, opgu);
        } catch (IOException e) {
            throw new ToolExecutionException("Failed to create temp file for GPG verification", e);
        } finally {
            deleteSilently(sigFile);
        }
    }

    private OpenPgpVerifyResult toOpenPgpVerifyResult(GpgVerifyResult gpgResult, OpenPgpClaim opgu) {
        String fingerprint = opgu.issuerFingerprint() != null ? opgu.issuerFingerprint() : gpgResult.keyId();
        OpenPgpVerifyResult result = new OpenPgpVerifyResult(
                gpgResult.outcome(),
                gpgResult.reason(),
                gpgResult.signerUserId(),
                gpgResult.algorithm(),
                opgu.packetVersion(),
                gpgResult.keyId(),
                fingerprint);
        String signing = gpgResult.signingFingerprint();
        if (signing == null) {
            return result;
        }
        String primary = signing.equals(gpgResult.primaryFingerprint())
                ? null
                : gpgResult.primaryFingerprint();
        return result.withKeyFingerprints(signing, primary);
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
     * Builds the GPG sign command. When a passphrase is available,
     * adds {@code --pinentry-mode loopback --passphrase-fd 0} so the passphrase
     * can be piped via stdin.
     */
    private String[] buildSignCommand(Path artifactFile, Path outputSig, String localUser) {
        List<String> command = new ArrayList<>();
        command.add(gpgExecutable);
        command.add("--batch");
        command.add("--yes");
        command.add("--armor");
        command.add("--detach-sign");

        if (passphrase != null) {
            command.add("--pinentry-mode");
            command.add("loopback");
            command.add("--passphrase-fd");
            command.add("0");
        }

        if (localUser != null) {
            command.add("--local-user");
            command.add(localUser);
        }

        command.add("--output");
        command.add(outputSig.toString());
        command.add(artifactFile.toString());

        return command.toArray(new String[0]);
    }

}
