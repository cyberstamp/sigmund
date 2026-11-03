package dev.cyberstamp.sigmund.cli;

import dev.cyberstamp.sigmund.core.Credential;
import dev.cyberstamp.sigmund.core.CredentialParser;
import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.SignerInspectionReport;
import dev.cyberstamp.sigmund.core.SignerInspectionReportFormatter;
import dev.cyberstamp.sigmund.core.ToolsConfig;
import dev.cyberstamp.sigmund.core.VerificationConfig;
import java.util.List;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

/**
 * CLI command that inspects a signer identity across all available sources.
 *
 * <p>
 * Takes a signer identifier (a full fingerprint or an email) as input,
 * queries local stores and HKP keyservers, and prints a per-source report
 * showing key metadata, User IDs, and where the key was found vs. not found.
 *
 * <p>
 * The identifier is auto-detected by default: hex strings are treated as
 * fingerprints, strings containing {@code @} as emails. Explicit
 * {@code --fingerprint} or {@code --email} flags override auto-detection. A Sigstore
 * keyless identity has no key material to look up, so it cannot be inspected.
 *
 * @see SignerInspectionReportFormatter
 */
@Command(name = "inspect-signer", description = "Inspect a signer identity across available sources", mixinStandardHelpOptions = true)
public class InspectSignerCommand implements Callable<Integer> {

    @Parameters(index = "0", arity = "0..1", description = "Signer identifier (fingerprint or email, auto-detected)")
    String identifier;

    @Option(names = "--fingerprint", description = "Treat identifier as a fingerprint")
    boolean forceFingerprint;

    @Option(names = "--email", description = "Treat identifier as an email")
    boolean forceEmail;

    @Option(names = { "--keyservers", "--keyserver" }, split = ",", description = "Keyservers to query (comma-separated)")
    List<String> keyservers;

    @Option(names = "--tool", description = "Tool to use (bc, sq, gpg)")
    String tool;

    @Mixin
    SqHomeMixin sqHomeMixin;

    @Mixin
    ConfigMixin configMixin;

    @Override
    public Integer call() {
        try {
            Credential credential = buildCredential();
            try (Sigmund sigmund = buildSigmund()) {
                SignerInspectionReport report = sigmund.inspectSigner(credential, tool);
                SignerInspectionReportFormatter.format(report, System.out::println);
                return 0;
            }
        } catch (IllegalArgumentException e) {
            System.err.println("Error: " + e.getMessage());
            return 1;
        } catch (Exception e) {
            System.err.println("Inspection failed: " + e.getMessage());
            return 1;
        }
    }

    /**
     * Builds a {@link Credential} from the command-line arguments.
     *
     * <p>
     * Priority: forced email → forced fingerprint → auto-detection via
     * {@link CredentialParser#parse}.
     *
     * @return the parsed credential
     * @throws IllegalArgumentException if no identifier was provided or it cannot be parsed
     */
    Credential buildCredential() {
        if (identifier == null || identifier.isBlank()) {
            throw new IllegalArgumentException(
                    "Provide a fingerprint or email as a positional argument");
        }
        if (forceEmail) {
            return CredentialParser.fromEmail(identifier);
        }
        if (forceFingerprint) {
            return CredentialParser.fromFingerprint(identifier);
        }
        return CredentialParser.parse(identifier);
    }

    private Sigmund buildSigmund() {
        SigmundConfig config = loadConfigSafely();

        VerificationConfig fileVerification = config != null && config.verificationConfig() != null
                ? config.verificationConfig()
                : VerificationConfig.DEFAULT;
        ToolsConfig fileTools = config != null && config.toolsConfig() != null
                ? config.toolsConfig()
                : ToolsConfig.EMPTY;

        List<String> effectiveServers = keyservers != null
                ? keyservers
                : fileVerification.keyservers();
        boolean effectiveResolve = keyservers != null || fileVerification.resolveSigners();

        VerificationConfig verificationConfig = new VerificationConfig(
                effectiveResolve, fileVerification.importToKeyring(),
                effectiveServers, fileVerification.toolchain());

        ToolsConfig toolsConfig = sqHomeMixin.applyTo(fileTools);

        return Sigmund.builder()
                .verificationConfig(verificationConfig)
                .toolsConfig(toolsConfig)
                .build();
    }

    /**
     * Loads the config, returning {@code null} on failure instead of throwing.
     */
    private SigmundConfig loadConfigSafely() {
        try {
            return configMixin.loadConfig();
        } catch (Exception e) {
            System.err.println("WARNING: Could not load config: " + e.getMessage());
            return null;
        }
    }

}
