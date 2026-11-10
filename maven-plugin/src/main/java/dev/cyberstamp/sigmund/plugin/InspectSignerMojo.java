package dev.cyberstamp.sigmund.plugin;

import dev.cyberstamp.sigmund.core.Credential;
import dev.cyberstamp.sigmund.core.CredentialParser;
import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.SignerInspectionReport;
import dev.cyberstamp.sigmund.core.SignerInspectionReportFormatter;
import dev.cyberstamp.sigmund.core.VerificationConfig;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

/**
 * Maven goal that inspects a signer identity across all available sources.
 *
 * <p>
 * Does not require dependency resolution — only needs tool configuration and
 * a signer credential. The credential is specified via Maven properties:
 * {@code sigmund.fingerprint} or {@code sigmund.email}. A Sigstore keyless identity has
 * no key material to look up, so it cannot be inspected.
 *
 * <p>
 * Output is printed to the Maven logger, grouped into local and remote
 * sources with per-source key metadata.
 *
 * <p>
 * Usage: {@code mvn sigmund:inspect-signer -Dsigmund.fingerprint=...}
 *
 * @see SignerInspectionReportFormatter
 */
@Mojo(name = "inspect-signer", requiresProject = false, threadSafe = true)
public class InspectSignerMojo extends AbstractConfigLookupMojo {

    @Parameter(property = "sigmund.fingerprint")
    String fingerprint;

    @Parameter(property = "sigmund.email")
    String email;

    @Parameter(property = "sigmund.tool")
    String tool;

    @Parameter(property = "sigmund.keyservers")
    String keyservers;

    @Parameter(property = "sigmund.resolveSigners")
    Boolean resolveSigners;

    @Override
    public void execute() throws MojoExecutionException {
        if (skip) {
            getLog().info("Skipping inspect-signer");
            return;
        }
        try {
            Credential credential = buildCredential();
            try (Sigmund sigmund = createSigmund()) {
                SignerInspectionReport report = sigmund.inspectSigner(credential, tool);
                SignerInspectionReportFormatter.format(report, msg -> getLog().info(msg));
            }
        } catch (IllegalArgumentException e) {
            throw new MojoExecutionException(e.getMessage(), e);
        } catch (Exception e) {
            throw new MojoExecutionException(
                    "Signer inspection failed: " + e.getMessage(), e);
        }
    }

    /**
     * Builds a {@link Credential} from the Maven properties.
     *
     * <p>
     * Priority: fingerprint → email.
     *
     * @return the parsed credential
     * @throws IllegalArgumentException if no credential properties are set
     */
    Credential buildCredential() {
        if (fingerprint != null && !fingerprint.isBlank()) {
            return CredentialParser.fromFingerprint(fingerprint);
        }
        if (email != null && !email.isBlank()) {
            return CredentialParser.fromEmail(email);
        }
        throw new IllegalArgumentException(
                "One of sigmund.fingerprint or sigmund.email is required");
    }

    private Sigmund createSigmund() throws MojoExecutionException {
        SigmundConfig config = loadConfig();
        VerificationConfig verificationConfig = resolveVerificationConfig(
                config.verificationConfig(), resolveSigners, keyservers, null);
        return buildSigmund(verificationConfig, mergeToolOverrides(config.toolsConfig()));
    }
}
