package dev.cyberstamp.sigmund.plugin;

import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.SigmundException;
import dev.cyberstamp.sigmund.core.Signer;
import dev.cyberstamp.sigmund.core.ToolsConfig;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Parameter;

/**
 * Base class for signing-related goals, providing shared parameters and
 * signer creation logic.
 */
abstract class AbstractSigningMojo extends AbstractConfigLookupMojo {

    /**
     * Signing profile to use: one of {@code signing.profiles}, whose credential types choose the
     * keys that sign. If not set, {@code signing.credential-types} chooses them, or every key of
     * every signing tool signs when that is not set either.
     */
    @Parameter(property = "sigmund.profile")
    protected String profile;

    /**
     * The Maven session, whose interactive mode says whether a signing tool may ask for a key's
     * passphrase: under {@code mvn -B}, as on CI, it never prompts.
     */
    @Parameter(defaultValue = "${session}", readonly = true, required = true)
    protected MavenSession session;

    /**
     * Creates the signer for {@link #profile}, or the default signer when no profile is named.
     *
     * @param sigmund the configured instance
     * @return the signer
     */
    protected Signer signer(Sigmund sigmund) {
        if (profile == null) {
            return sigmund.signer();
        }
        getLog().info("Signing profile: " + profile);
        return sigmund.signer(profile);
    }

    protected Sigmund buildSigningSigmund() throws MojoExecutionException {
        try {
            SigmundConfig config = loadConfig();
            ToolsConfig toolsConfig = mergeToolOverrides(config.toolsConfig());
            return Sigmund.builder()
                    .config(config)
                    .toolsConfig(toolsConfig)
                    .interactive(session.getRequest().isInteractiveMode())
                    .addSigningTools(name -> getLog().debug("Signing tool '" + name + "' not available, skipping"))
                    .build();
        } catch (SigmundException e) {
            throw new MojoExecutionException("Failed to initialize signing tools", e);
        }
    }
}
