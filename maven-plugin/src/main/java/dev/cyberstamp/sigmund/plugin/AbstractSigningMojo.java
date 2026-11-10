package dev.cyberstamp.sigmund.plugin;

import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.SigmundException;
import dev.cyberstamp.sigmund.core.Signer;
import dev.cyberstamp.sigmund.core.ToolConfig;
import dev.cyberstamp.sigmund.core.ToolsConfig;
import dev.cyberstamp.sigmund.core.VerificationConfig;
import java.util.List;
import java.util.Map;
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
            Sigmund.Builder builder = Sigmund.builder().config(config).toolsConfig(toolsConfig);

            List<String> toolchain = config.signingConfig().toolchain();
            List<String> toolNames = toolchain.isEmpty()
                    ? VerificationConfig.DEFAULT_TOOL_PRIORITY
                    : toolchain;

            for (String toolName : toolNames) {
                ToolConfig toolConfig = toolsConfig.get(toolName);
                Map<String, String> settings = toolConfig == null ? Map.of() : toolConfig.settings();
                try {
                    builder.addSigningTool(toolName, settings);
                } catch (SigmundException e) {
                    if (toolchain.contains(toolName)) {
                        throw e;
                    }
                    getLog().debug("Signing tool '" + toolName + "' not available, skipping");
                }
            }

            return builder.build();
        } catch (SigmundException e) {
            throw new MojoExecutionException("Failed to initialize signing tools", e);
        }
    }
}
