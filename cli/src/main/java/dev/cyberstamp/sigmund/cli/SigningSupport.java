package dev.cyberstamp.sigmund.cli;

import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.SigmundException;
import dev.cyberstamp.sigmund.core.Signer;
import dev.cyberstamp.sigmund.core.ToolConfig;
import dev.cyberstamp.sigmund.core.ToolsConfig;
import dev.cyberstamp.sigmund.core.VerificationConfig;
import java.util.List;
import java.util.Map;

/**
 * Shared logic for CLI commands that build a signing-capable Sigmund instance.
 */
final class SigningSupport {

    private SigningSupport() {
    }

    static Sigmund buildSigningSigmund(SigmundConfig config, SqHomeMixin sqHomeMixin) {
        Sigmund.Builder builder = Sigmund.builder().config(config);

        List<String> toolchain = config.signingConfig().toolchain();
        ToolsConfig toolsConfig = sqHomeMixin != null ? sqHomeMixin.applyTo(config.toolsConfig()) : config.toolsConfig();
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
                System.err.println("Note: signing tool '" + toolName + "' not available, skipping");
            }
        }

        return builder.build();
    }

    /**
     * Creates the signer for a named profile, or the default signer when none is named: the
     * profile's credential types, else {@code signing.credential-types}, choose the keys that sign.
     *
     * @param sigmund the configured instance
     * @param profile one of {@code signing.profiles}, or {@code null}
     * @return the signer
     */
    static Signer signer(Sigmund sigmund, String profile) {
        return profile != null ? sigmund.signer(profile) : sigmund.signer();
    }
}
