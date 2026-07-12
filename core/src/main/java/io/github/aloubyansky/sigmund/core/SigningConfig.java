package io.github.aloubyansky.sigmund.core;

import java.util.List;
import java.util.Map;

/**
 * Configures which identity to sign as and which credential types to use.
 * <p>
 * References a signer from the shared {@code signers} registry by name.
 * Profiles select subsets of credential types for different signing scenarios.
 *
 * @param signer the signer identity name (e.g., {@code "alice"}), or {@code null}
 * @param tools per-tool overrides keyed by tool name
 * @param profiles named profiles mapping to credential type lists
 * @param defaultProfile the default profile name, or {@code null} to use all credentials
 */
public record SigningConfig(
        String signer,
        Map<String, ToolConfig> tools,
        Map<String, List<String>> profiles,
        String defaultProfile) {

    /**
     * Default signing configuration: no signer, no overrides, no profiles.
     */
    public static final SigningConfig DEFAULT = new SigningConfig(null, Map.of(), Map.of(), null);

    /**
     * Creates a signing config with defensive copies.
     */
    public SigningConfig {
        tools = tools != null ? Map.copyOf(tools) : Map.of();
        profiles = profiles != null ? Map.copyOf(profiles) : Map.of();
    }
}
