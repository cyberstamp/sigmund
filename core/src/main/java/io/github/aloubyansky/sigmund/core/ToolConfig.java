package io.github.aloubyansky.sigmund.core;

import java.util.List;
import java.util.Map;

/**
 * Per-tool configuration overrides from the {@code signing.tools} section.
 *
 * @param credentials credential types this tool handles (overrides defaults), or {@code null}
 * @param settings tool-specific settings (e.g., {@code cipher-suite} for sq)
 */
public record ToolConfig(
        List<String> credentials,
        Map<String, String> settings) {

    /**
     * Creates a tool config with defensive copies.
     */
    public ToolConfig {
        credentials = credentials != null ? List.copyOf(credentials) : null;
        settings = settings != null ? Map.copyOf(settings) : Map.of();
    }
}
