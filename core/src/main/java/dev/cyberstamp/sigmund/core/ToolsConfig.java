package dev.cyberstamp.sigmund.core;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Read-only registry of per-tool configurations, parsed from the top-level
 * {@code tools} section of {@code sigmund.yaml}.
 * <p>
 * Each entry maps a tool name to its {@link ToolConfig} containing credentials
 * and settings. The registry is ordered by insertion (YAML declaration order).
 * <p>
 * Tool configurations provide per-tool overrides for credential types and
 * tool-specific settings (e.g., cipher suite, key formats). These are combined
 * with operational settings from {@link VerificationConfig} during tool initialization.
 *
 * @see ToolConfig
 * @see SigmundConfig
 * @see VerificationConfig
 */
public class ToolsConfig {

    /** Empty tool registry. */
    public static final ToolsConfig EMPTY = new ToolsConfig(Map.of());

    private final Map<String, ToolConfig> tools;

    /**
     * Creates a tool registry from the given map.
     * <p>
     * The map is defensively copied using {@link LinkedHashMap} to preserve
     * insertion order (YAML declaration order).
     *
     * @param tools tool configurations keyed by tool name
     */
    public ToolsConfig(Map<String, ToolConfig> tools) {
        this.tools = tools != null
                ? new LinkedHashMap<>(tools)
                : new LinkedHashMap<>();
    }

    /**
     * Returns the configuration for the given tool, or {@code null} if not registered.
     * <p>
     * A {@code null} result means no tool-specific overrides are configured for
     * that tool name — the tool should use its defaults.
     *
     * @param toolName the tool name (e.g., {@code "bc"}, {@code "sq"}, {@code "gpg"})
     * @return the tool configuration, or {@code null} if not found
     */
    public ToolConfig get(String toolName) {
        return tools.get(toolName);
    }

    /**
     * Returns all registered tool names.
     * <p>
     * The returned set preserves insertion order (YAML declaration order).
     *
     * @return an unmodifiable set of tool names, never {@code null}
     */
    public Set<String> toolNames() {
        return Collections.unmodifiableSet(new LinkedHashSet<>(tools.keySet()));
    }

    /**
     * Returns whether this registry is empty.
     * <p>
     * An empty registry means no tool-specific overrides are configured.
     *
     * @return {@code true} if no tools are registered
     */
    public boolean isEmpty() {
        return tools.isEmpty();
    }

    /**
     * Returns the number of registered tools.
     *
     * @return the number of tools in the registry
     */
    public int size() {
        return tools.size();
    }

    /**
     * Returns a copy with single-valued settings laid over one tool's, such as a home directory
     * given on the command line.
     *
     * <p>
     * The tool's other settings keep their shape (see {@link ToolConfig#withSettings(Map)}); a
     * tool the file does not configure gets the overrides as its only settings.
     *
     * @param toolName the tool to override, such as {@code sq}
     * @param overrides the settings to set, each a single value
     * @return the copy
     */
    public ToolsConfig withSettings(String toolName, Map<String, String> overrides) {
        Map<String, ToolConfig> copy = new LinkedHashMap<>(tools);
        ToolConfig existing = copy.get(toolName);
        copy.put(toolName, existing != null ? existing.withSettings(overrides) : new ToolConfig(overrides));
        return new ToolsConfig(copy);
    }
}
