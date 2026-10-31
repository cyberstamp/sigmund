package dev.cyberstamp.sigmund.core;

import java.util.Map;
import java.util.Set;

/**
 * One tool's settings from the top-level {@code tools} section.
 * <p>
 * Settings are keyed by name, as written. The parser checks only their shape; which settings a
 * tool accepts, and which of them may be lists, is declared by its
 * {@link SignatureToolFactory#acceptedSettings()} and {@link SignatureToolFactory#listSettings()}
 * and checked when tools are built.
 *
 * @param settings tool-specific settings (e.g., {@code gnupg-home} for bc); a setting written as a
 *        list is joined with {@link ToolSetting#LIST_SEPARATOR}
 * @param lists the names of the settings written as a YAML list
 */
public record ToolConfig(Map<String, String> settings, Set<String> lists) {

    /**
     * Creates a tool config with defensive copies.
     */
    public ToolConfig {
        settings = settings != null ? Map.copyOf(settings) : Map.of();
        lists = lists != null ? Set.copyOf(lists) : Set.of();
    }

    /**
     * Creates a tool config whose settings are all single values.
     *
     * @param settings tool-specific settings
     */
    public ToolConfig(Map<String, String> settings) {
        this(settings, Set.of());
    }
}
