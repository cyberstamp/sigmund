package dev.cyberstamp.sigmund.core;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * One setting a tool reads from its settings map, named once.
 * <p>
 * A tool factory declares its settings as an enum implementing this interface, reads them only
 * through it and derives {@link SignatureToolFactory#acceptedSettings()} from the enum's values.
 * Reading a setting and accepting it are then the same symbol: a new setting cannot be read
 * without being declared, and one that is no longer read shows as an unused constant rather
 * than as a setting that is accepted and ignored.
 */
public interface ToolSetting {

    /**
     * The separator between the items of a list-valued setting in the settings map: a list
     * written in {@code sigmund.yaml} reaches a factory joined with it. A setting declared as a
     * list must therefore not accept items containing this separator; fingerprints cannot.
     */
    String LIST_SEPARATOR = ",";

    /**
     * Returns the setting's name as written under {@code tools.<name>} in {@code sigmund.yaml}.
     *
     * @return the key, never {@code null}
     */
    String key();

    /**
     * Returns whether this setting may be written as a YAML list.
     * <p>
     * A setting that takes a list says so here, on its constant, and
     * {@link SignatureToolFactory#listSettings()} is derived from it. The default is
     * {@code false}: a list given to any other setting is a configuration error.
     *
     * @return {@code true} when the setting takes a list
     */
    default boolean takesList() {
        return false;
    }

    /**
     * Reads this setting as a list.
     *
     * @param settings the tool's settings
     * @return the items in written order, empty when the setting is unset or empty
     */
    default List<String> listFrom(Map<String, String> settings) {
        String value = from(settings);
        if (value == null || value.isEmpty()) {
            return List.of();
        }
        return List.of(value.split(LIST_SEPARATOR, -1));
    }

    /**
     * Reads this setting.
     *
     * @param settings the tool's settings
     * @return the value, or {@code null} when not set
     */
    default String from(Map<String, String> settings) {
        return settings.get(key());
    }

    /**
     * Reads this setting, falling back to a default.
     *
     * @param settings the tool's settings
     * @param defaultValue the value when not set
     * @return the value, or {@code defaultValue} when not set
     */
    default String from(Map<String, String> settings, String defaultValue) {
        return settings.getOrDefault(key(), defaultValue);
    }

    /**
     * Reads this setting as a flag.
     *
     * @param settings the tool's settings
     * @return {@code true} only when the value is {@code true}
     */
    default boolean isTrue(Map<String, String> settings) {
        return "true".equals(from(settings));
    }

    /**
     * Returns the keys of the given settings that take a list, for
     * {@link SignatureToolFactory#listSettings()}.
     *
     * @param settings the settings, typically an enum's {@code values()}
     * @return the keys of those whose {@link #takesList()} is {@code true}
     */
    static Set<String> listKeysOf(ToolSetting... settings) {
        return Arrays.stream(settings).filter(ToolSetting::takesList).map(ToolSetting::key)
                .collect(Collectors.toUnmodifiableSet());
    }

    /**
     * Returns the keys of the given settings, for {@link SignatureToolFactory#acceptedSettings()}.
     *
     * @param settings the settings, typically an enum's {@code values()}
     * @return their keys
     */
    static Set<String> keysOf(ToolSetting... settings) {
        return Arrays.stream(settings).map(ToolSetting::key).collect(Collectors.toUnmodifiableSet());
    }
}
