package dev.cyberstamp.sigmund.core;

import java.util.List;

/**
 * How verification runs, parsed from the {@code verification} section of {@code sigmund.yaml}.
 * <p>
 * Contains operational concerns: key fetching behavior, keyserver URLs, and the verification
 * toolchain. These configure how claims are checked, never what policy requires, so widening
 * them changes what can be seen, not what is accepted. Per-tool settings live in
 * {@link ToolsConfig}.
 *
 * @param resolveSigners whether tools should fetch missing keys to resolve signer identities
 * @param importToKeyring whether to persist fetched keys into the tool's keyring
 * @param keyservers keyserver URLs for key fetching (empty = default)
 * @param toolchain tools to use for verification and their order; {@code null} means all available
 * @see ToolsConfig
 * @see SigmundConfig
 */
public record VerificationConfig(
        boolean resolveSigners,
        boolean importToKeyring,
        List<String> keyservers,
        List<String> toolchain) {

    /** Default keyservers, in the order they are asked for a missing key. */
    public static final List<String> DEFAULT_KEYSERVERS = List.of(
            "hkps://keys.openpgp.org", "hkps://keyserver.ubuntu.com");

    /** Default tool priority order. */
    public static final List<String> DEFAULT_TOOL_PRIORITY = List.of("bc", "sq", "gpg");

    /** Default verification configuration. */
    public static final VerificationConfig DEFAULT = new VerificationConfig(
            true, false, DEFAULT_KEYSERVERS, null);

    /**
     * Creates a verification config with defensive copies.
     */
    public VerificationConfig {
        keyservers = keyservers != null && !keyservers.isEmpty()
                ? List.copyOf(keyservers)
                : DEFAULT_KEYSERVERS;
        toolchain = toolchain != null && !toolchain.isEmpty()
                ? List.copyOf(toolchain)
                : null;
    }

    /**
     * Returns the toolchain for iteration, falling back to the default order
     * when {@link #toolchain()} is {@code null}.
     *
     * @return the effective toolchain list, never {@code null}
     */
    public List<String> effectiveToolchain() {
        return toolchain != null ? toolchain : DEFAULT_TOOL_PRIORITY;
    }

    /**
     * Parses a comma-separated keyservers string from tool settings.
     * Used by tool factories to read the injected {@code "keyservers"} setting.
     *
     * @param value comma-separated keyserver URLs, or {@code null}
     * @return the parsed list, or an empty list if the input is null or blank
     */
    public static List<String> parseKeyserversSetting(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        return List.of(value.split(","));
    }
}
