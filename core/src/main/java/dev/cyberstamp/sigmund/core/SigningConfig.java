package dev.cyberstamp.sigmund.core;

import java.util.List;
import java.util.Map;

/**
 * Configures which identity to sign as and which signing tools to use.
 * <p>
 * References a signer from the shared {@code signers} registry by name.
 * The {@code toolchain} specifies which tools to use for signing and their
 * priority order.
 *
 * <h2>Credential type filtering</h2>
 * <p>
 * {@code credentialTypes} is the direct way to restrict which signature types are produced.
 * For example, {@code [pgp4, pgp6]} produces both OpenPGP v4 and v6 signatures.
 * When set, it serves as the default selection — the signing plan keeps the keys, across
 * all signing tools, whose credential type is in this list.
 * <p>
 * Named {@code profiles} are an opt-in overlay for scenarios that require switching
 * between different credential type sets at invocation time (e.g., {@code --profile classic}
 * vs {@code --profile hybrid}). When a profile is requested by name, it takes precedence
 * over {@code credentialTypes}. When neither is set, all available signing tools are used.
 *
 * <h2>Toolchain resolution</h2>
 * <p>
 * The {@code toolchain} list defines which signing tools to use and in what order.
 * If empty or {@code null}, the default toolchain from {@link VerificationConfig} is used.
 * Each tool name must have a corresponding entry in the top-level {@code tools} registry
 * for configuration lookup during initialization.
 *
 * @param signer the signer identity name (e.g., {@code "alice"}), or {@code null}
 * @param toolchain tools to use for signing and their priority order; empty means use default
 * @param credentialTypes default credential types to produce; empty means use all available
 * @param profiles named profiles mapping to credential type lists; opt-in overlay
 * @see VerificationConfig#effectiveToolchain()
 * @see ToolsConfig
 */
public record SigningConfig(
        String signer,
        List<String> toolchain,
        List<String> credentialTypes,
        Map<String, List<String>> profiles) {

    /**
     * Default signing configuration: no signer, empty toolchain, no credential types, no profiles.
     */
    public static final SigningConfig DEFAULT = new SigningConfig(null, List.of(), List.of(), Map.of());

    /**
     * Creates a signing config with defensive copies.
     */
    public SigningConfig {
        toolchain = toolchain != null ? List.copyOf(toolchain) : List.of();
        credentialTypes = credentialTypes != null ? List.copyOf(credentialTypes) : List.of();
        profiles = profiles != null ? Map.copyOf(profiles) : Map.of();
    }
}
