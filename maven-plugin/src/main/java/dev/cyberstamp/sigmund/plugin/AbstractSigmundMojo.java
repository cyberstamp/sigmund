package dev.cyberstamp.sigmund.plugin;

import dev.cyberstamp.sigmund.core.ConfigLoader;
import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.ToolsConfig;
import dev.cyberstamp.sigmund.core.VerificationConfig;
import java.io.File;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Parameter;

/**
 * Base class for mojos that need a configured {@link Sigmund} instance but do
 * not require Maven dependency resolution.
 *
 * <p>
 * Provides shared parameter handling (Sequoia home, GPG home, skip flag),
 * configuration loading, tool-override merging, and {@link Sigmund} builder
 * construction. Subclasses like {@link InspectSignerMojo} extend this directly;
 * mojos that also need dependency resolution extend {@link AbstractDependencyMojo}
 * instead.
 */
abstract class AbstractSigmundMojo extends AbstractMojo {

    @Parameter(property = "sigmund.sqHome")
    protected File sqHome;

    @Parameter(property = "sigmund.gpgHome")
    protected File gpgHome;

    @Parameter(property = "sigmund.skip", defaultValue = "false")
    protected boolean skip;

    /**
     * Loads the sigmund configuration from the default location.
     *
     * @return the parsed configuration
     * @throws MojoExecutionException if the configuration cannot be loaded
     */
    protected SigmundConfig loadConfig() throws MojoExecutionException {
        try {
            return ConfigLoader.load(null);
        } catch (Exception e) {
            throw new MojoExecutionException("Failed to load config", e);
        }
    }

    /**
     * Builds tool-specific configuration overrides from Maven properties.
     *
     * <p>
     * Merges Sequoia home ({@code sqHome}) and GnuPG home ({@code gpgHome})
     * overrides into a map keyed by tool name: {@code tools.sq.home} and
     * {@code tools.gpg.home}. BC reads public keys from the GnuPG home too, unless
     * {@code tools.bc.gnupg-home} is set; core derives that from {@code tools.gpg.home}.
     *
     * @return tool overrides map, possibly empty but never null
     */
    protected Map<String, Map<String, String>> toolOverrides() {
        var overrides = new HashMap<>(SequoiaHomeResolver.toolOverrides(sqHome));
        if (gpgHome != null) {
            overrides.put("gpg", Map.of("home", gpgHome.toPath().toString()));
        }
        return overrides;
    }

    /**
     * Merges file-based {@link VerificationConfig} with Maven property overrides.
     *
     * <p>
     * Each parameter, when non-null, takes precedence over the file configuration.
     * If signer resolution is enabled but no keyservers are configured, the
     * {@link VerificationConfig#DEFAULT_KEYSERVER default keyserver} is used.
     *
     * @param fileConfig base verification configuration from the config file
     * @param resolveSigners override for signer resolution, or {@code null} to use file config
     * @param keyservers comma-separated keyserver list override, or {@code null} to use file config
     * @param importToKeyring override for key import behavior, or {@code null} to use file config
     * @return the resolved verification configuration
     */
    protected VerificationConfig resolveVerificationConfig(VerificationConfig fileConfig,
            Boolean resolveSigners, String keyservers, Boolean importToKeyring) {
        if (keyservers == null) {
            keyservers = System.getProperty("sigmund.keyserver");
        }
        List<String> effectiveKeyservers = keyservers != null
                ? SignatureInspector.parseKeyservers(keyservers)
                : fileConfig.keyservers();
        boolean effectiveResolve = resolveSigners != null
                ? resolveSigners
                : (keyservers != null || fileConfig.resolveSigners());
        if (effectiveResolve && effectiveKeyservers.isEmpty()) {
            effectiveKeyservers = List.of(VerificationConfig.DEFAULT_KEYSERVER);
        }
        boolean effectiveImport = importToKeyring != null
                ? importToKeyring
                : fileConfig.importToKeyring();
        return new VerificationConfig(
                effectiveResolve, effectiveImport,
                effectiveKeyservers, fileConfig.toolchain());
    }

    /**
     * Merges tool overrides from Maven properties into a {@link ToolsConfig}.
     * <p>
     * For each tool override, if the tool already has a configuration in the
     * base config, the override settings are merged on top. Otherwise, a new
     * entry is created.
     *
     * @param baseConfig the base tool configuration from the config file
     * @return the merged tool configuration
     */
    protected ToolsConfig mergeToolOverrides(ToolsConfig baseConfig) {
        ToolsConfig merged = baseConfig;
        for (var override : toolOverrides().entrySet()) {
            merged = merged.withSettings(override.getKey(), override.getValue());
        }
        return merged;
    }

    /**
     * Builds a {@link Sigmund} instance with the given verification and tools configurations.
     *
     * @param verificationConfig the resolved verification configuration
     * @param toolsConfig the resolved tools configuration
     * @return a configured Sigmund instance
     */
    protected Sigmund buildSigmund(VerificationConfig verificationConfig, ToolsConfig toolsConfig) {
        return Sigmund.builder()
                .verificationConfig(verificationConfig)
                .toolsConfig(toolsConfig)
                .build();
    }
}
