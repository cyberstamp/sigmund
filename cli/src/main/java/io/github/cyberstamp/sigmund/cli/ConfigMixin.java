package io.github.cyberstamp.sigmund.cli;

import io.github.cyberstamp.sigmund.core.ConfigLoader;
import io.github.cyberstamp.sigmund.core.SigmundConfig;
import java.nio.file.Path;
import picocli.CommandLine;

/**
 * Picocli mixin providing the {@code --config} option for loading a
 * {@code sigmund.yaml} configuration file.
 */
public class ConfigMixin {

    @CommandLine.Option(names = { "--config" }, description = "Path to sigmund.yaml config file")
    private String configPath;

    /**
     * Loads the configuration from the explicit path (if given) or from default
     * locations. Returns a default config if no file is found.
     *
     * @return the loaded configuration, never {@code null}
     */
    public SigmundConfig loadConfig() {
        Path explicit = configPath != null ? Path.of(configPath) : null;
        return ConfigLoader.load(explicit);
    }
}
