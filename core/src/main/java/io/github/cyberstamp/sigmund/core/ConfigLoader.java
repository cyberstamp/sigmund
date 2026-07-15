package io.github.cyberstamp.sigmund.core;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/**
 * Locates and loads {@code sigmund.yaml} configuration files.
 * <p>
 * Search order when no explicit path is provided:
 * <ol>
 * <li>{@code ./sigmund.yaml} (current working directory)</li>
 * <li>{@code ~/.config/sigmund/sigmund.yaml} (user config directory)</li>
 * </ol>
 * <p>
 * Returns a default {@link SigmundConfig} when no file is found.
 */
public class ConfigLoader {

    static final String CONFIG_FILENAME = "sigmund.yaml";

    private ConfigLoader() {
    }

    /**
     * Loads a {@link SigmundConfig} from the given path, or by searching
     * the default locations, or returns a default config if no file is found.
     *
     * @param explicitPath an explicit config file path, or {@code null} to search default locations
     * @return the loaded or default configuration, never {@code null}
     * @throws PolicyConfigException if an explicit path is given but the file does not exist,
     *         or if the file exists but cannot be parsed
     */
    public static SigmundConfig load(Path explicitPath) {
        return load(explicitPath, Path.of("."));
    }

    /**
     * Loads a {@link SigmundConfig}, searching from the given base directory
     * instead of the current working directory.
     *
     * @param explicitPath an explicit config file path, or {@code null} to search
     * @param baseDir the directory to search for {@code sigmund.yaml}
     * @return the loaded or default configuration, never {@code null}
     */
    public static SigmundConfig load(Path explicitPath, Path baseDir) {
        Path configFile = locate(explicitPath, baseDir);
        if (configFile == null) {
            return defaultConfig();
        }
        return SigmundConfig.parse(configFile);
    }

    /**
     * Locates the config file without loading it.
     *
     * @param explicitPath an explicit config file path, or {@code null} to search default locations
     * @return the located config file path, or {@code null} if no file was found
     * @throws PolicyConfigException if an explicit path is given but the file does not exist
     */
    public static Path locate(Path explicitPath) {
        return locate(explicitPath, Path.of("."));
    }

    /**
     * Locates the config file, searching from the given base directory.
     *
     * @param explicitPath an explicit config file path, or {@code null} to search
     * @param baseDir the directory to search for {@code sigmund.yaml}
     * @return the located config file path, or {@code null} if no file was found
     * @throws PolicyConfigException if an explicit path is given but the file does not exist
     */
    public static Path locate(Path explicitPath, Path baseDir) {
        if (explicitPath != null) {
            if (!Files.exists(explicitPath)) {
                throw new PolicyConfigException("Config file not found: " + explicitPath);
            }
            return explicitPath;
        }
        Path local = baseDir.resolve(CONFIG_FILENAME);
        if (Files.isRegularFile(local)) {
            return local;
        }
        Path userConfig = userConfigPath();
        if (userConfig != null && Files.isRegularFile(userConfig)) {
            return userConfig;
        }
        return null;
    }

    private static Path userConfigPath() {
        String home = System.getProperty("user.home");
        if (home == null) {
            return null;
        }
        return Path.of(home, ".config", "sigmund", CONFIG_FILENAME);
    }

    private static SigmundConfig defaultConfig() {
        return new SigmundConfig(1, Map.of(), null, null, null);
    }
}
