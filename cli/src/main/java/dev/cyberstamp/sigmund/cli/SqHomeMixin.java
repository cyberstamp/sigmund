package dev.cyberstamp.sigmund.cli;

import dev.cyberstamp.sigmund.core.ToolsConfig;
import dev.cyberstamp.sigmund.core.UserPaths;
import java.nio.file.Path;
import java.util.Map;
import picocli.CommandLine;

/**
 * Picocli mixin for the {@code --sq-home} option shared across CLI commands.
 */
public class SqHomeMixin {

    @CommandLine.Option(names = {
            "--sq-home" }, description = "Sequoia home directory (overrides tools.sq.home and SEQUOIA_HOME)")
    private String sqHome;

    boolean hasExplicitHome() {
        return sqHome != null && !sqHome.isEmpty();
    }

    Path resolveSequoiaHome() {
        if (sqHome != null && !sqHome.isEmpty()) {
            return UserPaths.expand(sqHome);
        }
        return null;
    }

    /**
     * Returns the tools configuration with {@code --sq-home} laid over {@code tools.sq.home}, or
     * unchanged when the option is not given.
     *
     * @param tools the configuration from the file
     * @return the configuration to use
     */
    ToolsConfig applyTo(ToolsConfig tools) {
        Path home = resolveSequoiaHome();
        return home == null ? tools : tools.withSettings("sq", Map.of("home", home.toString()));
    }
}
