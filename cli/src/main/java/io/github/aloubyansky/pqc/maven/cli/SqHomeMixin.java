package io.github.aloubyansky.pqc.maven.cli;

import io.github.aloubyansky.pqc.maven.core.SqRunner;
import java.nio.file.Path;
import picocli.CommandLine;

/**
 * Picocli mixin for the {@code --sq-home} option and path utilities
 * shared across CLI commands.
 */
public class SqHomeMixin {

    @CommandLine.Option(names = { "--sq-home" }, description = "Sequoia home directory (default: ~/.local/share/sequoia)")
    private String sqHome;

    Path resolveSequoiaHome() {
        if (sqHome != null && !sqHome.isEmpty()) {
            return expandTilde(sqHome);
        }
        return SqRunner.defaultHome();
    }

    Path expandTilde(String path) {
        if (path.startsWith("~/")) {
            String userHome = System.getProperty("user.home");
            return Path.of(userHome, path.substring(2));
        }
        return Path.of(path);
    }
}
