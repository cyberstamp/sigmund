package io.github.aloubyansky.pqc.maven.plugin;

import io.github.aloubyansky.pqc.maven.core.SqRunner;
import java.io.File;
import java.nio.file.Path;
import org.apache.maven.plugin.MojoExecutionException;

/**
 * Resolves the Sequoia home directory from plugin configuration or the default location.
 */
final class SequoiaHomeResolver {

    private SequoiaHomeResolver() {
    }

    /**
     * Resolves the Sequoia home directory.
     *
     * @param sqHome the configured sqHome parameter, or null for the default
     * @return the resolved path
     * @throws MojoExecutionException if the default cannot be determined
     */
    static Path resolve(File sqHome) throws MojoExecutionException {
        if (sqHome != null) {
            return sqHome.toPath();
        }
        Path defaultHome = SqRunner.defaultHome();
        if (defaultHome == null) {
            throw new MojoExecutionException("Cannot resolve Sequoia home: user.home not set");
        }
        return defaultHome;
    }
}
