package dev.cyberstamp.sigmund.plugin;

import dev.cyberstamp.sigmund.core.ConfigLoader;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import java.io.File;
import java.nio.file.Path;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Parameter;

/**
 * Base class for goals that look their configuration up rather than read a project's policy:
 * the signing goals, {@code verify-signature} and {@code inspect-signer}.
 *
 * <p>
 * The file {@code sigmund.trustConfig} names is read, which must exist; without it,
 * {@code sigmund.yaml} in the project directory, else {@code ~/.config/sigmund/sigmund.yaml}, else
 * none. A goal run without a project looks in the directory Maven was started from, which is
 * then the project directory. The dependency goals read the project's policy file instead
 * ({@link AbstractDependencyMojo}), since what a build accepts belongs to the project.
 */
abstract class AbstractConfigLookupMojo extends AbstractSigmundMojo {

    /**
     * The configuration file. Without it, {@code sigmund.yaml} in the project directory is read,
     * else {@code ~/.config/sigmund/sigmund.yaml}, else the goal runs without configuration — never
     * a file that happens to be in the directory Maven was started from, when that is not the
     * project's.
     */
    @Parameter(property = "sigmund.trustConfig")
    protected File trustConfigFile;

    @Parameter(defaultValue = "${project.basedir}", readonly = true)
    protected File projectDir;

    /**
     * Loads the file {@link #trustConfigFile} names, which must exist, or the first of the
     * project's and the user's {@code sigmund.yaml}.
     *
     * @return the configuration, empty when there is none
     * @throws MojoExecutionException if a named file does not exist or the file does not parse
     */
    @Override
    protected SigmundConfig loadConfig() throws MojoExecutionException {
        try {
            return ConfigLoader.load(trustConfigFile == null ? null : trustConfigFile.toPath(),
                    projectDir == null ? Path.of(".") : projectDir.toPath());
        } catch (RuntimeException e) {
            throw new MojoExecutionException("Failed to load config: " + e.getMessage(), e);
        }
    }
}
