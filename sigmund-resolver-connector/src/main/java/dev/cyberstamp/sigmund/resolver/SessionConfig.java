package dev.cyberstamp.sigmund.resolver;

import dev.cyberstamp.sigmund.core.ConfigLoader;
import dev.cyberstamp.sigmund.core.PolicyConfigException;
import java.nio.file.Path;
import org.apache.maven.execution.MavenSession;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.util.ConfigUtils;

/**
 * Where the extension's {@code sigmund.yaml} is, shared by verification and signing. Each reads it its own way:
 * verification compiles the policy, signing never does.
 */
public final class SessionConfig {

    private SessionConfig() {
    }

    /**
     * Locates the configuration file: the one {@link SigmundConfigurationKeys#CONFIG_PROP_CONFIG} names, else
     * {@code sigmund.yaml} in the build's root directory, else the user's {@code ~/.config/sigmund/sigmund.yaml}.
     *
     * @param session the session, whose config properties may name the file
     * @param rootDirectory the build's root directory
     * @return the file, or {@code null} when none is found
     * @throws PolicyConfigException if a named file does not exist
     */
    public static Path locate(RepositorySystemSession session, Path rootDirectory) {
        String explicit = ConfigUtils.getString(session, null, SigmundConfigurationKeys.CONFIG_PROP_CONFIG);
        return ConfigLoader.locate(explicit == null ? null : Path.of(explicit), rootDirectory);
    }

    /**
     * The build's root directory: the one Maven identifies by its {@code .mvn} directory, else the directory Maven
     * was started in.
     *
     * @param mavenSession the Maven session
     * @return the root directory
     */
    public static Path rootDirectory(MavenSession mavenSession) {
        try {
            return mavenSession.getRootDirectory();
        } catch (IllegalStateException noDotMvn) {
            // Maven finds no root without a .mvn directory, which loading this extension from .mvn/extensions.xml implies
            return mavenSession.getTopDirectory();
        }
    }
}
