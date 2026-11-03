package dev.cyberstamp.sigmund.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import org.apache.maven.plugin.MojoExecutionException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The signing goals read the same {@code sigmund.yaml} wherever Maven is started from: the one
 * {@code -Dsigmund.trustConfig} names, else the project's.
 */
class AbstractSigningMojoTest {

    private static final String WITH_PROFILE = "signing:\n  profiles:\n    %s: [pgp4]\n";

    @TempDir
    Path dir;

    @Test
    void theProjectsFileIsReadRatherThanTheCurrentDirectorys() throws Exception {
        Path project = Files.createDirectories(dir.resolve("module"));
        Files.writeString(project.resolve("sigmund.yaml"), WITH_PROFILE.formatted("from-project"));
        SignerInfoMojo mojo = new SignerInfoMojo();
        mojo.projectDir = project.toFile();

        assertThat(mojo.loadConfig().signingConfig().profiles()).containsOnlyKeys("from-project");
    }

    @Test
    void aNamedFileIsReadInsteadOfTheProjects() throws Exception {
        Path project = Files.createDirectories(dir.resolve("module"));
        Files.writeString(project.resolve("sigmund.yaml"), WITH_PROFILE.formatted("from-project"));
        Path named = Files.writeString(dir.resolve("release.yaml"), WITH_PROFILE.formatted("from-release"));
        SignerInfoMojo mojo = new SignerInfoMojo();
        mojo.projectDir = project.toFile();
        mojo.trustConfigFile = named.toFile();

        assertThat(mojo.loadConfig().signingConfig().profiles()).containsOnlyKeys("from-release");
    }

    @Test
    void aNamedFileThatDoesNotExistIsAnError() {
        SignerInfoMojo mojo = new SignerInfoMojo();
        mojo.projectDir = dir.toFile();
        mojo.trustConfigFile = dir.resolve("missing.yaml").toFile();

        assertThatThrownBy(mojo::loadConfig)
                .isInstanceOf(MojoExecutionException.class)
                .hasMessageContaining("missing.yaml");
    }
}
