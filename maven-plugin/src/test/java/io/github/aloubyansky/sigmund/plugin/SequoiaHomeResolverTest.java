package io.github.aloubyansky.sigmund.plugin;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.nio.file.Path;
import org.apache.maven.plugin.MojoExecutionException;
import org.junit.jupiter.api.Test;

class SequoiaHomeResolverTest {

    @Test
    void resolveExplicitPathReturnsIt() throws MojoExecutionException {
        File sqHome = new File("/custom/sequoia/home");
        Path result = SequoiaHomeResolver.resolve(sqHome);
        assertEquals(sqHome.toPath(), result);
    }

    @Test
    void resolveNullReturnsDefaultHome() throws MojoExecutionException {
        Path result = SequoiaHomeResolver.resolve(null);
        assertNotNull(result);
        assertTrue(result.toString().endsWith(".local/share/sequoia"));
    }
}
