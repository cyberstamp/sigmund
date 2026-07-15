package io.github.cyberstamp.sigmund.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ConfigLoaderTest {

    private static final String MINIMAL_CONFIG = """
            version: 1
            signers:
              alice:
                email: alice@example.com
            """;

    @Test
    void explicitPathFound(@TempDir Path tempDir) throws IOException {
        Path configFile = tempDir.resolve("custom.yaml");
        Files.writeString(configFile, MINIMAL_CONFIG);

        SigmundConfig config = ConfigLoader.load(configFile);
        assertNotNull(config);
        assertEquals(1, config.version());
        assertTrue(config.signers().containsKey("alice"));
    }

    @Test
    void explicitPathMissing(@TempDir Path tempDir) {
        Path missing = tempDir.resolve("nonexistent.yaml");
        assertThrows(PolicyConfigException.class, () -> ConfigLoader.load(missing));
    }

    @Test
    void defaultConfigValues(@TempDir Path tempDir) {
        Path missing = tempDir.resolve("nonexistent.yaml");
        // Use locate to verify no file, then check default config shape
        assertNull(ConfigLoader.locate(null, missing));

        SigmundConfig config = ConfigLoader.load(null, missing);
        assertNotNull(config);
        assertEquals(1, config.version());
        assertTrue(config.signers().isEmpty());
        assertEquals(SigningConfig.DEFAULT, config.signingConfig());
        assertEquals(ToolsConfig.DEFAULT, config.toolsConfig());
    }

    @Test
    void locateExplicitPathFound(@TempDir Path tempDir) throws IOException {
        Path configFile = tempDir.resolve("sigmund.yaml");
        Files.writeString(configFile, MINIMAL_CONFIG);

        Path located = ConfigLoader.locate(configFile);
        assertEquals(configFile, located);
    }

    @Test
    void locateExplicitPathMissing(@TempDir Path tempDir) {
        Path missing = tempDir.resolve("nonexistent.yaml");
        assertThrows(PolicyConfigException.class, () -> ConfigLoader.locate(missing));
    }

    @Test
    void locateFindsFileInDirectory(@TempDir Path tempDir) throws IOException {
        Path configFile = tempDir.resolve("sigmund.yaml");
        Files.writeString(configFile, MINIMAL_CONFIG);

        Path located = ConfigLoader.locate(null, tempDir);
        assertEquals(configFile, located);
    }

    @Test
    void locateReturnsNullWhenDirHasNoConfig(@TempDir Path tempDir) {
        assertNull(ConfigLoader.locate(null, tempDir));
    }
}
