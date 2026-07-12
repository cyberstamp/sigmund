package io.github.aloubyansky.sigmund.plugin;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SequoiaHomeResolverTest {

    @Test
    void toolOverridesWithExplicitPath() {
        File sqHome = new File("/custom/sequoia/home");
        Map<String, Map<String, String>> overrides = SequoiaHomeResolver.toolOverrides(sqHome);
        assertEquals(sqHome.toPath().toString(), overrides.get("sq").get("home"));
    }

    @Test
    void toolOverridesWithNullReturnsEmpty() {
        Map<String, Map<String, String>> overrides = SequoiaHomeResolver.toolOverrides(null);
        assertTrue(overrides.isEmpty());
    }
}
