package io.github.aloubyansky.sigmund.plugin;

import java.io.File;
import java.util.Map;

/**
 * Builds tool setting overrides for the Sequoia home directory.
 */
final class SequoiaHomeResolver {

    private SequoiaHomeResolver() {
    }

    /**
     * Returns discovery tool overrides for the sq home directory.
     *
     * @param sqHome the configured sqHome parameter, or {@code null} if not set
     * @return tool overrides map (empty if sqHome is null)
     */
    static Map<String, Map<String, String>> toolOverrides(File sqHome) {
        if (sqHome == null) {
            return Map.of();
        }
        return Map.of("sq", Map.of("home", sqHome.toPath().toString()));
    }
}
