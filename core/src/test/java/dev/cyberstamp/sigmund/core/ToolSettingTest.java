package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * A path a tool setting holds is read through {@link UserPaths#expand}, so {@code ~} is the user's
 * home directory, as the documentation writes paths.
 */
class ToolSettingTest {

    private enum Setting implements ToolSetting {
        HOME;

        @Override
        public String key() {
            return "home";
        }
    }

    private static final Path USER_HOME = Path.of(System.getProperty("user.home"));

    @Test
    void aPathSettingExpandsALeadingTilde() {
        assertThat(Setting.HOME.pathFrom(Map.of("home", "~/.gnupg"))).isEqualTo(USER_HOME.resolve(".gnupg"));
    }

    @Test
    void anUnsetPathIsNull() {
        assertThat(Setting.HOME.pathFrom(Map.of())).isNull();
    }
}
