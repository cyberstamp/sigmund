package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * A path a tool setting holds is read as a shell would read it at the start: {@code ~} is the
 * user's home directory, since YAML leaves it as written and the documentation writes paths so.
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
    void aLeadingTildeIsTheUsersHome() {
        assertThat(Setting.HOME.pathFrom(Map.of("home", "~/.gnupg"))).isEqualTo(USER_HOME.resolve(".gnupg"));
    }

    @Test
    void aBareTildeIsTheUsersHome() {
        assertThat(Setting.HOME.pathFrom(Map.of("home", "~"))).isEqualTo(USER_HOME);
    }

    @Test
    void otherPathsAreReadAsWritten() {
        assertThat(Setting.HOME.pathFrom(Map.of("home", "/srv/keys"))).isEqualTo(Path.of("/srv/keys"));
        assertThat(Setting.HOME.pathFrom(Map.of("home", "keys/~"))).isEqualTo(Path.of("keys/~"));
        assertThat(Setting.HOME.pathFrom(Map.of("home", "~other/keys"))).isEqualTo(Path.of("~other/keys"));
    }

    @Test
    void anUnsetPathIsNull() {
        assertThat(Setting.HOME.pathFrom(Map.of())).isNull();
    }
}
