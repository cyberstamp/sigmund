package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class UserPathsTest {

    private static final Path USER_HOME = Path.of(System.getProperty("user.home"));

    @Test
    void aLeadingTildeIsTheUsersHome() {
        assertThat(UserPaths.expand("~/.gnupg")).isEqualTo(USER_HOME.resolve(".gnupg"));
    }

    @Test
    void aBareTildeIsTheUsersHome() {
        assertThat(UserPaths.expand("~")).isEqualTo(USER_HOME);
    }

    @Test
    void otherPathsAreReadAsWritten() {
        assertThat(UserPaths.expand("/srv/keys")).isEqualTo(Path.of("/srv/keys"));
        assertThat(UserPaths.expand("keys/~")).isEqualTo(Path.of("keys/~"));
        assertThat(UserPaths.expand("~other/keys")).isEqualTo(Path.of("~other/keys"));
    }
}
