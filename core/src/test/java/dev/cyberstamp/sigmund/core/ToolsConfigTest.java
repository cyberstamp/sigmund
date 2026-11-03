package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ToolsConfigTest {

    @Test
    void getReturnsTool() {
        var tc = new ToolsConfig(Map.of("bc", new ToolConfig(Map.of("key", "val"))));
        assertThat(tc.get("bc")).isNotNull();
        assertThat(tc.get("bc").settings().get("key")).isEqualTo("val");
    }

    @Test
    void getReturnsNullForUnknown() {
        var tc = ToolsConfig.EMPTY;
        assertThat(tc.get("bc")).isNull();
    }

    @Test
    void toolNamesReturnsAllKeys() {
        var tc = new ToolsConfig(Map.of(
                "bc", new ToolConfig(Map.of()),
                "sq", new ToolConfig(Map.of())));
        assertThat(tc.toolNames().size()).isEqualTo(2);
        assertThat(tc.toolNames().contains("bc")).isTrue();
        assertThat(tc.toolNames().contains("sq")).isTrue();
    }

    @Test
    void emptyConfig() {
        assertThat(ToolsConfig.EMPTY.isEmpty()).isTrue();
        assertThat(ToolsConfig.EMPTY.size()).isEqualTo(0);
    }

    @Test
    void nonEmptyConfig() {
        var tc = new ToolsConfig(Map.of("bc", new ToolConfig(Map.of())));
        assertThat(tc.isEmpty()).isFalse();
        assertThat(tc.size()).isEqualTo(1);
    }

    @Test
    void nullMapBecomesEmpty() {
        var tc = new ToolsConfig(null);
        assertThat(tc.isEmpty()).isTrue();
        assertThat(tc.size()).isEqualTo(0);
    }

    @Test
    void anOverrideKeepsTheToolsOtherSettingsAndTheirShape() {
        var written = new ToolsConfig(Map.of(
                "sq", new ToolConfig(Map.of("home", "/from/file", "signing-fingerprint", "AAAA,BBBB"),
                        Set.of("signing-fingerprint")),
                "bc", new ToolConfig(Map.of("cipher-suite", "ed25519"))));

        ToolsConfig merged = written.withSettings("sq", Map.of("home", "/from/command-line"));

        assertThat(merged.get("sq").settings()).containsEntry("home", "/from/command-line")
                .containsEntry("signing-fingerprint", "AAAA,BBBB");
        assertThat(merged.get("sq").lists()).containsExactly("signing-fingerprint");
        assertThat(merged.get("bc")).isEqualTo(written.get("bc"));
        assertThat(written.get("sq").settings()).containsEntry("home", "/from/file");
    }

    @Test
    void anOverrideForAToolTheFileDoesNotConfigureIsItsOnlySetting() {
        ToolsConfig merged = ToolsConfig.EMPTY.withSettings("gpg", Map.of("home", "/gpg"));

        assertThat(merged.get("gpg").settings()).containsExactly(Map.entry("home", "/gpg"));
    }
}
