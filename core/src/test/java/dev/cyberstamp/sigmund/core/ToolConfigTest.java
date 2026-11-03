package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ToolConfigTest {

    private static final ToolConfig WRITTEN = new ToolConfig(
            Map.of("home", "/from/file", "signing-fingerprint", "AAAA,BBBB"), Set.of("signing-fingerprint"));

    @Test
    void anOverrideKeepsTheListsItLeavesAlone() {
        ToolConfig merged = WRITTEN.withSettings(Map.of("home", "/from/command-line"));

        assertThat(merged.settings()).containsEntry("home", "/from/command-line")
                .containsEntry("signing-fingerprint", "AAAA,BBBB");
        assertThat(merged.lists()).containsExactly("signing-fingerprint");
    }

    @Test
    void anOverriddenListBecomesTheSingleValueGiven() {
        ToolConfig merged = WRITTEN.withSettings(Map.of("signing-fingerprint", "CCCC"));

        assertThat(merged.settings()).containsEntry("signing-fingerprint", "CCCC");
        assertThat(merged.lists()).isEmpty();
    }
}
