package dev.cyberstamp.sigmund.core;

import java.util.Map;

/**
 * Settings {@link Sigmund.Builder} passes to signing tools about the run rather than the tool.
 * <p>
 * Like {@link FetchSetting}, they reach the tool in its settings map but are never written under
 * {@code tools}, so no factory lists them in {@link SignatureToolFactory#acceptedSettings()}.
 */
enum SessionSetting implements ToolSetting {

    /**
     * Whether a tool may ask the user, such as for a key's passphrase: {@code false} when the build
     * runs unattended ({@link Sigmund.Builder#interactive(boolean)}). Absent means it may.
     */
    INTERACTIVE("interactive");

    private final String key;

    SessionSetting(String key) {
        this.key = key;
    }

    @Override
    public String key() {
        return key;
    }

    /**
     * Whether the run lets a tool ask the user.
     *
     * @param settings the tool's settings
     * @return {@code false} only when the builder said the run is not interactive
     */
    static boolean interactive(Map<String, String> settings) {
        return !"false".equals(INTERACTIVE.from(settings));
    }
}
