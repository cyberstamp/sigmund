package dev.cyberstamp.sigmund.core;

import java.util.Map;
import java.util.Set;

/**
 * Factory for constructing {@link SignatureTool} instances from configuration.
 * <p>
 * The builder uses factories to avoid hardcoding construction logic for each tool.
 * Each built-in tool has a corresponding factory that knows how to extract credentials
 * and settings from the config.
 * <p>
 * This is a public SPI for tool extensions. Third-party tools can implement this
 * interface and register via {@link java.util.ServiceLoader}. The builder discovers
 * factories at build time and initializes tools based on configuration.
 *
 * @see Sigmund.Builder#build()
 */
public interface SignatureToolFactory {

    /**
     * Returns the tool name this factory builds.
     *
     * @return the tool name (e.g., {@code "gpg"}, {@code "sq"})
     */
    String toolName();

    /**
     * Returns the credential types this factory can build tools for.
     *
     * @return the supported credential type strings
     */
    Set<String> supportedCredentialTypes();

    /**
     * Returns the settings this tool accepts under {@code tools.<name>} in {@code sigmund.yaml}.
     * <p>
     * A setting not listed is a configuration error when tools are built, naming the nearest
     * accepted one, so a misspelled setting fails instead of leaving the tool on its default.
     * The key-fetching settings Sigmund passes to OpenPGP tools from the {@code verification}
     * section are not listed: they are not written under {@code tools}.
     *
     * @return the accepted setting names, empty for a tool with no settings
     */
    Set<String> acceptedSettings();

    /**
     * Returns the accepted settings that may be written as a YAML list.
     * <p>
     * A list given to any other setting is a configuration error when tools are built. A factory
     * derives this from its settings enum with {@link ToolSetting#listKeysOf}, so what takes a
     * list is declared once, on the constant.
     * <p>
     * The default implementation returns an empty set.
     *
     * @return the names of the settings that take a list
     */
    default Set<String> listSettings() {
        return Set.of();
    }

    /**
     * Rejects a setting whose value this tool cannot use, when tools are built.
     * <p>
     * Runs for every tool configured under {@code tools}, whether or not a toolchain names it,
     * so a malformed value fails the run instead of leaving the tool out of it. Only the settings
     * {@link #acceptedSettings()} lists reach this method.
     * <p>
     * The default implementation accepts every value.
     *
     * @param settings the tool's settings as written under {@code tools.<name>}
     * @throws PolicyConfigException if a value is malformed, naming the tool and the setting
     */
    default void checkSettingValues(Map<String, String> settings) {
    }

    /**
     * Creates a signing-capable tool from its own settings.
     * <p>
     * The tool chooses its signing key from {@code settings} alone. {@code expected} is the signer
     * the run asserts, every identity entry naming its issuer; a tool may use it to refuse before
     * signing, never to select a key. Whether a signature proves it is decided by core after
     * signing, whatever the tool did with it.
     * <p>
     * The default implementation throws {@link UnsupportedOperationException}.
     * Factories that support signing must override this method.
     *
     * @param settings tool-specific settings from the config
     * @param expected the signer {@code signing.signer} names, resolved as above, or {@code null}
     *        when none is asserted
     * @return the configured tool
     * @throws UnsupportedOperationException if signing is not supported
     */
    default SignatureTool createSigning(Map<String, String> settings, SignerIdentity expected) {
        throw new UnsupportedOperationException(
                toolName() + " factory does not support signing");
    }

    /**
     * Creates a verify-only tool (no signing credentials).
     *
     * @param settings tool-specific settings from the config
     * @return the configured verify-only tool
     */
    SignatureTool createVerifyOnly(Map<String, String> settings);

    /**
     * Returns whether this tool should be the exclusive signer when no
     * signing tools are explicitly configured in {@code sigmund.yaml}.
     * <p>
     * This method is only consulted by {@link Sigmund.Builder} when the
     * {@code signing.toolchain} of the configuration is absent or empty.
     * When the user has explicitly configured signing tools, this method is
     * not called — the configured tools are used as-is, and the factory's
     * key resolution priority (which may still prefer the env var over
     * file-based keys) handles key selection independently.
     * <p>
     * A factory returns {@code true} when it detects a signing key from a
     * source that implies "use only me" — for example, an ephemeral key
     * injected via environment variable for CI builds. The factory reports
     * what it knows about its own state; the builder decides whether and
     * how to act on it based on the broader configuration context.
     * <p>
     * The default implementation returns {@code false}.
     *
     * @return {@code true} if this tool should be the sole signer when no
     *         signing tools are explicitly configured
     */
    default boolean isDefaultExclusiveSigner() {
        return false;
    }
}
