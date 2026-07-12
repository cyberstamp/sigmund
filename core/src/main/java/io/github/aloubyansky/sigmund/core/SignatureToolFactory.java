package io.github.aloubyansky.sigmund.core;

import java.util.Map;
import java.util.Set;

/**
 * Internal factory for constructing {@link SignatureTool} instances from configuration.
 * <p>
 * The builder uses factories to avoid hardcoding construction logic for each tool.
 * Each built-in tool has a corresponding factory that knows how to extract credentials
 * and settings from the config.
 * <p>
 * This is an internal implementation detail, not a public SPI. Third-party tools
 * use {@code Sigmund.builder().addTool()} directly. If a {@code ServiceLoader}-based
 * extension point is needed later, this interface is the natural candidate.
 */
interface SignatureToolFactory {

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
     * Creates a signing-capable tool for the given credential.
     *
     * @param credential the signing credential
     * @param settings tool-specific settings from the config
     * @return the configured tool, or {@code null} if the key/credential is not available
     */
    SignatureTool create(Credential credential, Map<String, String> settings);

    /**
     * Creates a verify-only tool (no signing credentials).
     *
     * @param settings tool-specific settings from the config
     * @return the configured verify-only tool
     */
    SignatureTool createVerifyOnly(Map<String, String> settings);
}
