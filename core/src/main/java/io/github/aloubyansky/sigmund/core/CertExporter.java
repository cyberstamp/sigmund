package io.github.aloubyansky.sigmund.core;

/**
 * Capability interface for tools that can export public certificates.
 *
 * @see KeyGenerator
 */
public interface CertExporter {

    /**
     * Exports the public certificate for the given fingerprint.
     *
     * @param fingerprint the key fingerprint to export
     * @return the exported certificate data (format depends on the tool)
     * @throws ToolExecutionException if the export fails or the key is not found
     */
    String exportCert(String fingerprint);
}
