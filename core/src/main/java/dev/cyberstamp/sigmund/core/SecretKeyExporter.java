package dev.cyberstamp.sigmund.core;

/**
 * Capability interface for tools that can export a secret key from their own store.
 * <p>
 * The export is how a key moves to a machine without the store — a CI runner given it through
 * {@code SIGMUND_BC_SIGNING_KEY} or a {@code tsk-file}. It is a secret: whoever holds it can sign as
 * the key. A key protected by a passphrase stays protected by it.
 *
 * @see CertExporter
 */
public interface SecretKeyExporter {

    /**
     * Exports the secret key with the given fingerprint as an ASCII-armored transferable secret
     * key.
     *
     * @param fingerprint the full fingerprint of the key's primary key
     * @return the armored key
     * @throws ToolExecutionException if the store holds no secret key with that fingerprint
     */
    String exportSecretKey(String fingerprint);
}
