package io.github.cyberstamp.sigmund.core;

/**
 * Provides passphrases for passphrase-protected private keys.
 *
 * <p>
 * This interface uses {@code char[]} rather than {@link String} deliberately.
 * {@code String} objects are immutable and interned, so a passphrase stored as
 * a {@code String} persists on the Java heap until garbage-collected — it cannot
 * be zeroed by the caller. A {@code char[]} can be explicitly wiped after use
 * (via {@code Arrays.fill}), limiting the window during which the passphrase is
 * present in process memory.
 *
 * <p>
 * Callers that accept passphrases interactively should use
 * {@link java.io.Console#readPassword}, which returns {@code char[]}.
 * Callers converting from environment variables (inherently {@code String})
 * should call {@link String#toCharArray()} and accept that the original
 * {@code String} remains on the heap — the env var is already in process
 * memory regardless.
 *
 * <p>
 * The provider is threaded through {@link Sigmund.Builder#bcPassphraseProvider}
 * rather than through the {@code Map<String, String>} tool settings to avoid
 * forcing a {@code String} conversion at the API boundary.
 */
@FunctionalInterface
public interface PassphraseProvider {

    /**
     * Returns the passphrase for the key with the given fingerprint.
     *
     * <p>
     * The caller is responsible for zeroing the returned array after use.
     * Returning {@code null} or an empty array signals "no passphrase" —
     * the key will be stored or read without encryption.
     *
     * @param keyFingerprint the hex fingerprint of the key needing a passphrase
     * @return the passphrase as a char array, or {@code null} if no passphrase is available
     */
    char[] getPassphrase(String keyFingerprint);
}
