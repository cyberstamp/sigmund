package io.github.aloubyansky.sigmund.core;

/**
 * A Sigstore verification bundle extracted from a signature file.
 * <p>
 * Holds the JSON bundle text (natural representation for Sigstore).
 * The entire bundle is a single verifiable unit — no sub-parsing is needed.
 *
 * @param jsonBundle the Sigstore bundle as a JSON string
 */
public record SigstoreVerificationUnit(
        String jsonBundle) implements VerificationUnit {
}
