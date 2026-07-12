package io.github.aloubyansky.sigmund.core;

/**
 * Metadata extracted from a signature packet in a single dearmor pass.
 *
 * @param version the OpenPGP signature version (e.g., 4 or 6), or -1 if detection fails
 * @param algorithmId the public-key algorithm ID, or -1 if extraction fails
 * @param issuerFingerprint the issuer fingerprint as an uppercase hex string, or null if not found
 */
public record OpenPgpSignaturePacketInfo(int version, int algorithmId, String issuerFingerprint) {
}
