package dev.cyberstamp.sigmund.core;

import java.time.Instant;

/**
 * Metadata extracted from a signature packet in a single dearmor pass.
 *
 * @param version the OpenPGP signature version (e.g., 4 or 6), or -1 if detection fails
 * @param algorithmId the public-key algorithm ID, or -1 if extraction fails
 * @param issuerFingerprint the issuer fingerprint as an uppercase hex string, or null if not found
 * @param creationTime the signature creation subpacket, or null if not found
 * @param signatureType the signature type (RFC 9580 §5.2.1), or -1 if the block is not a bare
 *        signature packet or the type cannot be read
 * @param packetTag the tag of the block's first packet (RFC 9580 §5.1), such as 2 for a
 *        signature, or -1 if the block cannot be decoded into a packet
 */
record OpenPgpSignaturePacketInfo(int version, int algorithmId, String issuerFingerprint,
        Instant creationTime, int signatureType, int packetTag) {
}
