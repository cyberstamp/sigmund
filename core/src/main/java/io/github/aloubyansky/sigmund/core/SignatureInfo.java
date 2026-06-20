package io.github.aloubyansky.sigmund.core;

/**
 * Represents information extracted from a signature block.
 * <p>
 * This record provides a unified view of signature metadata that can be
 * consumed by any reporting or verification utility. The {@code signerUserId}
 * is only available when the signing key is present in the GPG keyring.
 *
 * @param version the OpenPGP signature version (e.g., 4 for classical, 6 for PQC), or -1 if unknown
 * @param keyId the key ID (16-40 hex characters), or null if not available
 * @param algorithm the key algorithm (e.g., "RSA", "EDDSA"), or null if not available
 * @param signerUserId the full user ID from the key (e.g., "Name &lt;email&gt;"), or null if the key is not in the keyring
 * @param result the verification result
 */
public record SignatureInfo(
        int version,
        String keyId,
        String algorithm,
        String signerUserId,
        VerificationResult result) {
}
