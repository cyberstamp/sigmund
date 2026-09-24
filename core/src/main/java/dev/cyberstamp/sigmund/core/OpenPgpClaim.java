package dev.cyberstamp.sigmund.core;

import java.time.Instant;

/**
 * A single OpenPGP signature block extracted from an armored signature file.
 * <p>
 * Holds the armored text (natural representation for OpenPGP) along with
 * metadata extracted from the signature packet. The metadata enables routing
 * to the correct tool without re-parsing: v1–v4 packets go to GPG,
 * v5+ packets go to Sequoia.
 *
 * @param armoredBlock the ASCII-armored signature block text
 * @param packetVersion the OpenPGP signature packet version (4, 6, etc.),
 *        or {@code -1} if detection failed
 * @param issuerFingerprint the issuer fingerprint as an uppercase hex string,
 *        or {@code null} if not found (v4 signatures may not include it)
 * @param algorithmId the IANA public-key algorithm ID,
 *        or {@code -1} if extraction failed
 * @see Algorithms#algorithmName(int)
 */
public record OpenPgpClaim(
        String armoredBlock,
        int packetVersion,
        String issuerFingerprint,
        int algorithmId,
        Instant creationTime) implements Claim {

    /**
     * {@inheritDoc}
     *
     * <p>
     * For OpenPGP this is the signature creation subpacket.
     */
    @Override
    public Instant claimTime() {
        return creationTime;
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * Always {@link ClaimTimeSource#SIGNER}: the creation subpacket is covered by
     * the signature but chosen by the signer, and OpenPGP has no timestamp authority to
     * corroborate it.
     */
    @Override
    public ClaimTimeSource claimTimeSource() {
        return ClaimTimeSource.SIGNER;
    }
}
