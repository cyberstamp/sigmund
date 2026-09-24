package dev.cyberstamp.sigmund.core;

import java.time.Instant;

/**
 * A Sigstore verification bundle extracted from a signature file.
 * <p>
 * Holds the JSON bundle text (natural representation for Sigstore).
 * The entire bundle is a single verifiable claim — no sub-parsing is needed.
 *
 * @param jsonBundle the Sigstore bundle as a JSON string
 */
public record SigstoreClaim(
        String jsonBundle,
        Instant integratedTime) implements Claim {

    /**
     * {@inheritDoc}
     *
     * <p>
     * For Sigstore this is the transparency log's integrated time, carried inside the bundle.
     */
    @Override
    public Instant claimTime() {
        return integratedTime;
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * Always {@link ClaimTimeSource#TRANSPARENCY_LOG}: Rekor records and countersigns the time,
     * so it does not depend on the signer's clock or honesty.
     */
    @Override
    public ClaimTimeSource claimTimeSource() {
        return ClaimTimeSource.TRANSPARENCY_LOG;
    }
}
