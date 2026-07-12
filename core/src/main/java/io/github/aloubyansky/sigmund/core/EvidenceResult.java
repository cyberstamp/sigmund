package io.github.aloubyansky.sigmund.core;

import java.util.List;

/**
 * The output of verifying a piece of evidence.
 * <p>
 * Carries the full {@link VerifyResult} (with format-specific details like
 * signer display name, algorithm, and key metadata) alongside the proven
 * {@link Credential}s for identity matching.
 * <p>
 * The trust layer only needs {@link #verdict()} and {@link #provenCredentials()}
 * for policy decisions. Consumers that need richer display info (signer names,
 * key fingerprints, algorithms) access {@link #verifyResult()} directly.
 *
 * @param verifyResult the full verification result
 * @param provenCredentials the credentials proven by this evidence
 * @param provider the evidence provider name (e.g., {@code "openpgp"}, {@code "sigstore"})
 * @see EvidenceProvider
 * @see TrustResult
 */
public record EvidenceResult(VerifyResult verifyResult, List<Credential> provenCredentials, String provider) {

    public EvidenceResult {
        if (verifyResult == null) {
            throw new IllegalArgumentException("verifyResult must not be null");
        }
        provenCredentials = provenCredentials != null ? List.copyOf(provenCredentials) : List.of();
    }

    /**
     * Returns the verification outcome.
     *
     * @return the verdict (PASS, FAIL, NO_KEY, or SKIPPED)
     */
    public Verdict verdict() {
        return verifyResult.verdict();
    }
}
