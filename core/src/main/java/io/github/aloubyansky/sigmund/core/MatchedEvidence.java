package io.github.aloubyansky.sigmund.core;

/**
 * A pairing of a signer identity with the evidence that matched it.
 *
 * @param signer the matched signer identity
 * @param evidence the evidence that proved the signer's credentials
 * @see TrustResult#matchedEvidence()
 */
public record MatchedEvidence(
        SignerIdentity signer,
        EvidenceResult evidence) {
}
