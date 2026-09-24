package dev.cyberstamp.sigmund.core;

/**
 * The capacity in which an attester made a claim.
 *
 * <p>
 * Role is a first-class policy dimension because the same signature means different things
 * depending on who made it and why: a publisher vouching for their own release, a builder
 * attesting how it was produced, a distro re-signing what it ships. Flattening these into one
 * "trusted signer" notion yields identical green checks for very different assurances.
 *
 * <p>
 * Structure proposes and policy disposes: a role is derived where the claim's shape permits,
 * policy may assert one, and a mismatch is a configuration error rather than a silent
 * override.
 */
public enum AttesterRole {

    /** The party that published the artifact, vouching for it. */
    PUBLISHER,

    /** The system that produced the artifact, attesting how it was built. */
    BUILDER,

    /** A repository or registry signing on a publisher's behalf. */
    REGISTRY,

    /** A third party asserting a verification result about someone else's artifact. */
    THIRD_PARTY_VERIFIER,

    /**
     * No role could be established. Common today — a bare OpenPGP signature says nothing about
     * capacity — and deliberately visible rather than defaulted to {@link #PUBLISHER}, which
     * would claim an assurance nobody made.
     */
    UNKNOWN
}
