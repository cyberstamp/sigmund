package dev.cyberstamp.sigmund.core;

import java.time.Instant;

/**
 * A single verifiable piece extracted from a signature file.
 * <p>
 * Each implementation holds content in its natural form, avoiding
 * {@code String ↔ byte[]} roundtrips. The sealed interface ensures
 * that new signature formats are an intentional extension point —
 * adding a format requires adding a new {@code permits} entry and
 * implementation in core.
 *
 * <h2>Extensibility boundary</h2>
 * <p>
 * New <em>tools</em> within an existing format can be plugged in via
 * {@code Sigmund.builder().addTool()}. New <em>formats</em> require a core release
 * because both {@code Claim} and {@link VerifyResult} are sealed hierarchies.
 * This is intentional — a new format introduces new packet structures and verification
 * semantics that warrant review as part of core.
 *
 * @see SignatureFormat#parse(Evidence)
 * @see SignatureTool#canVerify(Claim)
 */
public sealed interface Claim permits OpenPgpClaim, SigstoreClaim {

    /**
     * Returns when the claim was made, as recorded in the evidence.
     *
     * <p>
     * This is the instant a claim's validity is judged against (§3.4), not the instant it was
     * verified. How much the value is worth depends on {@link #claimTimeSource()}.
     *
     * @return the claim time, or {@code null} when the evidence records none
     */
    Instant claimTime();

    /**
     * Returns who asserted {@link #claimTime()}, which is a property of the claim kind.
     *
     * @return the claim time's source
     */
    ClaimTimeSource claimTimeSource();
}
