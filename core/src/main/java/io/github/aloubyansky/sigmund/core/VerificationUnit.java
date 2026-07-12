package io.github.aloubyansky.sigmund.core;

/**
 * A single verifiable piece extracted from a signature file.
 * <p>
 * Each implementation holds content in its natural form, avoiding
 * {@code String ↔ byte[]} roundtrips. The sealed interface ensures
 * that new signature formats are an intentional extension point —
 * adding a format requires adding a new {@code permits} entry and
 * implementation in core.
 *
 * <h3>Extensibility boundary</h3>
 * <p>
 * New <em>tools</em> within an existing format can be plugged in via
 * {@code Sigmund.builder().addTool()}. New <em>formats</em> require a core release
 * because both {@code VerificationUnit} and {@link VerifyResult} are sealed hierarchies.
 * This is intentional — a new format introduces new packet structures and verification
 * semantics that warrant review as part of core.
 *
 * @see SignatureFormat#parse(java.nio.file.Path)
 * @see SignatureTool#canVerify(VerificationUnit)
 */
public sealed interface VerificationUnit
        permits OpenPgpVerificationUnit, SigstoreVerificationUnit {
}
