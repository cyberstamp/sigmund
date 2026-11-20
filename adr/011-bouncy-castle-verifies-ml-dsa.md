# ADR-011: Bouncy Castle Verifies ML-DSA Signatures Natively

## Status

Proposed. Amends [ADR-004](004-bouncy-castle-backend.md): how Phase 2 verifies post-quantum
composite signatures.

## Context

ADR-004 planned Phase 2 — the ML-DSA composites of RFC 9980 (ML-DSA-65+Ed25519,
ML-DSA-87+Ed448) — as custom packet handling on top of Bouncy Castle's raw ML-DSA primitives,
because Bouncy Castle's OpenPGP layer had no RFC 9980 support. Until then BC declined every
post-quantum signature, and a hybrid `.asc` needed `sq` to verify its post-quantum block.

Bouncy Castle 1.87 reads RFC 9980 keys — ML-DSA, SLH-DSA and ML-KEM — and verifies ML-DSA
composite signatures. Against keys and signatures made by `sq` 1.5.0, both composites verify,
fail on a tampered artifact, and prove the same signing and primary key as `sq`. SLH-DSA cannot
be checked the same way: `sq` does not produce it, and no other installed tool does.

## Decision

BC verifies the ML-DSA composite signatures (algorithm IDs 30 and 31) through Bouncy Castle's
own OpenPGP support, from 1.87 on. No custom RFC 9980 packet handling is written. BC keeps
declining SLH-DSA signatures (IDs 32–34) until it can be checked against another
implementation. Generating post-quantum keys and signing with them in BC stays open, as ADR-004
Phase 2 planned.

## Alternatives

- **Custom packet handling on raw primitives, as ADR-004 planned.** A second RFC 9980
  implementation to maintain beside the library's own, for no capability the library lacks.
  Rejected.
- **Accept every algorithm Bouncy Castle parses, SLH-DSA included.** BC would verify signatures
  no test checks against another backend, and "backends must agree" could not be shown for
  them. Rejected.
- **Keep declining post-quantum signatures.** A hybrid `.asc` would still need `sq` for a check
  the always-available backend can make. Rejected.

## Consequences

- A hybrid `.asc` verifies completely with BC alone; `sq` is needed only for SLH-DSA.
- Sigmund needs Bouncy Castle 1.87 or later: on an older one, an ML-DSA certificate cannot be
  read and the claim is reported as a key BC cannot read, not as unsupported.
- `BcPostQuantumTest` holds BC to `sq` on both composites; it is the test to extend when SLH-DSA
  gets a second implementation to compare with.
