# ADR-004: Bouncy Castle OpenPGP Backend

## Status
Accepted

## Context

Sigmund's signature verification and signing operations rely on external CLI
tools (`gpg`, `sq`). This creates deployment friction — users must install and
configure these tools separately. Additionally, `gpg` has no post-quantum
algorithm support, and `sq` availability cannot be guaranteed on all platforms.

## Decision

Add a pure-Java Bouncy Castle backend (`BcRunner`) as a `SignatureTool`
implementation in the `core` module, handling OpenPGP v4 and v6 signatures.

### Phased approach

- **Phase 1:** Classic algorithms (Ed25519, Ed448, RSA, ECDSA) using BC 1.85's
  high-level `BcOpenPGPApi` from the `bcpg` module. This API generates v6 keys
  for Ed25519, Ed448, and RSA; ECDSA uses JCA-based fallback (v4 keys).
- **Phase 2:** PQ composite algorithms (ML-DSA-87+Ed448, ML-DSA-65+Ed25519)
  via custom RFC 9980 packet handling on top of BC's raw ML-DSA primitives.
  BC's `bcpg` layer has no RFC 9980 wiring as of v1.85.

### Why not wait for BC to add RFC 9980 support?

No timeline has been announced. Only Sequoia (Rust) and GopenPGP (Go) implement
RFC 9980 today. Building a custom layer gives sigmund PQ support on its own
schedule.

### Key management

BcRunner reads public keys from GnuPG pubring and the shared OpenPGP cert-d
directory. BC-generated private keys are stored in a `bc-private` subdirectory
under cert-d. Public certs for BC-generated keys are written to the shared
cert-d so `sq` and other tools can see them.

### Tool priority

A configurable `tool-priority` setting in `DiscoveryConfig` controls which tool
handles each verification unit. Default: `[bc, sq, gpg]` — BC first to
maximize the "no external dependencies" benefit.

## Consequences

- Sigmund works out of the box on any JVM without external tool installation.
- No process forking or keyring locking for concurrent verification.
- BC dependency (`bcpg-jdk18on`) was already present for armor/dearmor.
- Phase 2 will require maintaining custom RFC 9980 packet code until BC adds
  native support, at which point we switch to their implementation.
