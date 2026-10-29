# Known Limitations

This page documents known limitations, ecosystem maturity notes, and caveats for Sigmund.

## Contents

- [BC v6 keys incompatible with GnuPG](#bc-v6-keys-incompatible-with-gnupg)
- [Not every BC cipher suite has both key versions](#not-every-bc-cipher-suite-has-both-key-versions)
- [PQC signature verification requires Sequoia](#pqc-signature-verification-requires-sequoia)
- [GPG ephemeral key fetch not supported](#gpg-ephemeral-key-fetch-not-supported)
- [GPG exit code 2 for hybrid .asc files](#gpg-exit-code-2-for-hybrid-asc-files)
- [Sequoia verdicts are read from its report text](#sequoia-verdicts-are-read-from-its-report-text)
- [GnuPG does not honour revocation reasons](#gnupg-does-not-honour-revocation-reasons)
- [Key passphrase protection caveats](#key-passphrase-protection-caveats)
  - [BC keys: decrypted material on the Java heap](#bc-keys-decrypted-material-on-the-java-heap)
- [PQC ecosystem maturity](#pqc-ecosystem-maturity)
- [PQC algorithm ID range](#pqc-algorithm-id-range)
- [PQC signature sizes](#pqc-signature-sizes)

## BC v6 keys incompatible with GnuPG

`sigmund keygen` generates v4 keys unless `--credential-type pgp6` is given. A v6 key cannot be imported into GnuPG, which follows the LibrePGP specification and does not support OpenPGP v6, and keys.openpgp.org does not serve v6 keys. Generate v6 with BC only for a tool that reads it — BC itself and `sq`.

A v4 Ed25519 key is written in the legacy EdDSA encoding: GnuPG 2.4 reads Ed25519 in v4 keys only in that form, and rejects the RFC 9580 encoding as an invalid public key algorithm.

## Not every BC cipher suite has both key versions

- **ECDSA** (`nistp256`, `nistp384`, `nistp521`) keys are v4 only. Bouncy Castle 1.85's high-level API does not generate ECDSA keys, so Sigmund uses a JCA-based fallback that produces v4 keys; `--credential-type pgp6` with these suites is an error.
- **Ed448** keys are v6 only: GnuPG reads no v4 Ed448 key, so a v4 one would serve no tool a v4 key is for. `--cipher-suite ed448` without `--credential-type pgp6` is an error.
- **Ed25519** and **RSA** (`rsa4096`) come in both versions.

## PQC signature verification requires Sequoia

Bouncy Castle (1.86) does not recognize post-quantum composite signature algorithm IDs (30-36, defined in RFC 9980). Attempting to verify a PQC signature with BC produces `INDETERMINATE [UNSUPPORTED_ALGORITHM]`, which sets that claim aside rather than failing the artifact.

**What this means:** PQC signature verification currently requires Sequoia `sq` 1.4.0+. If Sequoia is not installed, PQC signature blocks in hybrid `.asc` files will be skipped — the classical signature block is still verified normally.

BC support for PQC verification (ML-DSA-87+Ed448 and ML-DSA-65+Ed25519) is planned for a future release.

## GPG ephemeral key fetch not supported

When `import-to-keyring` is `false` (the default), GnuPG cannot fetch public keys for verification. GnuPG requires keys to be permanently imported into the keyring before they can be used — it has no concept of ephemeral (in-memory) key storage.

When a signing key is not in the GPG keyring, verification returns `INDETERMINATE [KEY_UNAVAILABLE]` and automatic key fetching is skipped.

**Workaround:** Either set `import-to-keyring: true` in `sigmund.yaml` to permanently import fetched keys, or use Bouncy Castle as your primary verification tool (the default). BC supports ephemeral key caching — fetched keys are held in memory for the duration of the build and discarded afterward.

## GPG exit code 2 for hybrid `.asc` files

GnuPG returns exit code 2 (rather than 0) when verifying a hybrid `.asc` file containing both v4 and v6 signature packets. GPG successfully verifies the v4 classical signature and reports "Good signature," but the v6 PQC packet triggers a warning about an unknown packet version, which changes the exit code.

**Sigmund handles this correctly** — it does not judge GnuPG by its exit code at all, but by the `--status-fd` status lines, where the v4 signature's `GOODSIG` is reported as usual.

**Impact on external scripts:** CI systems or scripts that check GPG's exit code strictly (expecting only 0 for success) may interpret exit code 2 as a failure. If you encounter this, update your scripts to check for "Good signature" in GPG's stderr rather than relying solely on the exit code.

## Sequoia verdicts are read from its report text

`sq verify` has no machine-readable report. Sigmund reads the closing tally of its text report —
`N bad signature` versus `N bad key` — and the detail of a bad key (revoked, expired, rejected by
policy, not bound) to tell a tampered artifact from a key `sq` will not use. This matches what
`sq` 1.4 prints, including the no-break space between a count and its noun. If a future `sq`
changed the tally, Sigmund would report `INDETERMINATE` with `TOOL_UNAVAILABLE`; if it changed
only how it describes a revoked or expired key, such a key could be read as `KEY_UNAVAILABLE`
instead of `FAILED`. The backend agreement tests run every case against the installed `sq`, so
either change fails Sigmund's build rather than going unnoticed.

## GnuPG does not honour revocation reasons

The design (§3.8 of the design direction) honours a revocation's reason code: a key revoked as
compromised invalidates every signature it made, while one retired or superseded invalidates only
signatures made after the revocation. Bouncy Castle and Sequoia do this. GnuPG reports a
signature by a revoked key (`REVKEYSIG`) without the revocation's time or reason, so Sigmund
treats every such signature as `FAILED` when GnuPG answers — including a signature made before
a key was retired, which the other backends verify. GnuPG is stricter, never more lenient, than
the others here. Reading the revocation details from GnuPG's key listing is part of roadmap task
P4.7.

## Key passphrase protection caveats

### BC keys: decrypted material on the Java heap

BC keys support passphrase encryption at rest (AES-256 AEAD with Argon2 key derivation), but once decrypted for signing, the private key material resides on the Java heap without memory locking. Unlike `gpg-agent` (which can use `mlock` to pin key material in RAM), the JVM cannot guarantee that key bytes stay in physical memory or are zeroed after use.

**In practice**, passphrase protection guards against filesystem-level exposure — stolen disks, backup leaks, compromised servers. For defense-in-depth against memory disclosure attacks, consider a hardware security module (HSM).

See the [Signing Guide](signing.md#passphrase-protection) for passphrase configuration details.

## PQC ecosystem maturity

Broad ecosystem adoption of PQC in OpenPGP is still early. Sequoia `sq` 1.4.0 includes stable PQC support based on [RFC 9980](https://datatracker.ietf.org/doc/rfc9980/) (Post-Quantum Cryptography in OpenPGP), published as a Proposed Standard in June 2026.

**Current state of the ecosystem:**

- **GnuPG** follows the LibrePGP specification, not RFC 9580/9980, and does not support v6 keys or PQC signatures
- **keys.openpgp.org** rejects v6 keys — public keyservers do not yet accept PQC keys
- **RHEL 10.1+** and recent Fedora releases ship PQC-enabled Sequoia as a system package
- **Debian** is unlikely to ship `sq` 1.4.0 before July 2027 due to packaging timelines

**Recommendation:** PQC signatures are suitable for production use when all parties in the trust chain have compatible tooling (Sigmund, Sequoia `sq` 1.4.0+, or other RFC 9980 implementations). For broader interoperability, use classical v4 signatures. Hybrid signing gives you both — classical compatibility today and PQC protection for the future.

## PQC algorithm ID range

Sigmund identifies PQC signatures by their public-key algorithm ID from the IANA OpenPGP registry. The recognized range (per RFC 9980) is:

| ID | Algorithm |
|----|-----------|
| 30 | ML-DSA-65+Ed25519 |
| 31 | ML-DSA-87+Ed448 |
| 32 | SLH-DSA-SHAKE-128s |
| 33 | SLH-DSA-SHAKE-128f |
| 34 | SLH-DSA-SHAKE-256s |
| 35 | ML-KEM-768+X25519 |
| 36 | ML-KEM-1024+X448 |

If IANA registers additional PQC algorithms beyond this range in the future, a Sigmund update will be needed to recognize them.

## PQC signature sizes

PQC signatures are significantly larger than classical signatures:

| Algorithm | Signature size |
|-----------|---------------|
| Ed25519 (classical) | ~64 bytes |
| ML-DSA-65+Ed25519 | ~3.3 KB |
| ML-DSA-87+Ed448 (default) | ~4.6 KB |

For a typical Maven module with 4 artifacts (JAR, POM, javadoc, sources) signed with both classical and PQC signatures, expect approximately 18 KB of additional `.asc` data. This is negligible compared to artifact sizes (JARs are typically measured in KB to MB).

Hybrid `.asc` files allow gradual PQC adoption — classical-only tools ignore the PQC signature block, and the size increase only affects the signature files, not the artifacts themselves.
