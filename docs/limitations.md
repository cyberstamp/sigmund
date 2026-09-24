# Known Limitations

This page documents known limitations, ecosystem maturity notes, and caveats for Sigmund.

## Contents

- [BC v6 keys incompatible with GnuPG](#bc-v6-keys-incompatible-with-gnupg)
- [BC ECDSA keys are v4, not v6](#bc-ecdsa-keys-are-v4-not-v6)
- [PQC signature verification requires Sequoia](#pqc-signature-verification-requires-sequoia)
- [GPG ephemeral key fetch not supported](#gpg-ephemeral-key-fetch-not-supported)
- [GPG exit code 2 for hybrid .asc files](#gpg-exit-code-2-for-hybrid-asc-files)
- [Key passphrase protection caveats](#key-passphrase-protection-caveats)
  - [BC keys: decrypted material on the Java heap](#bc-keys-decrypted-material-on-the-java-heap)
  - [Sequoia PQC keys: generated without passphrase](#sequoia-pqc-keys-generated-without-passphrase)
- [PQC ecosystem maturity](#pqc-ecosystem-maturity)
- [PQC algorithm ID range](#pqc-algorithm-id-range)
- [PQC signature sizes](#pqc-signature-sizes)

## BC v6 keys incompatible with GnuPG

Bouncy Castle (BC) generates v6 keys for Ed25519, Ed448, and RSA. These keys cannot be imported into GnuPG because GnuPG follows the LibrePGP specification and does not support OpenPGP v6.

**Workaround:** If you need GnuPG interoperability, use BC with a NIST P-curve cipher suite (`nistp256`, `nistp384`, or `nistp521`), which produces v4 keys that GnuPG can import and verify.

## BC ECDSA keys are v4, not v6

BC-generated ECDSA keys (NIST P-256, P-384, P-521) use the older v4 packet format. Ed25519, Ed448, and RSA keys generate v6 keys.

This is a Bouncy Castle 1.85 limitation — its high-level API does not support ECDSA key generation for NIST P-curves, so Sigmund uses a JCA-based fallback that produces v4 keys.

**In practice**, this is rarely a problem. v4 keys work with both GnuPG and Bouncy Castle, and most users choose Ed25519 (v6) as their cipher suite. This only matters if you specifically require v6 keys for all algorithms.

## PQC signature verification requires Sequoia

Bouncy Castle 1.85 does not recognize post-quantum composite signature algorithm IDs (30-36, defined in RFC 9980). Attempting to verify a PQC signature with BC produces `INDETERMINATE [UNSUPPORTED_ALGORITHM]`, which sets that claim aside rather than failing the artifact.

**What this means:** PQC signature verification currently requires Sequoia `sq` 1.4.0+. If Sequoia is not installed, PQC signature blocks in hybrid `.asc` files will be skipped — the classical signature block is still verified normally.

BC support for PQC verification (ML-DSA-87+Ed448 and ML-DSA-65+Ed25519) is planned for a future release.

## GPG ephemeral key fetch not supported

When `import-to-keyring` is `false` (the default), GnuPG cannot fetch public keys for verification. GnuPG requires keys to be permanently imported into the keyring before they can be used — it has no concept of ephemeral (in-memory) key storage.

When a signing key is not in the GPG keyring, verification returns `INDETERMINATE [KEY_UNAVAILABLE]` and automatic key fetching is skipped.

**Workaround:** Either set `import-to-keyring: true` in `sigmund.yaml` to permanently import fetched keys, or use Bouncy Castle as your primary verification tool (the default). BC supports ephemeral key caching — fetched keys are held in memory for the duration of the build and discarded afterward.

## GPG exit code 2 for hybrid `.asc` files

GnuPG returns exit code 2 (rather than 0) when verifying a hybrid `.asc` file containing both v4 and v6 signature packets. GPG successfully verifies the v4 classical signature and reports "Good signature," but the v6 PQC packet triggers a warning about an unknown packet version, which changes the exit code.

**Sigmund handles this correctly** — it checks for "Good signature" in GPG's output when exit code is 2 and treats it as a pass.

**Impact on external scripts:** CI systems or scripts that check GPG's exit code strictly (expecting only 0 for success) may interpret exit code 2 as a failure. If you encounter this, update your scripts to check for "Good signature" in GPG's stderr rather than relying solely on the exit code.

## Key passphrase protection caveats

### BC keys: decrypted material on the Java heap

BC keys support passphrase encryption at rest (AES-256 AEAD with Argon2 key derivation), but once decrypted for signing, the private key material resides on the Java heap without memory locking. Unlike `gpg-agent` (which can use `mlock` to pin key material in RAM), the JVM cannot guarantee that key bytes stay in physical memory or are zeroed after use.

**In practice**, passphrase protection guards against filesystem-level exposure — stolen disks, backup leaks, compromised servers. For defense-in-depth against memory disclosure attacks, consider a hardware security module (HSM).

See the [Signing Guide](signing.md#passphrase-protection) for passphrase configuration details.

### Sequoia PQC keys: generated without passphrase

Sequoia `sq` PQC keys are generated with `--without-password` by default to support non-interactive use in CI/CD and headless environments.

**For production deployments**, keys should be passphrase-protected. Use `sq key generate` with `--new-password-file` to supply a passphrase non-interactively. See the [Sequoia documentation](https://sequoia-pgp.org/) for details.

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
