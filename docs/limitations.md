# Known Limitations

This page documents known limitations, ecosystem maturity notes, and caveats for Sigmund.

## Contents

- [BC v6 keys incompatible with GnuPG](#bc-v6-keys-incompatible-with-gnupg)
- [Not every BC cipher suite has both key versions](#not-every-bc-cipher-suite-has-both-key-versions)
- [GPG ephemeral key fetch not supported](#gpg-ephemeral-key-fetch-not-supported)
- [GPG exit code 2 for hybrid .asc files](#gpg-exit-code-2-for-hybrid-asc-files)
- [Sequoia verdicts are read from its report text](#sequoia-verdicts-are-read-from-its-report-text)
- [GnuPG does not honour revocation reasons](#gnupg-does-not-honour-revocation-reasons)
- [BC cannot use a user ID that is not UTF-8](#bc-cannot-use-a-user-id-that-is-not-utf-8)
- [keys.openpgp.org alone cannot serve keys without a verified address](#keysopenpgporg-alone-cannot-serve-keys-without-a-verified-address)
- [Designated revokers are not honoured by BC or Sequoia](#designated-revokers-are-not-honoured-by-bc-or-sequoia)
- [A user ID is labelled verified only from a copy BC fetched](#a-user-id-is-labelled-verified-only-from-a-copy-bc-fetched)
- [Key passphrase protection caveats](#key-passphrase-protection-caveats)
  - [BC keys: decrypted material on the Java heap](#bc-keys-decrypted-material-on-the-java-heap)
- [PQC ecosystem maturity](#pqc-ecosystem-maturity)
- [PQC algorithm ID range](#pqc-algorithm-id-range)
- [PQC signature sizes](#pqc-signature-sizes)

## BC v6 keys incompatible with GnuPG

`sigmund keygen` generates v4 keys unless `--credential-type pgp6` is given. A v6 key cannot be imported into GnuPG, which follows the LibrePGP specification and does not support OpenPGP v6, and keys.openpgp.org does not serve v6 keys. Generate v6 with BC only for a tool that reads it — BC itself and `sq`.

A v4 Ed25519 key is written in the legacy EdDSA encoding: GnuPG 2.4 reads Ed25519 in v4 keys only in that form, and rejects the RFC 9580 encoding as an invalid public key algorithm.

## Not every BC cipher suite has both key versions

- **ECDSA** (`nistp256`, `nistp384`, `nistp521`) keys are v4 only. Bouncy Castle's high-level API (1.87) has no ECDSA key preset, so Sigmund uses a JCA-based fallback that produces v4 keys; `--credential-type pgp6` with these suites is an error.
- **Ed448** keys are v6 only: GnuPG reads no v4 Ed448 key, so a v4 one would serve no tool a v4 key is for. `--cipher-suite ed448` without `--credential-type pgp6` is an error.
- **ML-DSA** (`mldsa65-ed25519`, `mldsa87-ed448`) keys are v6 only, as RFC 9980 defines them for v6 keys alone; without `--credential-type pgp6` they are an error.
- **Ed25519** and **RSA** (`rsa4096`) come in both versions.

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
compromised, or with no reason given, invalidates every signature it made, while one retired or
superseded invalidates only signatures made after the revocation. Bouncy Castle and Sequoia do
this. GnuPG reports a signature by a revoked key (`REVKEYSIG`) without the revocation's time or
reason, so Sigmund treats every such signature as `FAILED` when GnuPG answers — including a
signature made before a key was retired, which the other backends verify. GnuPG is stricter,
never more lenient, than the others here.

Since a conclusive answer ends routing, the toolchain order decides which view applies: with the
default `[bc, sq, gpg]`, Bouncy Castle answers and a signature made before the key was retired is
`VERIFIED`; with `gpg` listed first it is `FAILED`. `KeyValidityAgreementTest` pins both views.
Reading the revocation details from GnuPG's key listing, so that the backends agree, is part of
roadmap task P4.7.

## BC cannot use a user ID that is not UTF-8

Some older keys carry a user ID in another encoding — gson's release key, which signs
`com.google.code.gson:gson`, is one. Its self-signature is valid, and GnuPG and Sequoia verify
signatures by such a key. Bouncy Castle's certificate API drops a user ID it cannot decode, so to
BC the key is not bound, and BC reports `INDETERMINATE` with `KEY_UNAVAILABLE` where the other
backends report `VERIFIED`. It is never reported as `FAILED`
([ADR-009](../adr/009-an-unbound-key-is-never-failed.md)). When `sq` or `gpg` holds the key in its
own store (`sq cert import`, `gpg --import`), verification falls through to it and the signature
verifies. A key fetched from a keyserver reaches only BC, unless `import-to-keyring: true` lets
`gpg` fetch it into its keyring too.

## keys.openpgp.org alone cannot serve keys without a verified address

`keys.openpgp.org` publishes a user ID only once its owner has verified the address, and an
address belongs to one key at a time: verifying it for a new key removes it from the key it was
verified for before ([FAQ](https://keys.openpgp.org/about/faq)). A key with no verified address is
served without its user IDs, and so without the self-signatures that carry its expiry, its
allowed uses and the binding of its subkeys. GnuPG, Sequoia and Bouncy Castle all treat such a
copy as unusable, so a signature by that key is `INDETERMINATE` with `KEY_UNAVAILABLE` — never
`FAILED` ([ADR-009](../adr/009-an-unbound-key-is-never-failed.md)) — when `keys.openpgp.org` is
the only source of the key.

This reaches two kinds of key:

- **A key whose owner never verified an address**, common among release keys on Maven Central —
  the gson and error_prone release keys among them.
- **A key its owner rotated away from.** Once the address is verified for the new key, the old
  key is served stripped, and every signature it made stops verifying from `keys.openpgp.org`
  alone — even under a policy that pins the old key's fingerprint, since the copy itself cannot be
  used.

This is mitigated by default: `keyserver.ubuntu.com`, the second default keyserver, serves such
keys in full, and Sigmund merges the copies every keyserver serves, so both kinds verify. A user
ID only `keyserver.ubuntu.com` served is shown as `(unverified)`, since it does not verify
addresses. What remains is a key no configured keyserver serves in full; listing a keyserver
that does resolves it — see
[Keys Served Without User IDs](verification.md#keys-served-without-user-ids). A publisher keeps
old signatures verifiable from `keys.openpgp.org` by leaving a verified address on the old key,
or by publishing the old key's full certificate where verifiers can find it, such as the
project's `KEYS` file.

Verifiers that check a signature against the key alone, without the key's validity —
pgpverify-maven-plugin does — are not affected, and do not check the key's expiry or the
binding of its subkeys either.

## Designated revokers are not honoured by BC or Sequoia

A key can name another key as a designated revoker (RFC 4880's revocation key subpacket), which
may then revoke it. Bouncy Castle and Sequoia ignore such a revocation: a key revocation counts
only when it verifies against the key's own primary key, which also keeps a revocation forged by
any keyserver from making a signature `FAILED`. GnuPG honours it, but only when the revoker's key
is in its keyring. So a signature by a key revoked this way is `VERIFIED` under `bc` and `sq`, and
`FAILED` under `gpg` when it holds the revoker's key. RFC 9580 deprecates the subpacket;
making the backends agree is roadmap task P4.12.

## A user ID is labelled verified only from a copy BC fetched

A displayed user ID is labelled `(address verified by keys.openpgp.org)` only when that
directory's copy of the key, fetched into Bouncy Castle's key store this run, carried it. A key
`gpg` fetched into its own keyring (`import-to-keyring: true` with `gpg` answering), or one
answered from `sq`'s or `gpg`'s own store, has no such copy, so its user ID is labelled
`(unverified)` even when the directory publishes it. The label only understates: it never shows
a name as verified that the directory did not serve, and it never changes an outcome — matching
`email:` entries goes through the directory's own answer.

## Key passphrase protection caveats

### BC keys: decrypted material on the Java heap

BC keys support passphrase encryption at rest (AES-256 AEAD with Argon2 key derivation), but once decrypted for signing, the private key material resides on the Java heap without memory locking. Unlike `gpg-agent` (which can use `mlock` to pin key material in RAM), the JVM cannot guarantee that key bytes stay in physical memory or are zeroed after use.

**In practice**, passphrase protection guards against filesystem-level exposure — stolen disks, backup leaks, compromised servers. For defense-in-depth against memory disclosure attacks, consider a hardware security module (HSM).

See the [Signing Guide](signing.md#passphrase-protection) for passphrase configuration details.

## PQC ecosystem maturity

Broad ecosystem adoption of PQC in OpenPGP is still early. Sequoia `sq` 1.4.0 includes stable PQC support based on [RFC 9980](https://datatracker.ietf.org/doc/rfc9980/) (Post-Quantum Cryptography in OpenPGP), published as a Proposed Standard in June 2026.

**Current state of the ecosystem:**

- **GnuPG** follows the LibrePGP specification, not RFC 9580/9980, and does not support v6 keys or PQC signatures
- **keys.openpgp.org** rejects v6 keys, so it serves no PQC key
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

PQC signatures are much larger than classical ones. Measured as they appear in an armored `.asc`:

| Key | Per signature in the `.asc` |
|-----|----------------------------|
| Ed25519 (classical, v4) | 248–325 bytes |
| ML-DSA-65+Ed25519 | 4,752 bytes |
| ML-DSA-87+Ed448 | 6,604 bytes |

For a typical Maven module with 4 artifacts (JAR, POM, javadoc, sources) signed with a classical and an ML-DSA-87+Ed448 key, expect about 27 KB of `.asc` data, against about 1 KB classical-only. This is small next to the artifacts themselves. See [PQC Signature Sizes](signing.md#pqc-signature-sizes) for how the figures were measured.

Hybrid `.asc` files allow gradual PQC adoption — classical-only tools ignore the PQC signature block, and the size increase only affects the signature files, not the artifacts themselves.
