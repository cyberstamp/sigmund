# Signature Verification

This guide covers how to verify artifact signatures using Sigmund. Signature verification confirms that an artifact hasn't been tampered with and was signed by a specific key.

**Note:** This is distinct from trust verification, which additionally checks whether the signing key belongs to someone you trust. For trust verification, see [Trust Verification](trust-verification.md).

## Contents

- [Overview](#overview)
- [Verifying with the CLI](#verifying-with-the-cli)
  - [Example Output](#example-output)
- [Verifying with the Maven Plugin](#verifying-with-the-maven-plugin)
- [Verification Modes](#verification-modes)
  - [Strict Mode (Default)](#strict-mode-default)
  - [Lenient Mode](#lenient-mode)
- [Tool Routing](#tool-routing)
  - [How Routing Works](#how-routing-works)
  - [Tool Capabilities](#tool-capabilities)
  - [Outcomes and reasons](#outcomes-and-reasons)
  - [Accepted algorithms](#accepted-algorithms)
- [Sigstore Verification](#sigstore-verification)
  - [Auto-Detection](#auto-detection)
  - [Identity Extraction](#identity-extraction)
  - [Cross-Backend Identity Matching](#cross-backend-identity-matching)
- [Toolchain Configuration](#toolchain-configuration)
  - [Example: Prefer Sequoia](#example-prefer-sequoia)
  - [Example: GPG Only](#example-gpg-only)
- [Key Discovery](#key-discovery)
  - [How Key Fetching Works](#how-key-fetching-works)
  - [Keys Served Without User IDs](#keys-served-without-user-ids)
- [Verification Report Format](#verification-report-format)
  - [Example: All Signatures Verify](#example-all-signatures-verify)
  - [Example: Missing Key](#example-missing-key)
  - [Example: A Block No Tool Can Check](#example-a-block-no-tool-can-check)
  - [Example: Failed Signature](#example-failed-signature)
- [Troubleshooting](#troubleshooting)

> **Note:** The examples in this guide use the `sigmund` plugin prefix (e.g., `mvn sigmund:verify-signature`). This requires adding the plugin to your project's `pluginManagement`:
>
> ```xml
> <pluginManagement>
>   <plugins>
>     <plugin>
>       <groupId>dev.cyberstamp.sigmund</groupId>
>       <artifactId>sigmund-maven-plugin</artifactId>
>       <version>0.0.2</version>
>     </plugin>
>   </plugins>
> </pluginManagement>
> ```
>
> Alternatively, replace `sigmund` with the full plugin coordinates, e.g.:
> `mvn dev.cyberstamp.sigmund:sigmund-maven-plugin:0.0.2:verify-signature`

## Overview

Sigmund verifies signatures by:

1. Detecting the signature format from the file extension (`.asc` for OpenPGP, `.sigstore.json` for Sigstore)
2. Parsing the signature file into claims
3. Routing each claim to an appropriate verification tool (BC, Sequoia, GPG, or Sigstore)
4. Verifying each signature against the artifact
5. Reporting the outcome of each signature block, and the counts across them

For OpenPGP, a single `.asc` file may contain multiple signature blocks — for example, a classical v4 signature followed by a PQC v6 signature. Each block is verified independently.

For Sigstore, the `.sigstore.json` bundle is self-contained with the certificate and transparency log entry.

## Verifying with the CLI

Use the `verify-signature` command to verify a signature file:

```bash
sigmund verify-signature --file artifact.jar --signature artifact.jar.asc
```

### Example Output

A hybrid `.asc` — a classic block and a post-quantum one — whose PQC key is in no local key
store and on no keyserver:

```
Signature Verification Report:
  [1] VERIFIED (EdDSA) [key: B9708CEF29D52FAF0783A5B0442ECAFFC2204CA2] [signer: Alice <alice@example.org>]
  [2] INDETERMINATE [KEY_UNAVAILABLE: no local key store or configured keyserver has it] (ML-DSA-65+Ed25519) [key: 010940A63349D8D99F0CE7445F3EEDE307F9FCCE2158A7C7FD0C04EC8546F3EA]
  Overall: 1 VERIFIED, 1 INDETERMINATE
```

Each line shows:
- **Index** — signature block number
- **Outcome** — `VERIFIED`, `FAILED`, or `INDETERMINATE`, the last followed by the
  reason it could not be decided and, when the tool says, why
- **Algorithm** — the signing key's algorithm (e.g., `RSA`, `EdDSA`, `ML-DSA-65+Ed25519`)
- **Key** — the fingerprint of the key the signature names (when it names one)
- **Signer** — the signer's user ID, when a tool found the key; display text only, never an identity

**Overall** counts the outcomes rather than naming a verdict of its own: a
hybrid signature whose PQC block could not be checked reads as
`1 VERIFIED, 1 INDETERMINATE`, which says what happened, where a single verdict
would have to choose between "passed" and "not fully checked".

`--lenient` passes when at least one block verified and none failed (see
[Verification Modes](#verification-modes)). For every option, see
[`sigmund verify-signature`](cli-reference.md#sigmund-verify-signature) in the CLI reference.

## Verifying with the Maven Plugin

Use the `sigmund:verify-signature` goal to verify a single artifact:

```bash
mvn sigmund:verify-signature \
  -Dfile=artifact.jar \
  -Dsignature=artifact.jar.asc
```

This goal does not require a Maven project — it can be run standalone. Like the CLI command, it
reads the toolchain, key fetching and tool settings from `sigmund.yaml`: the file
`sigmund.trustConfig` names, else the project directory's — the directory Maven was started from,
when run without a project — else `~/.config/sigmund/sigmund.yaml`.

`-Dsigmund.lenient=true` is the goal's lenient mode. For every parameter, see
[`sigmund:verify-signature`](maven-plugin.md#sigmundverify-signature) in the plugin reference.

## Verification Modes

Sigmund supports two verification modes:

### Strict Mode (Default)

Every signature block must verify: at least one `VERIFIED`, and no `FAILED` or
`INDETERMINATE` block. A block nobody could check is not a pass.

```bash
sigmund verify-signature --file artifact.jar --signature artifact.jar.asc
```

Use strict mode when you require all signatures to be valid — for example, when verifying a hybrid signature where both classical and PQC signatures must succeed.

### Lenient Mode

At least one block must verify and none may fail. `INDETERMINATE` blocks are
tolerated, whatever left them undecided — a missing key, an unsupported
algorithm, or a tool that could not be run.

```bash
sigmund verify-signature --file artifact.jar --signature artifact.jar.asc --lenient
```

Use lenient mode when you want verification to succeed if any valid signature exists, even if some blocks cannot be verified (e.g., missing keys or unsupported algorithms).

**Maven plugin:**

```bash
mvn sigmund:verify-signature -Dfile=... -Dsignature=... -Dsigmund.lenient=true
```

## Tool Routing

Sigmund supports four verification backends:

| Tool | Availability | Format | v4 Support | v6 Support | PQC Support |
|------|--------------|--------|------------|------------|-------------|
| **BC** | Always (pure Java) | OpenPGP | Yes | Yes (classic algorithms) | No — Bouncy Castle 1.86 cannot read ML-DSA keys |
| **sq** | Optional (requires Sequoia CLI) | OpenPGP | Yes | Yes | Yes (RFC 9980) |
| **gpg** | Optional (requires GnuPG) | OpenPGP | Yes | No | No |
| **sigstore** | Optional (`sigmund-sigstore` module) | Sigstore | N/A | N/A | N/A |

No backend is routed v5 signatures, LibrePGP's format: Sequoia does not implement it, and GnuPG is routed v4 and earlier only. A v5 signature is therefore set aside as `INDETERMINATE [UNSUPPORTED_ALGORITHM]` rather than verified or failed.

### How Routing Works

When verifying a signature file:

1. **Parse the `.asc` file** into armored blocks
2. **Inspect each block** to extract packet version, algorithm ID, and issuer fingerprint
3. **Try each tool** in priority order
   - Each tool's `canVerify()` method checks whether it can handle the signature
   - A conclusive answer — `VERIFIED` or `FAILED` — is used immediately, and no later tool is
     asked to overrule it: whether the bytes match does not depend on the tool, so the toolchain
     order decides only which tool answers, and a `FAILED` cannot be outvoted
   - An `INDETERMINATE` answer falls through to the next tool — a different tool may have the key in its local keyring or support the algorithm
   - A tool that answers `KEY_UNAVAILABLE` and can fetch keys fetches it and verifies again (see [Key Discovery](#key-discovery))
   - If no tool decides the block, the most conclusive `INDETERMINATE` result seen is kept
   - A tool that throws is recorded as `INDETERMINATE [TOOL_UNAVAILABLE]` and the remaining tools still get their turn
4. **Report every block.** A block no tool in the toolchain can check — a PQC block with
   `toolchain: [gpg]`, or a v5 signature — is reported as `INDETERMINATE [UNSUPPORTED_ALGORITHM]`,
   never left out, so strict mode cannot pass on the blocks that were checked alone

This fallthrough is important because each tool has access to different key stores. For example, BC checks its ephemeral cache and cert-d, GPG reads `pubring.kbx`, and Sequoia reads its own cert store. A key missing from one tool's store may be present in another's.

### Tool Capabilities

**BC (Bouncy Castle)** handles any OpenPGP signature with classical algorithms (RSA, EdDSA, ECDSA). It does not take post-quantum signatures: Bouncy Castle 1.86 cannot read an ML-DSA key, so such a block goes to `sq`, or is `INDETERMINATE [UNSUPPORTED_ALGORITHM]` when no tool in the toolchain reads it. It searches for the signing key in:
- GnuPG pubring (`~/.gnupg/pubring.kbx`)
- Shared certificate directory (`~/.local/share/pgp.cert.d`), the store `sq` also uses
- Keys fetched in this session (in memory)

BC returns `INDETERMINATE [KEY_UNAVAILABLE]` if the signing key is not found in any of these locations. A stored certificate BC cannot read is never taken for a missing one, and does not hide the keys stored next to it:

- the keys a certificate holds are read from its packets even when Bouncy Castle cannot parse it, so an unreadable certificate concerns only its own keys — an `sq` post-quantum certificate in the shared cert-d does not affect other keys;
- a copy of the signing key with an algorithm Bouncy Castle does not know is `UNSUPPORTED_ALGORITHM` with the detail "Bouncy Castle cannot read the copy from …", so the next tool, such as `sq`, still answers; a subkey of an unknown algorithm is dropped and the rest of its certificate used;
- a damaged copy of the signing key is `KEY_UNAVAILABLE` with the detail "the copy from … cannot be read: …", and so is a copy a keyserver served that does not parse;
- a damaged file whose keys cannot be told apart concerns no key in particular: it is logged once as a warning naming the file, not reported with each signature.

BC verifies with Bouncy Castle's high-level OpenPGP API, which judges a signature in the context of its whole certificate, as GnuPG and Sequoia do. A signature verifies only if the key that made it was, at the signature's creation time, the primary key or a subkey validly bound to it: a binding signature by the primary that verifies, the signing flag, a back-signature (cross-certification) by a signing subkey, and neither revoked nor expired, with the primary key's expiry applying to the whole certificate. A subkey attached to someone else's certificate therefore proves nothing about that certificate's primary key. Algorithm acceptance is unchanged: SHA-1 and RIPEMD-160 signatures, and RSA and DSA keys from 1024 bits, still verify, since rejecting weak algorithms is a policy decision rather than a failed signature.

**Sequoia (sq)** handles v4 and v6 signatures, the versions RFC 9580 defines, including PQC hybrid signatures (ML-DSA, RFC 9980). It does not implement LibrePGP v5 signatures. It looks up the signer's certificate in its certificate store (`~/.local/share/pgp.cert.d` by default, or under `tools.sq.home`) and verifies using `sq verify --signer-file`.

**GPG** runs `gpg --verify` against the local keyring. It handles v1-v4 signatures. When verifying hybrid signatures containing v6 PQC packets, GPG prints a warning about unknown packets but still reports "Good signature" if the v4 classical signature is valid.

### Outcomes and reasons

Each verification tool returns one of three outcomes:

- **`VERIFIED`** — the signature is valid
- **`FAILED`** — the signature must not be trusted: the artifact's bytes do not match it
  (tampering, or the wrong signature), or the key that made it had already expired when it
  signed, or was revoked — as compromised, at any time; for another reason, before it signed
- **`INDETERMINATE`** — nothing was established either way, with a reason saying why

Keeping "could not check" apart from "checked and rejected" is the point of the
third outcome: only `FAILED` is an attack signal. The reasons are:

| Reason | Meaning | Transient |
|--------|---------|-----------|
| `KEY_UNAVAILABLE` | The signing key is in no keyring and could not be fetched, or the copy found cannot be used — a certificate served without the self-signatures that bind the key, or a damaged one | yes |
| `TRUST_ROOT_UNAVAILABLE` | Sigstore TUF metadata missing or too stale | yes |
| `DISCOVERY_UNAVAILABLE` | Evidence might exist but the source could not be queried | yes |
| `TOOL_UNAVAILABLE` | The verification tool could not be run, or broke while running | yes |
| `UNSUPPORTED_ALGORITHM` | No installed tool can check this signature, or it uses an algorithm Sigmund does not accept (see below) | no |
| `EVIDENCE_MALFORMED` | The signature or bundle could not be parsed | no |

A transient reason may resolve on a later run; a permanent one will not without
installing different tooling or fixing the evidence.

A tool declining to *use a key* is never reported as `FAILED`. A correct signature by a key
whose certificate lacks its binding self-signatures is `KEY_UNAVAILABLE`: keys.openpgp.org,
for example, serves a key without its user IDs — and so without the self-signatures on them —
until its owner verifies an address, and a fuller copy from another keyserver may resolve it.
A key bound only with an algorithm Sigmund does not accept is `UNSUPPORTED_ALGORITHM`.

### Accepted algorithms

Every backend accepts the same algorithms, so the verdict for an artifact does not depend on
which tool answered, or on the machine it ran on. The set is fixed in Sigmund, not
configurable. On top of each tool's current defaults, Sigmund accepts what artifacts in Maven
repositories have long been signed with:

| Accepted | Why |
|---|---|
| SHA-1 and RIPEMD-160 document signatures | Older releases are signed this way |
| SHA-1 and RIPEMD-160 self-signatures, at any date | Many active release keys are still bound by SHA-1 self-signatures. The practical attack on SHA-1 is a chosen-prefix collision, which needs the victim to sign data the attacker prepared; a self-signature is made by the key's owner over their own key, so it does not apply. GnuPG exempts self-signatures for the same reason, and Sigmund never relies on third-party certifications |
| RSA and DSA keys from 1024 bits | Older release keys |

A signature using anything weaker is `INDETERMINATE` with `UNSUPPORTED_ALGORITHM`, not
`FAILED`.

How each tool is made to apply it:

- **Bouncy Castle** — Sigmund configures its verification policy in code.
- **Sequoia (`sq`)** — Sigmund runs `sq` with `SEQUOIA_CRYPTO_POLICY` pointing at a policy file
  it writes, which **replaces the host's system crypto policy** for those runs. On Fedora and
  RHEL the system policy (`/etc/crypto-policies/back-ends/sequoia.config`) rejects SHA-1,
  RIPEMD-160, RSA-1024 and DSA, so without the override a SHA-1-bound key such as many on Maven
  Central would be rejected by `sq` alone. Your own `sq` use outside Sigmund is unaffected.
- **GnuPG** — its defaults already accept the set; Sigmund passes no options. GnuPG does
  reject a SHA-1 self-signature on an ECDSA P-256 key — for hash size rather than for SHA-1 —
  where the other tools accept it; SHA-1-bound keys are in practice RSA or DSA keys from before
  ECDSA was common.

Each tool is also read by what it actually concluded rather than by its exit code: GnuPG exits
0 for a good signature by a revoked key, so Sigmund reads its status lines, and Sequoia's report
is read for whether it found a bad signature or a key it would not use.

## Sigstore Verification

The Sigstore backend verifies `.sigstore.json` bundles using `sigstore-java`'s `KeylessVerifier`. Verification is fully offline after the initial TUF trusted root fetch.

### Auto-Detection

Sigstore signature files are detected by the `.sigstore.json` extension. When verifying dependencies, Sigmund checks for both `.asc` (OpenPGP) and `.sigstore.json` (Sigstore) files alongside each artifact. No configuration is needed to enable Sigstore verification — if the `sigmund-sigstore` module is on the classpath, `.sigstore.json` files are handled automatically.

### Identity Extraction

After a successful Sigstore verification, the tool extracts identity credentials from the Fulcio certificate embedded in the bundle:

- **One `IdentityCredential`** — issuer: the OIDC issuer; attributes: the certificate `subject`, `email` when the subject is an RFC 822 address, and every Fulcio certificate extension present (`source-repository-uri`, `build-config-uri`, and the rest). It matches `identities` and `email` entries in the signer definition. A certificate that names no issuer proves nothing.

### Cross-Backend Identity Matching

An `email` entry matches an address vouched for by any issuer it accepts — the directory `keys.openpgp.org` for OpenPGP keys, or an OIDC provider for Sigstore certificates:

```yaml
issuers:
  - keys.openpgp.org
  - https://accounts.google.com

signers:
  release-lead:
    email: "release@example.com"
    pgp4: "ABCDEF1234567890ABCDEF1234567890ABCDEF12"

rules:
  - match: ["com.example.*"]
    requires: [release-lead]
```

An artifact signed with OpenPGP satisfies `release-lead` by the pinned fingerprint, or by a newer key for which `keys.openpgp.org` has verified the address; one signed with Sigstore satisfies it by the address in a Google-issued certificate. A user ID on an OpenPGP key is never matched on its own.

## Toolchain Configuration

You can configure which tools are used and their order in `sigmund.yaml`:

```yaml
verification:
  toolchain: [bc, sq, gpg]
```

The default toolchain is `[bc, sq, gpg]`:
- BC attempts verification first (zero external dependencies)
- Sequoia is tried if BC cannot verify
- GPG is tried last

**Important:** When `toolchain` is set, only the listed tools are used. Omitted tools are excluded entirely. When `toolchain` is not set, all available tools are initialized in the default order.

### Example: Prefer Sequoia

To prioritize Sequoia for PQC verification:

```yaml
verification:
  toolchain: [sq, bc, gpg]
```

### Example: GPG Only

To use only GPG:

```yaml
verification:
  toolchain: [gpg]
```

## Key Discovery

When a signature is left `INDETERMINATE` with `KEY_UNAVAILABLE` because no local keyring has
its key, Sigmund can fetch the key from a keyserver and verify again. Whether it does, where it
looks and whether it keeps what it fetches are set by `resolve-signers`, `import-to-keyring` and
`keyservers`; see [`verification`](configuration.md#verification) for each setting and its
default.

### How Key Fetching Works

1. Every tool in the toolchain returns `KEY_UNAVAILABLE` for the signature
2. Sigmund takes the issuer fingerprint from the signature packet
3. It asks each keyserver in order, and stops at the first copy that carries user IDs; a copy
   without them is kept only if no keyserver has a fuller one
4. The key is added to the fetching tool's store — in memory for the session, or persisted when
   `import-to-keyring: true`
5. Verification is retried with the key now available

Only BC and GPG fetch keys; `sq` uses only the certificates already in its own store.

| Tool | `import-to-keyring: false` (default) | `import-to-keyring: true` |
|---|---|---|
| BC | kept in memory, discarded when the build ends | written to the shared cert-d |
| GPG | not fetched — GnuPG cannot import a key for one session only | imported into the GnuPG keyring |
| sq | not fetched | not fetched |

Keyservers supply key material only. The signature proves the key whoever served it, and the
claim records which keyserver supplied it. A user ID a keyserver serves is display text, never an
identity, so adding a keyserver such as `keyserver.ubuntu.com` does not widen what is accepted;
identities come only from the [`issuers`](configuration.md#issuers) a policy names.

### Keys Served Without User IDs

`keys.openpgp.org` serves a key without its user IDs until the owner verifies an address. Without
the self-signatures on those user IDs, no tool can validate the key, so its signatures are
`INDETERMINATE` with `KEY_UNAVAILABLE`, not `FAILED`; GnuPG refuses to import such a key at all.
A fuller copy resolves it:

1. List another keyserver after it, so the fetch can find a copy with user IDs:
   ```yaml
   verification:
     keyservers:
       - hkps://keys.openpgp.org
       - hkps://keyserver.ubuntu.com
   ```
2. Or import the key from elsewhere before verifying, e.g. `gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys <FINGERPRINT>`

## Verification Report Format

The verification report shows the outcome of each signature block, and counts
them in its last line.

### Example: All Signatures Verify

```
Signature Verification Report:
  [1] VERIFIED (EdDSA) [key: B9708CEF29D52FAF0783A5B0442ECAFFC2204CA2] [signer: Alice <alice@example.org>]
  [2] VERIFIED (ML-DSA-65+Ed25519) [key: 010940A63349D8D99F0CE7445F3EEDE307F9FCCE2158A7C7FD0C04EC8546F3EA] [signer: <alice@example.org>]
  Overall: 2 VERIFIED
```

### Example: Missing Key

```
Signature Verification Report:
  [1] VERIFIED (EdDSA) [key: B9708CEF29D52FAF0783A5B0442ECAFFC2204CA2] [signer: Alice <alice@example.org>]
  [2] INDETERMINATE [KEY_UNAVAILABLE: no local key store or configured keyserver has it] (ML-DSA-65+Ed25519) [key: 010940A63349D8D99F0CE7445F3EEDE307F9FCCE2158A7C7FD0C04EC8546F3EA]
  Overall: 1 VERIFIED, 1 INDETERMINATE
```

In strict mode (default), this fails: a block nobody could check is not a pass.
In lenient mode (`--lenient`), it passes because at least one signature is valid
and none failed.

### Example: A Block No Tool Can Check

The same file verified with `toolchain: [gpg]`, which does not read the PQC block:

```
Signature Verification Report:
  [1] VERIFIED (EDDSA) [key: B9708CEF29D52FAF0783A5B0442ECAFFC2204CA2] [signer: Alice <alice@example.org>]
  [2] INDETERMINATE [UNSUPPORTED_ALGORITHM] (ML-DSA-65+Ed25519) [key: 010940A63349D8D99F0CE7445F3EEDE307F9FCCE2158A7C7FD0C04EC8546F3EA]
  Overall: 1 VERIFIED, 1 INDETERMINATE
```

The unchecked block is reported rather than left out, so strict mode fails here too; lenient mode
passes.

### Example: Failed Signature

The artifact changed after it was signed:

```
Signature Verification Report:
  [1] FAILED (EdDSA) [key: B9708CEF29D52FAF0783A5B0442ECAFFC2204CA2] [signer: Alice <alice@example.org>]
  [2] FAILED (ML-DSA-65+Ed25519) [key: 010940A63349D8D99F0CE7445F3EEDE307F9FCCE2158A7C7FD0C04EC8546F3EA] [signer: <alice@example.org>]
  Overall: 2 FAILED
```

This fails in both strict and lenient modes: a `FAILED` block is an attack
signal, and no mode tolerates it.

## Troubleshooting

### "No signatures found in signature file"

The `.asc` file contains no valid OpenPGP armored blocks. Check that the file:
- Contains `-----BEGIN PGP SIGNATURE-----` and `-----END PGP SIGNATURE-----`
- Was not corrupted during transfer
- Is an actual signature file (not a public key or encrypted message)

### "No public key"

The signing key is not in any keyring. Solutions:

1. **Enable automatic key fetching** (default):
   ```yaml
   verification:
     resolve-signers: true
   ```

2. **Import the key manually:**
   ```bash
   gpg --recv-keys <FINGERPRINT>
   # or
   sq cert import --cert-file signer-cert.asc
   ```

3. **Use lenient mode** if other signatures are valid:
   ```bash
   sigmund verify-signature --file ... --signature ... --lenient
   ```

### GPG prints "packet with unknown version 6" but succeeds

This is expected when verifying hybrid signatures. GPG processes the v4 classical signature and ignores the v6 PQC signature it doesn't understand. The verification succeeds because the classical signature is valid.

To verify the PQC signature, ensure Sequoia is installed and appears in the toolchain:

```yaml
verification:
  toolchain: [bc, sq, gpg]
```

### "Bad signature"

The signature is invalid. Possible causes:
- The artifact was modified after signing
- The wrong artifact or signature file was provided
- The signature file is corrupted

Ensure you are verifying the correct artifact against the correct signature file.
