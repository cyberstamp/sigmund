# Architecture

This document describes how Sigmund works internally — the three-tool system, pipeline architecture, key management, interoperability, and identity verification.

## Contents

- [Three-Tool System](#three-tool-system)
- [Toolchain and Routing](#toolchain-and-routing)
- [OpenPGP Key Structure](#openpgp-key-structure)
- [Key Management](#key-management)
  - [BC Key Store](#bc-key-store)
  - [Sequoia Keystore](#sequoia-keystore)
  - [GnuPG Keyring](#gnupg-keyring)
  - [Passphrase Protection](#passphrase-protection)
- [Interoperability Matrix](#interoperability-matrix)
- [Signing Pipeline](#signing-pipeline)
  - [Stage 1: Classic Signature](#stage-1-classic-signature)
  - [Stage 2: PQC Signature (Optional)](#stage-2-pqc-signature-optional)
  - [Stage 3: Combine](#stage-3-combine)
- [Verification Pipeline](#verification-pipeline)
  - [BC Verification](#bc-verification)
  - [sq Verification (v5+ packets)](#sq-verification-v5-packets)
  - [gpg Verification (v1-v4 packets)](#gpg-verification-v1-v4-packets)
  - [Verification Modes](#verification-modes)
- [Identity Verification Layer](#identity-verification-layer)
  - [Layer 2: Signature Operations](#layer-2-signature-operations)
  - [Layer 1: Identity Verification](#layer-1-identity-verification)
  - [Credential Types and Matching](#credential-types-and-matching)
  - [Artifact Outcomes](#artifact-outcomes)
- [Supported Cipher Suites](#supported-cipher-suites)
  - [Phase 1 (Implemented)](#phase-1-implemented)
  - [Phase 2 (Planned for BC)](#phase-2-planned-for-bc)
  - [Sequoia sq PQC Support](#sequoia-sq-pqc-support)
- [Project Structure](#project-structure)

## Three-Tool System

Sigmund supports three OpenPGP backends, each with distinct capabilities:

| Tool | Availability | v4 Support | v6 Support | PQC Support | Process Deps |
|------|--------------|------------|------------|-------------|--------------|
| **BC** | Always (pure Java) | Sign, verify | Sign, verify (classic algos) | Phase 2 planned | None |
| **sq** | Optional | Verify | Sign, verify | Sign, verify (RFC 9980) | Sequoia CLI |
| **gpg** | Optional | Sign, verify | None | None | GnuPG CLI |
| **sigstore** | Optional (pure Java) | N/A | N/A | N/A | None |

**BC (Bouncy Castle)** is the default first-choice tool. It requires no external process dependencies and works on any JVM. BC generates v6 keys for Ed25519, Ed448, and RSA using Bouncy Castle 1.85's `BcOpenPGPApi`. ECDSA keys (P-256, P-384, P-521) use a JCA-based fallback and produce v4 keys.

**sq (Sequoia)** is used for PQC hybrid signing when available. Version 1.4.0+ implements RFC 9980 and can generate and verify ML-DSA composite signatures.

**gpg (GnuPG)** provides compatibility with existing GPG-based workflows and reads GPG keyrings. GnuPG follows LibrePGP and does not support v6 keys.

**sigstore** provides OIDC-based keyless signing and verification via the `sigmund-sigstore` module. It uses `dev.sigstore:sigstore-java` for both signing (Fulcio + Rekor) and verification (KeylessVerifier). It is pure Java, requires no external CLI binary, and is ServiceLoader-discovered — adding `sigmund-sigstore` to the classpath is sufficient. The `SigstoreToolFactory` implements the `SignatureToolFactory` SPI.

## Toolchain and Routing

Claims are routed to tools based on a configurable toolchain. The default toolchain is:

```
[bc, sq, gpg]
```

BC attempts verification first. If BC cannot fully verify a signature (missing key, unsupported algorithm, or verification failure), the next tool in the toolchain is tried. This ensures that each tool's strengths are leveraged — BC's zero-dependency backend, GPG's local keyring (`pubring.kbx`), and Sequoia's PQC support and cert store.

The routing mechanism works as follows:

1. Each signature file is parsed into one or more `Claim`s by its `SignatureFormat`
2. For each unit, tools are checked in toolchain order
3. Each tool where `canVerify(unit)` returns true attempts verification
4. If a tool returns `VERIFIED`, it is used immediately
5. If a tool does not verify the block, the next tool is tried — a different tool may have the key in its local keyring or support the algorithm
6. If no tool verifies it, the most conclusive result seen is kept (`FAILED` over an undecided one, and among undecided ones a transient reason over a permanent one)

For example, a hybrid `.asc` with both a PGP4 (RSA) and PGP6 (ML-DSA) signature:
- **PGP4 block:** BC may return `KEY_UNAVAILABLE` if the key is not in its stores, but GPG finds it in `pubring.kbx` and verifies it
- **PGP6 block:** BC and GPG cannot verify ML-DSA, but Sequoia finds the key in its cert store and verifies it

Configure the toolchain in `sigmund.yaml`:

```yaml
discovery:
  toolchain: [bc, sq, gpg]
```

When `toolchain` is set, only the listed tools are used. When omitted, all available tools are initialized in the default order.

## OpenPGP Key Structure

**EdDSA keys** (Ed25519, Ed448) have a three-key structure:
- **Primary key** — Certify-only, signs subkeys
- **Encryption subkey** — X25519 or X448, used for encryption
- **Signing subkey** — Ed25519 or Ed448, used for signatures

**RSA keys** are singleton keys with all flags (certify + sign + encrypt) on the primary key.

**ECDSA keys** (P-256, P-384, P-521) generated by BC use a singleton structure similar to RSA.

Key flags determine which key in the ring is used for each operation. Sigmund's signing flow prefers subkeys over the primary key, selecting the first signing-capable subkey if one exists, otherwise falling back to the primary key if it has the sign flag.

## Key Management

### BC Key Store

BC manages keys across three sources, searched in order:

1. **GnuPG pubring** (`~/.gnupg/pubring.kbx` or legacy `pubring.gpg`) — read-only. BC can read public keys from GnuPG's keyring for verification. The modern keybox format (`pubring.kbx`, GnuPG 2.1+) is tried first.

2. **Shared cert-d** (`~/.local/share/openpgp-cert-d/`) — read/write for public certificates. Uses the standard OpenPGP cert-d two-level directory layout (fingerprint `ABCDEF...` is stored at `AB/CDEF...`). Public certificates written here are visible to `sq` and other tools that support cert-d.

3. **BC private store** (`~/.local/share/openpgp-cert-d/bc-private/`) — read/write for private keys. BC-generated private keys are stored in standard OpenPGP transferable secret key format in a subdirectory under cert-d.

4. **Ephemeral cache** — in-memory cache for keys fetched from keyservers when `import-to-keyring` is false. Keys are available for verification during the session but are not persisted to disk.

The key lookup algorithm in `BcKeyStore.findPublicKey()`:
1. Check GnuPG pubring for matching fingerprint
2. Check cert-d for matching fingerprint (primary key or subkey)
3. Extract public keys from BC private store if a matching secret key exists
4. Check ephemeral in-memory cache

### Sequoia Keystore

Sequoia manages its own keystore controlled by the `SEQUOIA_HOME` environment variable (defaults to `~/.local/share/sequoia`). Keys generated with `sq key generate` are stored here and used for signing with the `sq` tool.

### GnuPG Keyring

GnuPG uses the standard keyring at `~/.gnupg/`. Keys managed by `gpg` are stored here.

### Passphrase Protection

BC private keys can be encrypted at rest using AES-256 AEAD (OCB mode) with Argon2 S2K key derivation. Each key in the ring is encrypted individually because v6 AEAD encryption binds the ciphertext to the key's public key packet as associated data.

Passphrase resolution order:
1. Explicit `PassphraseProvider` via `Sigmund.Builder.bcPassphraseProvider()` (programmatic API)
2. `passphrase-env` setting (env var name, default `SIGMUND_BC_PASSPHRASE`)
3. Interactive console prompt (if a terminal is available)
4. No passphrase (works only for unencrypted keys)

Private key files in `bc-private/` are created with owner-only (600) file permissions on POSIX systems.

## Interoperability Matrix

| From → To | BC | sq | gpg |
|-----------|----|----|-----|
| **BC v6 keys** | Yes | Yes | No (v6 not supported) |
| **BC v4 keys** | Yes | Yes | Yes |
| **sq v6 classic** | Yes | Yes | No |
| **sq v6 PQC** | Phase 2 | Yes | No |
| **gpg v4** | Yes | Yes | Yes |

**BC → sq interop** works for v6 keys because both support RFC 9580 (OpenPGP v6). BC-generated public certs are written to the shared cert-d so `sq` can see them.

**BC → gpg interop** works only for v4 keys. BC can read GPG's `pubring.kbx` (or legacy `pubring.gpg`) for verification. BC v6 keys cannot be imported into GPG because GPG follows LibrePGP and does not support v6.

**sq → BC interop** works for v6 classic algorithm signatures (Ed25519, Ed448, RSA). PQC signatures (algorithm IDs 30-36) cannot be parsed by BC yet (Phase 2).

## Signing Pipeline

The signing flow has three stages:

```
artifact.jar
    |
    +-- bc / gpg --detach-sign --> classic.asc  (v4 or v6 signature packet)
    |
    +-- sq sign --signature-file --> pqc.sig    (v6 PQC signature packet)
    |
    +-- OpenPgpSignatureFormat.combine() -> artifact.jar.asc
```

### Stage 1: Classic Signature

The signing tool (BC by default, or GPG if configured) produces a detached ASCII-armored signature. BC uses Bouncy Castle's `PGPSignatureGenerator` to create the signature in pure Java. GPG invokes the external `gpg` process:

```bash
gpg --batch --yes --armor --detach-sign [--local-user <keyId>] --output <sig> <artifact>
```

The signature version (v4 or v6) is determined by the key version. BC generates v6 signatures for v6 keys and v4 signatures for v4 keys. GPG always produces v4 signatures.

The `Signer` class orchestrates the signing flow:
1. Call `sign()` on each configured tool → `SignResult` with algorithm metadata
2. Group results by `SignatureFormat`
3. For combinable formats → merge into one output file
4. For non-combinable → write each as a separate file
5. Return `SigningOutput` with metadata per file

### Stage 2: PQC Signature (Optional)

If PQC signing is configured and `sq` is available, `SqRunner` invokes Sequoia `sq` as an external process:

```bash
sq --overwrite sign --signer <fingerprint> --signature-file <sig> <artifact>
```

Sequoia produces a detached ASCII-armored signature containing a v6 OpenPGP signature packet with the configured PQC hybrid cipher suite (ML-DSA-87+Ed448 by default) per RFC 9980.

### Stage 3: Combine

`OpenPgpSignatureFormat` concatenates the signatures into a single `.asc` file as separate armored blocks, classic first:

```
-----BEGIN PGP SIGNATURE-----
(classic signature — exactly as the tool produced it)
-----END PGP SIGNATURE-----
-----BEGIN PGP SIGNATURE-----
(PQC signature — exactly as Sequoia produced it)
-----END PGP SIGNATURE-----
```

Neither signature is re-armored — each is preserved byte-for-byte as its respective tool produced it. Verifiers that parse only the first armored block (including Maven Central) see only the classic signature and succeed. PQC-aware tools process all blocks.

## Verification Pipeline

```
artifact.jar + artifact.jar.asc
    |
    +-- extract all armored blocks
    |
    +-- for each block:
    |     route to tool based on priority and canVerify()
    |     bc / sq / gpg verify --> VerifyResult (VERIFIED/FAILED/INDETERMINATE + reason)
    |
    +-- SignatureVerificationReport (all results)
```

Each armored block is parsed into a `Claim` and routed to the first available tool in the priority list that can handle it (via `canVerify()`).

### BC Verification

BC handles any `OpenPgpClaim` (v4 or v6 classic algorithms). Verification steps:

1. Extract issuer fingerprint from the signature packet's Issuer Fingerprint subpacket (type 33)
2. Search for the signer's public key in GnuPG pubring, cert-d, or BC private store
3. If key not found and key fetching is enabled, attempt to import from keyservers
4. Parse the signature packet using Bouncy Castle's `BcPGPObjectFactory`
5. Verify the signature against the artifact using BC's `PGPSignature.verify()`
6. Return `VERIFIED` or `FAILED`

### sq Verification (v5+ packets)

The issuer fingerprint is extracted from the signature packet, used to look up the signer's certificate in the Sequoia cert store (`sq inspect --cert`), locate the cert file in cert-d, and verify with `sq verify --signer-file`. If the certificate is not in the store, the result is `INDETERMINATE [KEY_UNAVAILABLE]`. If `sq` is not available or the fingerprint cannot be extracted, it is `INDETERMINATE` citing `TOOL_UNAVAILABLE` or `UNSUPPORTED_ALGORITHM`.

### gpg Verification (v1-v4 packets)

Runs `gpg --verify` against the local keyring. GPG exit codes are interpreted as:
- **Exit 0** — signature valid (`VERIFIED`)
- **Exit 2 with "Good signature" in stderr** — signature valid but GPG encountered an unknown packet (`VERIFIED`). This is the expected result for hybrid `.asc` files containing v6 PQC packets.
- **Exit 1** — bad signature (`FAILED`)
- **stderr contains "No public key"** — signer's key not in keyring (`KEY_UNAVAILABLE`)

The block's public-key algorithm ID is used to classify the signature as PQC or classical in the report. PQC algorithm IDs are 30-36 per the IANA OpenPGP Public Key Algorithms registry (RFC 9980).

### Verification Modes

- **Default:** Every signature in the file must pass for the overall result to be `PASS`.
- **Lenient (`--lenient`):** At least one signature must pass and none may fail. Skipped or no-key signatures are tolerated.

## Identity Verification Layer

Sigmund implements a two-layer architecture separating cryptographic verification (Layer 2) from identity-based trust assessment (Layer 1).

### Layer 2: Signature Operations

Layer 2 is the `SignatureTool` SPI, implemented by `BcRunner`, `SqRunner`, and `GpgRunner`. Each tool:

1. Declares capabilities via `supportedCredentialTypes()` (e.g., `["openpgp4", "openpgp6"]`)
2. Routes verification via `canVerify(Claim)` (packet version and algorithm)
3. Performs cryptographic verification → `VerifyResult` (outcome, reason, and metadata)
4. Extracts proven credentials via `extractCredentials(VerifyResult)` → `List<Credential>`

The credential type is determined by the packet version that was cryptographically verified:
- `version < 6` → `FingerprintCredential("openpgp4", fingerprint)`
- `version >= 6` → `FingerprintCredential("openpgp6", fingerprint)`

### Layer 1: Identity Verification

Layer 1 is the `EvidenceProvider` interface, bridged from Layer 2 via `SignatureEvidenceAdapter`. The adapter:

1. Delegates `canHandle(Path)` to `SignatureFormat`
2. Parses signature files into `Claim`s
3. Routes each unit to the appropriate `SignatureTool`
4. Handles key fetching when a claim is left undecided by `KEY_UNAVAILABLE` (if `resolve-signers` is enabled)
5. Records a tool that throws as `INDETERMINATE [TOOL_UNAVAILABLE]` rather than letting it end the run
6. Wraps `VerifyResult` + the credentials the tool extracted into a `ClaimResult`, which also
   carries the evidence it was read from, the trust root it was checked against, the tool that
   checked it, and when the claim was made

The `TrustVerifier` consumes `ClaimResult`s and produces one `ArtifactResult` per artifact:

1. **Collect claims** — each provider verifies the evidence resolved for the artifact
2. **Evaluate requirements** — `TrustPolicy.requirements()` decides which verified claims the
   policy accepts, and which it does not
3. **Roll up** — `OutcomeRollup` derives the `ArtifactOutcome` from the claims and that
   evaluation, in a fixed order: a failed claim dominates, claims no installed tool supports
   are set aside, no applicable rule means `NOT_CONFIGURED`, requirements met means
   `SATISFIED`, and otherwise the most informative remaining state decides

The roll-up lives in core rather than in an integration so that a goal and a resolver-level
extension cannot reach different outcomes from the same policy and the same evidence.

### Credential Types and Matching

Sigmund supports multiple credential types:

- `FingerprintCredential(type, fingerprint)` — OpenPGP fingerprint with credential type
  - Type: `"openpgp4"` or `"openpgp6"`
  - Matches: exact fingerprint match, same credential type
- `EmailCredential(email)` — email address extracted from user ID
  - Matches: case-insensitive email match
- `SigstoreCredential` — Sigstore certificate extension fields (issuer, subject, source-repository-uri, etc.)
  - Type: `"sigstore"`
  - Built via `SigstoreCredential.Builder` with nullable fields
  - Matches: every non-null field in the configured credential must equal the corresponding field in the extracted credential. Null fields are wildcards. This enables flexible trust policies — matching on `issuer` + `source-repository-uri` trusts all releases from a repository without pinning to a specific workflow ref.
  - Extracted from Fulcio certificates during Sigstore verification. When the certificate subject is an email (SAN type `rfc822Name`), an `EmailCredential` is also extracted, enabling cross-backend matching.

Identity matching works via credential overlap: a claim satisfies a signer when one of the
credentials it proved matches one the signer is configured with.

The matching logic lives in `TrustPolicy.requirements()`, the default
`RequirementEvaluator`:
```java
for (Credential proven : claim.attesterCredentials()) {
    for (Credential expected : signer.credentials()) {
        if (expected.matches(proven)) {
            return true;
        }
    }
}
```

It is a separate interface from the roll-up on purpose: deriving an outcome needs to know
whether requirements were met and which claims met them, not what a requirement is.

### Artifact Outcomes

- `SATISFIED` — the claims found meet what the policy requires of this artifact
- `UNSATISFIED` — verification succeeded, but not by a signer the policy accepts
- `FAILED` — a signature did not verify; an attack signal, and never tolerated
- `NO_CLAIM` — no evidence was found at all
- `INDETERMINATE` — nothing could be established either way, with a reason saying why
- `NOT_CONFIGURED` — no rule applies to this artifact

`NO_CLAIM` replaces the older `UNSIGNED`, which stops being accurate once provenance exists:
an artifact can be unsigned but attested, or signed but unattested. Separating `FAILED` from
`INDETERMINATE` is what keeps "checked and rejected" apart from "could not check".

## Supported Cipher Suites

### Phase 1 (Implemented)

Classic algorithms supported by BC:
- `ed25519` — EdDSA with Ed25519 curve (default)
- `ed448` — EdDSA with Ed448 curve
- `rsa4096` — RSA with 4096-bit modulus
- `nistp256` — ECDSA with P-256 curve
- `nistp384` — ECDSA with P-384 curve
- `nistp521` — ECDSA with P-521 curve

### Phase 2 (Planned for BC)

PQC composite algorithms:
- `mldsa87-ed448` — ML-DSA-87 + Ed448 hybrid
- `mldsa65-ed25519` — ML-DSA-65 + Ed25519 hybrid

### Sequoia sq PQC Support

Sequoia sq 1.4.0+ supports:
- `mldsa87-ed448` — ML-DSA-87 + Ed448 (default)
- `mldsa65-ed25519` — ML-DSA-65 + Ed25519

PQC algorithm IDs (RFC 9980):
- 30: ML-DSA-65+Ed25519
- 31: ML-DSA-87+Ed448
- 32-34: SLH-DSA variants
- 35-36: ML-KEM composites

## Project Structure

```
core/              Core signing and verification library (pure Java, no CLI dependencies)
cli/               Command-line interface (picocli)
maven-plugin/      Maven plugin for build integration
sigstore/          Sigstore signing/verification backend (dev.sigstore:sigstore-java)
```
