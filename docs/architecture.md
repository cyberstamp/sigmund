# Architecture

This document describes how Sigmund is built — its tools, key stores, the signing and verification pipelines, and the types behind identity verification. For the model these implement — evidence, claims, credentials, policy and outcomes — read [How Sigmund Works](how-it-works.md) first.

## Contents

- [Tools](#tools)
- [Toolchain and Routing](#toolchain-and-routing)
- [OpenPGP Key Structure](#openpgp-key-structure)
- [Key Management](#key-management)
  - [BC Key Store](#bc-key-store)
  - [Sequoia Keystore](#sequoia-keystore)
  - [GnuPG Keyring](#gnupg-keyring)
  - [Passphrase Protection](#passphrase-protection)
- [Interoperability Matrix](#interoperability-matrix)
- [Signing Pipeline](#signing-pipeline)
- [Verification Pipeline](#verification-pipeline)
  - [BC Verification](#bc-verification)
  - [sq Verification (v4 and v6 packets)](#sq-verification-v4-and-v6-packets)
  - [gpg Verification (v1-v4 packets)](#gpg-verification-v1-v4-packets)
  - [Verification Modes](#verification-modes)
- [Identity Verification Layer](#identity-verification-layer)
  - [Layer 2: Signature Operations](#layer-2-signature-operations)
  - [Layer 1: Identity Verification](#layer-1-identity-verification)
  - [Policy Model](#policy-model)
  - [Credential Types and Matching](#credential-types-and-matching)
- [Cipher Suites](#cipher-suites)
- [Project Structure](#project-structure)

## Tools

Sigmund has three OpenPGP backends and a Sigstore one:

| Tool | Availability | v4 Support | v6 Support | PQC Support | Process Deps |
|------|--------------|------------|------------|-------------|--------------|
| **BC** | Always (pure Java) | Sign, verify | Sign, verify (classic algorithms) | Verify ML-DSA composites (RFC 9980); signing planned | None |
| **sq** | Optional | Sign, verify | Sign, verify | Sign, verify (RFC 9980) | Sequoia CLI |
| **gpg** | Optional | Sign, verify | None | None | GnuPG CLI |
| **sigstore** | Optional (pure Java) | N/A | N/A | N/A | None |

**BC (Bouncy Castle)** is the default first-choice tool. It requires no external process dependencies and works on any JVM. BC generates v4 keys by default, the version keyservers serve and GnuPG reads, and v6 keys on request (Ed25519, Ed448 and RSA, through Bouncy Castle's `BcOpenPGPApi`); ECDSA keys (P-256, P-384, P-521) use a JCA-based fallback and are v4 only. See [Known Limitations](limitations.md#not-every-bc-cipher-suite-has-both-key-versions).

**sq (Sequoia)** is used for PQC hybrid signing when available. Version 1.4.0+ implements RFC 9980 and can generate and verify ML-DSA composite signatures.

**gpg (GnuPG)** provides compatibility with existing GPG-based workflows and reads GPG keyrings. GnuPG follows LibrePGP and does not support v6 keys.

**sigstore** provides OIDC-based keyless signing and verification via the `sigmund-sigstore` module. It uses `dev.sigstore:sigstore-java` for both signing (Fulcio + Rekor) and verification (KeylessVerifier). It is pure Java, requires no external CLI binary, and is ServiceLoader-discovered — adding `sigmund-sigstore` to the classpath is sufficient. The `SigstoreToolFactory` implements the `SignatureToolFactory` SPI.

## Toolchain and Routing

Claims are routed to tools based on a configurable toolchain. The default toolchain is:

```
[bc, sq, gpg]
```

BC attempts verification first. If BC cannot decide a signature (missing key, unsupported algorithm), the next tool in the toolchain is tried; a signature BC verifies or fails is not passed on. This ensures that each tool's strengths are leveraged — BC's zero-dependency backend, GPG's local keyring (`pubring.kbx`), and Sequoia's PQC support and cert store.

The routing mechanism, `ClaimRouter`, is shared by trust verification and by `verify-signature`, so the two cannot disagree about a claim:

1. Each signature file is parsed into one or more `Claim`s by its `SignatureFormat`
2. An OpenPGP claim whose block holds no signature packet — one that cannot be decoded, or whose first packet is not a signature or compressed data — or whose signature type is not a binary or text document signature is `INDETERMINATE [EVIDENCE_MALFORMED]` and no tool is asked: the backends disagree on such a block, or set it aside as unsupported when they decline it, so the router settles it
3. For each other claim, tools are checked in toolchain order
4. Each tool where `canVerify(claim)` returns true attempts verification
5. If a tool returns `VERIFIED` or `FAILED`, that answer stands and no later tool is asked — the toolchain order decides which tool answers, never what the answer is, so a `FAILED` cannot be outvoted
6. If a tool leaves the claim `INDETERMINATE`, the next tool is tried — a different tool may have the key in its local keyring or support the algorithm; a tool that throws is recorded as `TOOL_UNAVAILABLE` and the next tool still gets its turn
7. If no tool decides it, the most conclusive result seen is kept (a transient reason over a permanent one)
8. A claim no tool answered is `INDETERMINATE [UNSUPPORTED_ALGORITHM]`; it is never left out, so a block nobody could check cannot pass strict verification

For example, a hybrid `.asc` with both a PGP4 (RSA) and PGP6 (ML-DSA) signature:
- **PGP4 block:** BC may return `KEY_UNAVAILABLE` if the key is not in its stores, but GPG finds it in `pubring.kbx` and verifies it
- **PGP6 block:** GPG cannot verify ML-DSA; BC verifies it when the key is in its stores, and otherwise Sequoia finds the key in its cert store and verifies it

Configure the toolchain in `sigmund.yaml`:

```yaml
verification:
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

BC manages keys across four sources:

1. **GnuPG pubring** (`~/.gnupg/pubring.kbx` or legacy `pubring.gpg`) — read-only. BC can read public keys from GnuPG's keyring for verification. The modern keybox format (`pubring.kbx`, GnuPG 2.1+) is tried first.

2. **Shared cert-d** (`~/.local/share/pgp.cert.d/`) — read/write for public certificates. Uses the standard OpenPGP cert-d two-level directory layout (fingerprint `ABCDEF...` is stored at `AB/CDEF...`). It is the location the cert-d specification names and `sq`'s default certificate store, so certificates written here are visible to `sq` and other tools that support cert-d.

3. **BC private store** (`~/.local/share/sigmund/bc-private/`) — read/write for private keys. BC-generated private keys are stored in standard OpenPGP transferable secret key format, in the same two-level layout, outside the shared cert-d: that is a public certificate store other tools read, and secret keys do not belong in it.

4. **Ephemeral cache** — in-memory cache for keys fetched from keyservers when `import-to-keyring` is false. Keys are available for verification during the session but are not persisted to disk.

The key lookup algorithm in `BcKeyStore.findPublicKey()` returns the key together with its source:
1. Check the ephemeral in-memory cache
2. Check GnuPG pubring for matching fingerprint
3. Check cert-d for matching fingerprint (primary key or subkey)
4. Extract public keys from BC private store if a matching secret key exists

A key fetched this session reports the keyservers that served it (`TrustRootRef.keyservers`, their URLs in configured order), wherever it was stored; otherwise the store it was found in is reported. Claims carry that source in their trust root.

Responsibilities are split three ways:
- **`BcKeyStore`** — where keys live: lookup in order, per-store answers for `inspect-signer`, storing generated keys, and storing fetched keys (`addFetched`), which keeps, of the certificates the keyservers served, those of the asked key's own certificate (or the one that binds it as a subkey) and joins them, with every local copy of that certificate, into one certificate, keeps it in memory or writes it to cert-d according to `import-to-keyring`, and records the contributing keyservers in the same step. It keeps each keyserver's copy beside the joined certificate, and answers which servers' copies carried a given user ID or revocation — the provenance behind the display label and the revocation detail.
- **`KeyserverFetcher`** — talking to HKP keyservers: the HTTP client, which asks every configured keyserver for a missing key concurrently, the size limit per copy (1 MiB, against certificate flooding), and the per-build `KeyFetchCache` with its per-server circuit breaker, which trips on a server that cannot answer — unreachable, timed out, or any answer but the key or 404 — and credits only servers whose copy the store kept. It records, per key, which servers could not answer, for the not-found detail. It hands the readable copies to the store; a copy of a different primary key, possible for a 64-bit key-ID lookup, is set aside. The factory creates one when `resolve-signers` is on and keyservers are configured.
- **`BcRunner`** — signing, verification, key generation and signer inspection, using the store and, when keys may be fetched, the fetcher.

### Sequoia Keystore

Sequoia manages its own keystore, in `tools.sq.home` when set, else where the `SEQUOIA_HOME` environment variable points, else `sq`'s default (`~/.local/share/sequoia` on Linux). Keys generated with `sq key generate` are stored here and used for signing with the `sq` tool.

### GnuPG Keyring

GnuPG uses its keyring in `tools.gpg.home` when set, else its own default (`~/.gnupg/`). Keys managed by `gpg` are stored here.

### Passphrase Protection

BC private keys can be encrypted at rest using AES-256 AEAD (OCB mode) with Argon2 S2K key derivation. Each key in the ring is encrypted individually because v6 AEAD encryption binds the ciphertext to the key's public key packet as associated data.

Passphrase resolution order:
1. Explicit `PassphraseProvider` via `Sigmund.Builder.bcPassphraseProvider()` (programmatic API)
2. `passphrase-env` setting (env var name, default `SIGMUND_BC_PASSPHRASE`; a variable named there that is not set is an error)
3. Interactive console prompt (only when the run is interactive and a terminal is available; never under `mvn -B` or on CI)
4. No passphrase (works only for unencrypted keys)

Private key files in `bc-private/` are created with owner-only (600) file permissions on POSIX systems.

## Interoperability Matrix

| From → To | BC | sq | gpg |
|-----------|----|----|-----|
| **BC v6 keys** (ML-DSA composites included) | Yes | Yes | No (v6 not supported) |
| **BC v4 keys** | Yes | Yes | Yes |
| **sq v6 classic** | Yes | Yes | No |
| **sq v6 PQC** | Yes | Yes | No |
| **gpg v4** | Yes | Yes | Yes |

**BC → sq interop** works for v6 keys because both support RFC 9580 (OpenPGP v6). BC-generated public certs are written to the shared cert-d so `sq` can see them.

**BC → gpg interop** works only for v4 keys. BC can read GPG's `pubring.kbx` (or legacy `pubring.gpg`) for verification. BC v6 keys cannot be imported into GPG because GPG follows LibrePGP and does not support v6.

**sq → BC interop** works for v6 classic algorithm signatures (Ed25519, Ed448, RSA) and the post-quantum signatures of RFC 9980: the ML-DSA composites (ML-DSA-65+Ed25519, ML-DSA-87+Ed448) and SLH-DSA, in agreement with `sq` under Sigmund's crypto policy (`BcPostQuantumTest`).

## Signing Pipeline

```
artifact.jar
    |
    +-- SigningPlan: the keys of every signing tool, narrowed to the requested credential types
    |
    +-- for each planned key, in tool order:
    |     bc     PGPSignatureGenerator                      --> temporary .asc (v4 or v6 packet)
    |     gpg    gpg --detach-sign --local-user <fpr>       --> temporary .asc (v4 packet)
    |     sq     sq sign --signer <fpr> --signature-file    --> temporary .asc (v4 or v6 packet)
    |     sigstore  Fulcio certificate + Rekor entry        --> temporary .sigstore.json
    |
    +-- SignerBindingCheck: each signature must prove signing.signer, when set
    |
    +-- per format: OpenPGP signatures combined into artifact.jar.asc, v4 blocks first;
        a Sigstore bundle written as artifact.jar.sigstore.json
```

The `Signer` class orchestrates the signing flow:
1. Work out the `SigningPlan` when the `Signer` is created: each tool's keys (`signingInfo()`;
   a tool reporting no key signs once), narrowed to the requested credential types when there
   are any; a tool left with no key does not sign. A plan with a problem (a key whose type
   cannot be read while types are requested, a requested type no key has) fails before any tool
   signs
2. Call `sign()` once per planned key, in tool order and then key order, each into its own
   temporary file → `SignResult` with algorithm metadata
3. When `signing.signer` asserts a signer, `SignerBindingCheck` verifies each fresh signature and
   requires it to prove that signer; one that does not fails signing, and nothing is written
4. Group results by `SignatureFormat`
5. For combinable formats → merge into one output file
6. For non-combinable → write each as a separate file
7. Return `SigningOutput` with metadata per file

Each tool signs with the key its settings select. BC signs in-process with Bouncy Castle; `gpg`
and `sq` run as external processes:

```bash
gpg --batch --yes --armor --detach-sign [--pinentry-mode loopback --passphrase-fd 0] \
    [--local-user <fingerprint>] --output <sig> <artifact>
sq sign --signer <fingerprint> --signature-file <sig> <artifact>
```

The signature packet's version follows the key's: a v4 key gives a v4 signature, a v6 key a v6
one, post-quantum keys included. GnuPG signs with v4 keys only.

`OpenPgpSignatureFormat.combine` concatenates a file's OpenPGP signatures into one `.asc`, one
armored block each, ordered by packet version — v4 before v6, the planned order kept within a
version:

```
-----BEGIN PGP SIGNATURE-----
(v4 signature — exactly as its tool produced it)
-----END PGP SIGNATURE-----
-----BEGIN PGP SIGNATURE-----
(v6 signature, such as a PQC one — exactly as its tool produced it)
-----END PGP SIGNATURE-----
```

No signature is re-armored. Verifiers that parse only the first armored block — Maven Central,
`sq verify` — see the classic signature. Sigmund splits the file into its blocks and verifies
each as its own claim.

## Verification Pipeline

```
artifact.jar + artifact.jar.asc
    |
    +-- extract all armored blocks
    |
    +-- for each block (a Claim):
    |     ClaimRouter: tools in toolchain order, those whose canVerify() accepts it
    |     bc / sq / gpg verify --> VerifyResult (VERIFIED/FAILED/INDETERMINATE + reason)
    |     the answer that counts --> ClaimResult
    |
    +-- SignatureVerificationReport (one ClaimResult per block)
```

Each armored block is parsed into a `Claim` and routed by `ClaimRouter` through the tools in the toolchain that can handle it (via `canVerify()`); the answer that counts becomes the block's `ClaimResult`. `verify-signature` reports these directly; trust verification evaluates the same records against the policy.

### BC Verification

BC handles any `OpenPgpClaim` (v4 or v6, classic or the post-quantum signatures of RFC 9980) except one naming ML-KEM, which no signature is made with. Verification steps:

1. Extract issuer fingerprint from the signature packet's Issuer Fingerprint subpacket (type 33), or the 64-bit key ID when it carries none
2. Search for the signer's certificate in the key store (`BcKeyStore.findPublicKey()`); if it is absent and key fetching is enabled, fetch it from keyservers (`KeyserverFetcher`)
3. Parse the signature packet using Bouncy Castle's `BcPGPObjectFactory`
4. Verify with Bouncy Castle's high-level API (`OpenPGPCertificate` and `OpenPGPDetachedSignatureProcessor`): the signature must be correct and made, at its creation time, by the primary key or a subkey validly bound to it — binding signature, signing flag, a signing subkey's back-signature, not revoked or expired, the primary key's expiry applying to the whole certificate. Bouncy Castle sets aside the self-signatures and revocations that do not verify against the primary key, so a packet a keyserver added without the holder's key changes nothing; validity is judged on a view of the certificate without user ID revocations and without the user IDs no certification binds, as Bouncy Castle would otherwise take the primary key's binding from such a user ID
5. Return `VERIFIED`, proving the signing key's and the primary key's full fingerprints, when the signature is correct and the key valid
6. When the signature is correct (`isTestedCorrect()`) but the key is not valid, explain why: revoked or expired at the signature's time is `FAILED`, with a detail naming the revocation's reason and date (and the keyservers that served it) or the expiry date; an algorithm the policy rejects is `INDETERMINATE [UNSUPPORTED_ALGORITHM]`; any other key the certificate does not bind — no self-signature, as keys.openpgp.org serves one without user IDs; a self-signature that does not verify; or one over a user ID that is not UTF-8, which Bouncy Castle's certificate API drops — is `INDETERMINATE [KEY_UNAVAILABLE]`, as GnuPG and Sequoia also report it ([ADR-009](../adr/009-an-unbound-key-is-never-failed.md))
7. A signature that is not correct is `FAILED` with the detail "the artifact does not match the signature"; one that cannot be parsed is `INDETERMINATE [EVIDENCE_MALFORMED]`; an exception is `INDETERMINATE [TOOL_UNAVAILABLE]`

The algorithm policy comes from `VerificationAlgorithms`, shared with the other backends: SHA-1 and RIPEMD-160 document signatures, SHA-1 and RIPEMD-160 self-signatures at any date, and RSA and DSA keys from 1024 bits, on top of Bouncy Castle's defaults. See [Accepted algorithms](verification.md#accepted-algorithms).

### sq Verification (v4 and v6 packets)

Sequoia implements RFC 9580, so it is routed v4 and v6 signatures, including RFC 9980 post-quantum ones; it does not implement LibrePGP's v5. The issuer fingerprint is extracted from the signature packet, used to look up the signer's certificate in the Sequoia cert store (`sq inspect --cert`), locate the cert file in cert-d, and verify with `sq verify --signer-file`. If the certificate is not in the store, the result is `INDETERMINATE [KEY_UNAVAILABLE]`. If `sq` is not available or the fingerprint cannot be extracted, it is `INDETERMINATE` citing `TOOL_UNAVAILABLE` or `UNSUPPORTED_ALGORITHM`.

`sq` runs with `SEQUOIA_CRYPTO_POLICY` pointing at a copy of the `sequoia-policy.toml` classpath resource that `VerificationAlgorithms` defines, replacing the host's system crypto policy. A non-zero exit is read from its report (`SqRunner.verdict`): a *bad signature* is `FAILED`; a *bad key* is `FAILED` when revoked or expired, `UNSUPPORTED_ALGORITHM` when the policy rejected it, and `KEY_UNAVAILABLE` otherwise; a report without that tally is `TOOL_UNAVAILABLE`.

### gpg Verification (v1-v4 packets)

Runs `gpg --status-fd 1 --verify` against the local keyring and reads the status lines (`GpgRunner.verdict`), never the exit code — GnuPG exits 0 for a good signature by a revoked key:
- **`GOODSIG`** — `VERIFIED`, also when GnuPG exits 2 for an unknown v6 packet in a hybrid `.asc`
- **`BADSIG`** or **`REVKEYSIG`** — `FAILED`
- **`EXPKEYSIG`** — `FAILED` when the `KEYEXPIRED` time is not after the signature's own time (from `VALIDSIG`), otherwise `VERIFIED`
- **`ERRSIG`** with **`NO_PUBKEY`** — `KEY_UNAVAILABLE`; GnuPG also answers this way for a certificate it refused to import, such as one without user IDs
- **`ERRSIG`** with return code 4 — `UNSUPPORTED_ALGORITHM`
- **none of these** — `TOOL_UNAVAILABLE`

GnuPG's defaults already accept the algorithms in `VerificationAlgorithms`. `KeyValidityAgreementTest` holds the three backends to the same answers.

The block's public-key algorithm ID is used to classify the signature as PQC or classical in the report. PQC algorithm IDs are 30-36 per the IANA OpenPGP Public Key Algorithms registry (RFC 9980).

### Verification Modes

- **Default:** Every signature in the file must be `VERIFIED` for the file to verify.
- **Lenient (`--lenient`):** At least one signature must be `VERIFIED` and none `FAILED`. Signatures left `INDETERMINATE` — a key not available, an algorithm no installed tool supports — are tolerated.

## Identity Verification Layer

Sigmund implements a two-layer architecture separating cryptographic verification (Layer 2) from identity-based trust assessment (Layer 1).

### Layer 2: Signature Operations

Layer 2 is the `SignatureTool` SPI, implemented by `BcRunner`, `SqRunner`, and `GpgRunner`, each
built by a `SignatureToolFactory` that also declares the settings it accepts under
`tools.<name>` (`acceptedSettings()`); `Sigmund.Builder` checks the configured tool names and
settings against the factories before building any tool. Each tool:

1. Declares capabilities via `supportedCredentialTypes()` (e.g., `["pgp4", "pgp6"]`)
2. Routes verification via `canVerify(Claim)` (packet version and algorithm)
3. Performs cryptographic verification → `VerifyResult` (outcome, reason, and metadata)
4. Extracts proven credentials via `extractCredentials(VerifyResult)` → `List<Credential>`

The credential type is determined by the packet version that was cryptographically verified:
- `version < 6` → `KeyCredential("pgp4", fingerprint)`
- `version >= 6` → `KeyCredential("pgp6", fingerprint)`

Only full fingerprints are proven — the verifying key's and, when it is a subkey, its primary
key's — and every OpenPGP backend proves the same ones.

### Layer 1: Identity Verification

Layer 1 is the `EvidenceProvider` interface, bridged from Layer 2 via `SignatureEvidenceAdapter`. The adapter:

1. Delegates `canHandle(Path)` to `SignatureFormat`
2. Parses signature files into `Claim`s
3. Routes each claim through `ClaimRouter`, which asks the tools in toolchain order, has a tool
   fetch a key it reports `KEY_UNAVAILABLE` for (if `resolve-signers` is enabled), and records a
   tool that throws as `INDETERMINATE [TOOL_UNAVAILABLE]` rather than letting it end the run
4. Receives a `ClaimResult` per claim: the outcome and the credentials the answering tool
   extracted, the evidence it was read from, the trust root it was checked against, the tool
   that checked it, when the claim was made, and the tool's own `VerifyResult` for format
   details such as an OpenPGP key ID

The `TrustVerifier` consumes `ClaimResult`s and produces one `ArtifactResult` per artifact:

1. **Collect claims** — each provider verifies the evidence resolved for the artifact; a file that yields no claim — one that cannot be read, or one holding no signature its format recognises, such as an empty `.asc` — is recorded on the result as `EvidenceWithoutClaims`, and the run goes on
2. **Match the rule** — `TrustPolicy.matchRule` selects the most specific `Rule`, recorded on the
   result as a `MatchedRule` (the pattern that matched and the rule's location)
3. **Roll up** — `OutcomeRollup` evaluates the rule's `Requirement` over the verified claims and
   derives the `ArtifactOutcome` in a fixed order: a failed claim dominates, claims no installed
   tool supports are set aside, no rule means `NOT_CONFIGURED`, requirements met means
   `SATISFIED`, and otherwise the most informative remaining state decides; evidence without
   claims counts as an unresolved claim with its reason, `EVIDENCE_UNREADABLE` or
   `EVIDENCE_MALFORMED`

Whether an outcome blocks is decided afterwards, by `VerificationReport.enforcement`, from the
matched rule's overrides, the policy defaults and the built-in defaults — so enforcement never
changes an outcome.

### Policy Model

The policy exists in two forms:

- **`TrustPolicySpec`** of `RuleSpec`s — what the parser produces: patterns, clauses as signer
  IDs, enforcement overrides and each rule's location. Only structure is checked. Signing reads
  the configuration in this form and never goes further, so a verification-only mistake cannot
  stop a release from being signed.
- **`RulePolicy`** of `Rule`s — produced by `RulePolicy.compile` when a verifier is built. It
  resolves signer IDs into `SignerIdentity`s and builds each rule's `Requirement` (a conjunction
  of `Clause`s, each a disjunction of signers), validates issuers and identity entries, and
  rejects rules that tie on specificity — any equal-specificity patterns of two rules sharing a
  coordinate.

`ArtifactPattern` holds a parsed pattern: its specificity, whether it matches a coordinate, and
whether two patterns overlap.

The roll-up lives in core rather than in an integration so that a goal and a resolver-level
extension cannot reach different outcomes from the same policy and the same evidence.

### Credential Types and Matching

`Credential` is sealed over two kinds, classified by who vouches for the fact
([ADR-006](../adr/006-identity-and-credential-model.md)):

- `KeyCredential(type, fingerprint)` — key material, proven by the signature itself
  - Type: `"pgp4"` or `"pgp6"`, by key version
  - Full fingerprints only, matched exactly; a 64-bit key ID is rejected
  - OpenPGP backends prove the verifying key and, when it is a subkey, its primary key
- `IdentityCredential(issuer, attributes)` — an identity asserted by an issuer
  - Proven by a Fulcio certificate (issuer = OIDC issuer; attributes = `subject`, `email`
    for an address SAN, and the Fulcio extensions) or by a directory that verifies addresses
    (issuer = `keys.openpgp.org`; attribute = `email`)
  - In policy the issuer is optional: an entry without one accepts the top-level `issuers`
  - Matches: the issuer is accepted, and every attribute the entry names is present with an
    equal value (`email` ignoring case)

`IssuerKind` classifies an issuer by name and holds the attributes each kind can assert;
`IdentityEntryValidator` rejects entries that none of their issuers can assert, suggesting the
nearest name for a misspelled attribute: every signer's when the policy compiles, and the
asserted signer's (`signing.signer`) when the parser loads the file, without compiling the policy.

An OpenPGP user ID never becomes a credential. `ClaimIdentityResolver` asks a directory for
the verified addresses of a signing key only when an expected signer has an email entry a
named directory can vouch for and none of its fingerprints already matched; a failed lookup
leaves the claim `INDETERMINATE` with `KEY_UNAVAILABLE`. The directory answers from its own copy
of the key when the fetcher got one this run and that copy holds the fingerprint asked about
(`KeysOpenPgpOrgDirectory.answerFrom`), and asks its VKS endpoint otherwise. The resolver also
tells each `ClaimResult` who vouches for its displayed identity (`displayNameVouchedBy`): a
directory listed in `issuers` whose fetched copy carried exactly the displayed user ID, or a
listed Sigstore OIDC issuer. It is display only — `labeledDisplayName` renders it as
`(address verified by …)`, `(attested by …)` or `(unverified)` — and never a credential.

Identity matching works via credential overlap: a claim satisfies a signer when one of the
credentials it proved matches one the signer is configured with.

A `Clause` accepts a claim when any of its signers has a credential matching one the claim
proved; a `Requirement` is satisfied when every clause accepts some claim. Identity
credentials without an issuer of their own match against the policy's listed issuers:
```java
for (SignerIdentity signer : signers) {
    for (Credential expected : signer.credentials()) {
        for (Credential proven : claim.attesterCredentials()) {
            if (matches(expected, proven, defaultIssuers)) {
                return true;
            }
        }
    }
}
```

`Requirement` implements `RequirementEvaluator`, the interface the roll-up consults. It is
separate from the roll-up on purpose: deriving an outcome needs to know whether requirements
were met and which claims met them, not what a requirement is.

The outcomes an artifact can get, and what each means, are in
[How Sigmund Works](how-it-works.md#outcomes) and
[Configuration](configuration.md#outcomes). `ArtifactOutcome` is the type that holds them.

## Cipher Suites

The key algorithms BC generates are listed with `tools.bc.cipher-suite` in
[Configuration](configuration.md#bc-bouncycastle); the post-quantum suites `sq` generates are
listed with `tools.sq` in [Configuration](configuration.md#sq-sequoia). Post-quantum algorithm IDs
are in [Known Limitations](limitations.md#pqc-algorithm-id-range).

## Project Structure

```
core/              Core signing and verification library (pure Java, no CLI dependencies)
cli/               Command-line interface (picocli)
maven-plugin/      Maven plugin for build integration
sigstore/          Sigstore signing/verification backend (dev.sigstore:sigstore-java)
sigmund-resolver-connector/
                   Maven 3.10+ extension verifying downloads and local-repository hits at resolution time (ADR-010), signing deploys (ADR-012)
```
