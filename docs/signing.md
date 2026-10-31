# Signing Guide

This guide covers artifact signing with Sigmund's backends: GPG (simplest, existing keys), Bouncy Castle (zero external dependencies), Sequoia sq (post-quantum hybrid signing), and Sigstore (OIDC keyless signing).

## Contents

- [Overview](#overview)
- [Checking the Signing Setup](#checking-the-signing-setup)
- [Signing with Existing GPG Keys](#signing-with-existing-gpg-keys)
- [Signing with Bouncy Castle](#signing-with-bouncy-castle)
  - [Key Generation](#key-generation)
  - [Passphrase Protection](#passphrase-protection)
  - [Passphrase Resolution Order](#passphrase-resolution-order)
- [Ephemeral CI Signing](#ephemeral-ci-signing)
- [Hybrid PQC Signing](#hybrid-pqc-signing)
  - [Prerequisites](#prerequisites)
  - [Installing Sequoia sq](#installing-sequoia-sq)
  - [Generating a PQC Key](#generating-a-pqc-key)
  - [Signing with PQC](#signing-with-pqc)
  - [sq with both keys](#sq-with-both-keys)
  - [Rotating a signing key](#rotating-a-signing-key)
  - [PQC Signature Sizes](#pqc-signature-sizes)
- [Signing with Sigstore](#signing-with-sigstore)
  - [OIDC Authentication](#oidc-authentication)
  - [CI Configuration (GitHub Actions)](#ci-configuration-github-actions)
  - [Sigstore Output Format](#sigstore-output-format)
- [Signing Credential Types and Profiles](#signing-credential-types-and-profiles)
- [Signing Pipeline](#signing-pipeline)
- [Backward Compatibility](#backward-compatibility)
- [Maven Central Compatibility](#maven-central-compatibility)

> **Note:** The examples in this guide use the `sigmund` plugin prefix (e.g., `mvn sigmund:sign`). This requires adding the plugin to your project's `pluginManagement`:
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
> `mvn dev.cyberstamp.sigmund:sigmund-maven-plugin:0.0.2:sign`

## Overview

Sigmund signs artifacts using one or more OpenPGP backends. The signing pipeline produces a detached `.asc` signature file. When multiple tools sign, their signatures are combined into a single `.asc` as separate armored blocks:

```
-----BEGIN PGP SIGNATURE-----
(classic signature — GPG or BC)
-----END PGP SIGNATURE-----
-----BEGIN PGP SIGNATURE-----
(PQC signature — Sequoia sq)
-----END PGP SIGNATURE-----
```

Existing tools (GPG, Maven Central) see only the first block and work as before. PQC-aware tools can verify all blocks.

## Checking the Signing Setup

Use `signer-info` to display the effective signing configuration — which tools are active, what keys they will use, and which credential types they produce — without signing anything.

**CLI:**

```bash
sigmund signer-info
```

**Maven:**

```bash
mvn sigmund:signer-info
```

Example output:

```
bc: pgp4 Ed25519 D62AAB339E45E5EA2FD036872B01D46A517A2991... (Alice <alice@example.com>)
sq: pgp6 ML-DSA-87+Ed448 A1B2C3D4E5F6... (Alice <alice@example.com>)
```

Each line shows the tool name, the credential type (`pgp4`, `pgp6`, or `type unknown`), the algorithm, the key fingerprint, and the user ID. A tool with several keys prints one line per key that will sign.

If the plan has problems, such as a requested credential type no key covers, the CLI prints `Problem: <message>` after the keys and exits 1, and the Maven goal fails with the same message. `sign` refuses the same plan.

**Options:**

| | CLI | Maven |
|---|---|---|
| Select profile | `--profile hybrid` | `-Dsigmund.profile=hybrid` |
| Explicit config | `--config path/to/sigmund.yaml` | `-Dsigmund.trustConfig=path/to/sigmund.yaml` |

When `--profile` is specified, only the keys whose credential type the profile lists are shown. Without it, the default profile is used (or all keys of all configured tools if no default profile is set).

This is useful for verifying your setup before a release, debugging CI signing configuration, or confirming that a config file is being loaded correctly.

## Signing with Existing GPG Keys

The simplest path if you already have GPG keys. If you have a single GPG secret key (or a `default-key` set in `gpg.conf`), no configuration is needed — Sigmund uses it automatically:

```bash
mvn sigmund:sign
```

```bash
sigmund sign --file artifact.jar
```

**Key resolution order:**

1. `signing-fingerprint` in `sigmund.yaml` (explicit override)
2. `default-key` in `gpg.conf` (`$GNUPGHOME/gpg.conf` or `~/.gnupg/gpg.conf`)
3. First secret key in the GPG keyring

A tool without `signing-fingerprint` signs with its one default key; when `gpg.conf` holds several `default-key` lines the last one signs, and without one the first secret key does.

To override the default, set `signing-fingerprint` in `sigmund.yaml` to the key's full
fingerprint (`gpg --list-secret-keys --with-colons`, the `fpr` line). A key ID or an email is
not accepted: it can match more than one key in the keyring. A primary key's fingerprint signs
with its signing subkey.

```yaml
tools:
  gpg:
    signing-fingerprint: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
```

`signing-fingerprint` also takes a list, and the tool signs once with each key. Under `gpg` every fingerprint must be a v4 key (40 hex characters), since GnuPG signs only with v4 keys.

```yaml
tools:
  gpg:
    signing-fingerprint:
      - "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
      - "9C1B7E2D4F6A8B0C3D5E7F9A1B2C4D6E8F0A1B3C"
```

## Signing with Bouncy Castle

The BC backend requires no external tools and works on any JVM.

### Key Generation

Generate a signing key using BC:

```bash
sigmund keygen \
  --userid "Your Name <you@example.com>" \
  --cipher-suite ed25519
```

Output:

```
BC key generated successfully!

Fingerprint: 4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12
Key is passphrase-protected (from SIGMUND_BC_PASSPHRASE).

Use this fingerprint with the 'sign' command.
```

**Supported cipher suites:**

Classic algorithms:

- `ed25519` — EdDSA with Ed25519 curve (default)
- `ed448` — EdDSA with Ed448 curve (v6 only, with `--credential-type pgp6`)
- `rsa4096` — RSA with 4096-bit modulus
- `nistp256` — ECDSA with P-256 curve
- `nistp384` — ECDSA with P-384 curve
- `nistp521` — ECDSA with P-521 curve

BC generates v4 keys by default: keys.openpgp.org serves only v4 keys, and GnuPG signs and verifies only v4. Pass `--credential-type pgp6` for a v6 key, for `ed25519`, `ed448` and `rsa4096`; the ECDSA suites (P-256, P-384, P-521) produce v4 keys only. A v4 Ed25519 key uses the legacy EdDSA encoding, the form GnuPG reads.

### Passphrase Protection

BC private keys can be encrypted at rest using AES-256 AEAD (OCB mode) with Argon2 S2K key derivation. This protects against filesystem-level exposure (stolen disk, backup leak, compromised server). It does not protect key material in memory — once decrypted for signing, the private key lives on the Java heap and cannot be pinned or zeroed by the JVM.

**Generating a passphrase-protected key:**

```bash
# Interactive — prompts for passphrase with confirmation
sigmund keygen \
  --userid "Alice <alice@example.com>" \
  --cipher-suite ed25519

# Non-interactive — reads from SIGMUND_BC_PASSPHRASE by default
SIGMUND_BC_PASSPHRASE=mysecret sigmund keygen \
  --userid "Alice <alice@example.com>"

# Non-interactive — custom env var
MY_PASSPHRASE=mysecret sigmund keygen \
  --userid "Alice <alice@example.com>" \
  --passphrase-env MY_PASSPHRASE
```

**Signing with a passphrase-protected key:**

Set the `SIGMUND_BC_PASSPHRASE` environment variable before signing:

```bash
export SIGMUND_BC_PASSPHRASE=mysecret
mvn sigmund:sign
```

If the environment variable is not set, Sigmund prompts interactively when a terminal is available. If neither is available, signing fails for encrypted keys.

To use a different environment variable name (e.g., to reuse an existing CI secret), set `passphrase-env` in `sigmund.yaml`:

```yaml
tools:
  bc:
    signing-fingerprint: "ABCDEF1234567890ABCDEF1234567890ABCDEF12"
    passphrase-env: MY_KEY_PASSPHRASE
```

### Passphrase Resolution Order

When signing with BC, the passphrase is resolved in this order:

1. **Programmatic `PassphraseProvider`** via `Sigmund.Builder.bcPassphraseProvider()` (API use only)
2. **Environment variable** — `SIGMUND_BC_PASSPHRASE` by default, or the variable named in the `passphrase-env` setting
3. **Interactive console prompt** — if a terminal is available
4. **No passphrase** — works only for unencrypted keys

Unencrypted keys continue to work without a passphrase. Private key files in `bc-private/` are created with owner-only (600) file permissions on POSIX systems.

## Ephemeral CI Signing

For ephemeral CI runners (containers, VMs that are destroyed after each build), you can inject the BC signing key directly from a CI secret — no key files on disk, no `keygen` step on the runner.

**One-time setup:** Export your signing key in ASCII-armored format and store it as a CI secret:

```bash
sigmund keygen --userid "CI <ci@example.com>"
# Copy the key file from ~/.local/share/sigmund/bc-private/<first 2 hex>/<rest of fingerprint>
# Or export with GPG: gpg --export-secret-keys --armor <fingerprint>
# Store the armored content as a CI secret named SIGMUND_BC_SIGNING_KEY
```

**On each CI run:** Set the environment variable and sign:

```bash
export SIGMUND_BC_SIGNING_KEY="$CI_SECRET"
export SIGMUND_BC_PASSPHRASE="$CI_PASSPHRASE"
mvn sigmund:sign
```

Sigmund checks `SIGMUND_BC_SIGNING_KEY` by default. The key is parsed in memory and never written to disk. No `sigmund.yaml` configuration is needed for this to work.

> **Important:** When `SIGMUND_BC_SIGNING_KEY` is set and no signing tools are configured in `sigmund.yaml`, BC claims **exclusive signing** — all other signing tools (GPG, sq) are automatically removed. This prevents CI runners with a pre-installed GPG and a default key from accidentally co-signing artifacts. When `sigmund.yaml` does configure signing tools, the env var acts only as a key provider for BC — it does not override the configured tool selection.

To use a different env var name, set `signing-key-env` in `sigmund.yaml`:

```yaml
tools:
  bc:
    signing-key-env: MY_SIGNING_KEY
```

**Priority:** `tsk-file` takes precedence over `signing-key-env` if both are configured.

## Hybrid PQC Signing

Hybrid signing combines a classic signature (GPG or BC) with a post-quantum signature (Sequoia sq) in one `.asc` file. This provides quantum resistance while maintaining backward compatibility.

### Prerequisites

**Sequoia sq 1.4.0+ with PQC support** is required for hybrid signing.

Verify your installation:

```bash
sq version
# Must show 1.4.0 or later

sq key generate --help | grep mldsa
# Must show mldsa87-ed448 in the cipher-suite options
```

### Installing Sequoia sq

**From crates.io (recommended):**

```bash
# 1. Install build dependencies

# Fedora / RHEL:
sudo dnf install \
  cargo rust gcc clang-devel openssl-devel sqlite-devel \
  pkg-config nettle-devel capnproto

# Debian / Ubuntu:
sudo apt install \
  cargo rustc gcc clang libssl-dev libsqlite3-dev \
  pkg-config libnettle-dev capnproto
```

Required packages and why:

- `openssl-devel` / `libssl-dev` — the build links against OpenSSL and needs `openssl.pc` for pkg-config
- `sqlite-devel` / `libsqlite3-dev` — required for the Sequoia keystore (`libsqlite3` linkage)
- `gcc` — the C compiler (`cc`) is needed to compile bundled C dependencies like `bzip2-sys`

```bash
# 2. Install sq 1.4.0 with PQC support
cargo install sequoia-sq@1.4.0 --features crypto-openssl --no-default-features
```

**Troubleshooting:**

- **`Disk quota exceeded` during build** — The build produces ~2 GB of intermediate artifacts. If `/tmp` has a quota, redirect the temp and target directories:
  ```bash
  mkdir -p ~/tmp-build
  TMPDIR=~/tmp-build CARGO_TARGET_DIR=~/cargo-sq-build \
    cargo install sequoia-sq@1.4.0 --features crypto-openssl --no-default-features
  ```
  Clean up after installation: `rm -rf ~/tmp-build ~/cargo-sq-build`

- **`Could not find directory of OpenSSL installation`** — Install `openssl-devel` (Fedora) or `libssl-dev` (Debian).

- **`cannot find -lsqlite3`** — Install `sqlite-devel` (Fedora) or `libsqlite3-dev` (Debian).

- **`cc failed with exit status 1`** — Check that `gcc` is installed (`which cc`).

**On RHEL 10.1+**, a PQC-enabled Sequoia package is available as a system package.

### Generating a PQC Key

Generate a PQC key using `sq`:

```bash
sq key generate \
  --userid "Your Name <you@example.com>" \
  --cipher-suite mldsa87-ed448 \
  --profile rfc9580 \
  --own-key \
  --without-password
```

The default cipher suite `mldsa87-ed448` is a hybrid composite of ML-DSA-87 (post-quantum) and Ed448 (classical). This provides quantum resistance while maintaining classical security. See `sq key generate --help` for the full set of options.

Output:

```
Key generated successfully!

Fingerprint: D62AAB339E45E5EA2FD036872B01D46A517A2991ABCDEF1234567890ABCDEF12
Stored in:   /home/user/.local/share/sequoia

Use this fingerprint with the 'sign' command.
```

### Signing with PQC

If you have a single key in your Sequoia store (or have set `sign.signer-self` in sq's config), no configuration is needed — Sigmund uses it automatically:

```bash
mvn sigmund:sign
```

```bash
sigmund sign --file artifact.jar
```

**Key resolution order:**

1. `signing-fingerprint` in `sigmund.yaml` (explicit override)
2. `sign.signer-self` in sq's config (`~/.config/sequoia/sq/config.toml`)

sq has no command to set a value in its configuration file. Edit the file, or write a commented template with `sq config template` and uncomment the setting:

```toml
[sign]
signer-self = ["YOUR_FINGERPRINT"]
```

`sq config get sign.signer-self` shows the effective value. When `sign.signer-self` lists several keys and `signing-fingerprint` is not set, Sigmund signs with the first only.

To override the default, set `signing-fingerprint` in `sigmund.yaml`:

```yaml
tools:
  sq:
    signing-fingerprint: "D62AAB339E45E5EA2FD036872B01D46A517A29911A2B3C4D5E6F7A8B9C0D1E2F"
```

This produces a hybrid `.asc` file containing both a classic signature (from GPG or BC) and a PQC signature (from sq).

### sq with both keys

One tool can sign with a v4 and a v6 key in one run. Generate both keys with `sq`:

```bash
sq key generate --own-key --without-password \
  --userid "Your Name <you@example.com>" \
  --profile rfc4880

sq key generate --own-key --without-password \
  --userid "Your Name <you@example.com>" \
  --cipher-suite mldsa87-ed448 --profile rfc9580
```

`--profile` is `rfc4880` (v4, the default) or `rfc9580` (v6). The `--cipher-suite` values are `rsa2k`, `rsa3k`, `rsa4k`, `cv25519` (the default), `mldsa65-ed25519` and `mldsa87-ed448`. List both fingerprints under `tools.sq.signing-fingerprint`; each key's type comes from its length, 40 hex characters for v4 and 64 for v6:

```yaml
tools:
  sq:
    signing-fingerprint:
      - "41A2197725BD63EB00D071D46A7F5DB1C68BDB81"
      - "D62AAB339E45E5EA2FD036872B01D46A517A29911A2B3C4D5E6F7A8B9C0D1E2F"

signing:
  toolchain: [sq]
  profiles:
    hybrid: [pgp4, pgp6]
```

`signer-info --profile hybrid` shows one line per key:

```
sq: pgp4 Ed25519 41A2197725BD63EB00D071D46A7F5DB1C68BDB81 (Your Name <you@example.com>)
sq: pgp6 ML-DSA-87+Ed448 D62AAB339E45E5EA2FD036872B01D46A517A29911A2B3C4D5E6F7A8B9C0D1E2F (Your Name <you@example.com>)
```

Both signatures go into the one `.asc`.

### Rotating a signing key

To move to a new key without a gap, list the old and the new fingerprint under the tool's `signing-fingerprint`; every artifact is then signed with both. When `signing.signer` is set, pin both keys under the signer, so each signature matches a credential the signer holds. Once consumers trust the new key, drop the old fingerprint from the list to end the overlap.

```yaml
tools:
  gpg:
    signing-fingerprint:
      - "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"   # old
      - "9C1B7E2D4F6A8B0C3D5E7F9A1B2C4D6E8F0A1B3C"   # new
```

### PQC Signature Sizes

With the default `mldsa87-ed448` cipher suite, the PQC signature adds approximately:

| Component | ML-DSA-87 (default) | ML-DSA-65 | Ed25519/Ed448 (comparison) |
|-----------|---------------------|-----------|----------------------------|
| Public key | ~2,592 bytes | ~1,952 bytes | 114 bytes (Ed448) / 64 bytes (Ed25519) |
| Private key | ~4,896 bytes | ~4,032 bytes | N/A |
| Signature | ~4,627 bytes | ~3,309 bytes | 114 bytes (Ed448) / 64 bytes (Ed25519) |

**Per artifact:** ~4.6 KB for ML-DSA-87, ~3.3 KB for ML-DSA-65

**Typical Maven module** (JAR, POM, sources, javadoc): ~18 KB for ML-DSA-87, ~13 KB for ML-DSA-65

## Signing with Sigstore

Sigstore provides keyless signing using short-lived certificates obtained via OIDC authentication. No long-lived keys to generate, store, or rotate. The `sigmund-sigstore` module uses `sigstore-java` and is pure Java — no external CLI binary required.

### Configuration

The default configuration is tuned for CI-based signing — only ambient OIDC providers (GitHub Actions) are used, and signing fails with a clear error if no ambient token is available. No browser window is opened.

Minimal `sigmund.yaml` for CI:

```yaml
signing:
  toolchain: [sigstore]
```

For desktop use, enable the browser-based OIDC login:

```yaml
tools:
  sigstore:
    interactive: true

signing:
  toolchain: [sigstore]
```

See the [configuration guide](configuration.md) for all Sigstore tool settings (`staging`, `trusted-root`, `interactive`).

### Maven Plugin Setup

Add `sigmund-sigstore` as a plugin dependency to enable the Sigstore backend:

```xml
<plugin>
  <groupId>dev.cyberstamp.sigmund</groupId>
  <artifactId>sigmund-maven-plugin</artifactId>
  <version>0.0.2</version>
  <dependencies>
    <dependency>
      <groupId>dev.cyberstamp.sigmund</groupId>
      <artifactId>sigmund-sigstore</artifactId>
      <version>${sigmund.version}</version>
    </dependency>
  </dependencies>
  <executions>
    <execution>
      <id>sign</id>
      <phase>verify</phase>
      <goals>
        <goal>sign</goal>
      </goals>
    </execution>
  </executions>
</plugin>
```

### CLI Usage

The CLI bundles Sigstore support — no extra dependency needed:

```bash
# Sign an artifact (produces artifact.jar.sigstore.json)
sigmund sign --file artifact.jar

# Verify a Sigstore bundle
sigmund verify-signature --file artifact.jar --signature artifact.jar.sigstore.json
```

When signing produces multiple files (e.g., both `.asc` and `.sigstore.json` with a hybrid toolchain), all output files are listed. The `--output` flag is only valid when a single signature file is produced.

### OIDC Authentication

Sigstore signing uses the OIDC keyless flow:

1. An ephemeral signing key pair is generated in memory
2. An OIDC identity token is obtained (ambient or interactive)
3. The token is exchanged for a short-lived Fulcio certificate binding the ephemeral key to the OIDC identity
4. The artifact is signed with the ephemeral key
5. The signature is recorded in the Rekor transparency log
6. A Sigstore bundle (`.sigstore.json`) is produced containing the signature, certificate, and log entry

**Ambient credentials (GitHub Actions):** When the workflow has `id-token: write` permission, GitHub Actions sets `ACTIONS_ID_TOKEN_REQUEST_TOKEN` and `ACTIONS_ID_TOKEN_REQUEST_URL` environment variables. sigstore-java's `GithubActionsOidcClient` detects these and obtains an OIDC token automatically — no Sigmund configuration needed. The resulting identity is the workflow URI (e.g., `https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0`), not a personal email. Without this permission, signing fails with a clear error.

**Environment variable token:** Set `SIGSTORE_JAVA_ID_TOKEN` to an OIDC identity token. This is tried before GitHub Actions ambient credentials and enables Sigstore signing on any CI system (GitLab CI, Jenkins, CircleCI, etc.) without the browser flow.

**Interactive credentials:** Require `interactive: true` in `sigmund.yaml`. Opens a browser for authentication via Google, GitHub, or Microsoft. The identity from the OIDC token (typically an email address) becomes the signer identity.

> **Identity validation timing:** When `signing.signer` names a signer, the OIDC token is checked before a Fulcio certificate is requested against every identity entry whose issuer is an OIDC issuer — an entry without its own `issuer` uses the top-level `issuers`: the token's issuer always, and its subject too when the entry names a `subject`. A token matching no entry is refused before Fulcio is asked. The other Sigstore credential fields (`source-repository-uri`, `build-trigger`, etc.) are Fulcio certificate extensions that don't exist in the OIDC token; they are checked on the issued certificate, together with the issuer and subject, before the signature is written, so a signature that does not prove the signer never reaches the output directory. Verification checks them again. For CI pipelines, `issuer` + `source-repository-uri` gives stable matching without needing to update the `subject` (which includes the git ref) on every release.

### CI Configuration (GitHub Actions)

Add `id-token: write` to the workflow permissions to enable ambient OIDC:

```yaml
permissions:
  id-token: write
  contents: read

steps:
  - uses: actions/checkout@v4
  - name: Build and sign artifacts
    run: mvn verify
```

The `sigmund:sign` goal is bound to the `verify` phase, so `mvn verify` builds the project and then signs all produced artifacts.

### Sigstore Output Format

Signing produces a `.sigstore.json` bundle for each artifact, containing:

- The artifact signature
- The short-lived Fulcio certificate
- The Rekor transparency log entry

Unlike OpenPGP `.asc` files, Sigstore bundles are self-contained — no keyserver lookup is needed for verification. The bundle format follows the [Sigstore Bundle specification](https://github.com/sigstore/protobuf-specs).

## Signing Credential Types and Profiles

Use `credential-types` to restrict which signature types are produced by default:

```yaml
signing:
  credential-types: [pgp4, pgp6]  # produce both v4 and v6 signatures
```

For scenarios that require named switching at invocation time, define profiles:

```yaml
signing:
  credential-types: [pgp4, pgp6]  # default
  profiles:
    classic:
      - pgp4
```

`credential-types` and profiles select keys, not tools. A tool signs with each of its keys whose type is requested, and a tool left with no such key does not sign. With `[pgp6]` requested, a tool holding a v4 and a v6 key signs with the v6 key alone.

A requested type that no key in the run covers fails before anything is signed, naming the keys that are in the run:

```
no signing key for requested credential type pgp6; keys in the run: bc pgp4, gpg pgp4
```

`signing.toolchain` names the tools that may sign, not ones that must: under a profile, a listed tool with no key of the profile's types simply does not sign. One toolchain can therefore serve several profiles — with `toolchain: [bc, sq]`, a v4 key in bc and a v6 key in sq, a `classic: [pgp4]` profile signs with bc and a `pqc: [pgp6]` profile with sq.

While types are requested, a key whose type cannot be read — an unparseable `tsk-file`, say — also fails before anything is signed, since Sigmund cannot tell whether it was meant to sign:

```
tool 'bc': the credential type of signing key key.tsk cannot be read, and the run requests credential types [pgp4]
```

Use `sigmund:signer-info` (Maven) or `sigmund signer-info` (CLI) to see which tools and keys are active:

```bash
mvn sigmund:signer-info
mvn sigmund:signer-info -Dsigmund.profile=classic
```

## Signing Pipeline

The signing pipeline combines signatures from multiple tools into a single `.asc` file:

```
artifact.jar
    |
    +-- Classic tool (BC or GPG)
    |   |
    |   +-- bc / gpg --detach-sign --> classic.asc
    |       (v4 or v6 signature packet)
    |
    +-- PQC tool (sq, if configured)
    |   |
    |   +-- sq sign --signature-file --> pqc.sig
    |       (v6 PQC signature packet)
    |
    +-- OpenPgpSignatureFormat.combine()
        |
        +-- artifact.jar.asc (combined signatures)
```

**Stage 1 — Classic signature:**

The signing tool (BC by default, or GPG if configured) produces a detached ASCII-armored signature. BC uses Bouncy Castle's `PGPSignatureGenerator` to create the signature in pure Java. GPG invokes the external `gpg` process:

```bash
gpg --batch --yes --armor --detach-sign \
  [--local-user <keyId>] \
  --output <sig> <artifact>
```

The signature version (v4 or v6) is determined by the key version. BC generates v6 signatures for v6 keys and v4 signatures for v4 keys. GPG always produces v4 signatures.

**Stage 2 — PQC signature (optional):**

If PQC signing is configured and `sq` is available, `SqRunner` invokes Sequoia `sq`:

```bash
sq --overwrite sign \
  --signer <fingerprint> \
  --signature-file <sig> <artifact>
```

Sequoia produces a detached ASCII-armored signature containing a v6 OpenPGP signature packet with the configured PQC hybrid cipher suite (ML-DSA-87+Ed448 by default) per RFC 9980.

**Stage 3 — Combine:**

`OpenPgpSignatureFormat` concatenates the signatures into a single `.asc` file as separate armored blocks, classic first. Neither signature is re-armored — each is preserved byte-for-byte as its respective tool produced it. Verifiers that parse only the first armored block (including Maven Central) see only the classic signature and succeed. PQC-aware tools process all blocks.

## Backward Compatibility

Standard GPG can verify hybrid `.asc` files — it reads the classic v4 packet and ignores the PQC v6 packet:

```bash
gpg --verify artifact.jar.asc artifact.jar
```

GPG will print a warning about the unknown v6 packet but still report "Good signature" and exit successfully:

```
gpg: packet(2) with unknown version 6
gpg: Signature made Wed 15 Apr 2026 10:44:00 AM CEST
gpg:                using RSA key 41A2197725BD63EB00D071D46A7F5DB1C68BDB81
gpg: Good signature from "Your Name <you@example.com>" [ultimate]
```

**Note:** GnuPG returns exit code 2 (rather than 0) when it encounters the v6 packet. Tools that strictly check exit codes may interpret this as a failure, but GPG itself reports the signature as valid.

## Maven Central Compatibility

Maven Central's upload validation parses the first armored block in the `.asc` file, verifies the classic signature against public keyservers, and ignores subsequent blocks. The PQC signature is silently skipped. No changes to Maven Central are required.

**Requirements for Maven Central:**

1. The first armored block must be a valid v4 signature (GPG-compatible)
2. The signing key must be available on a public keyserver (e.g., `hkps://keys.openpgp.org`)
3. The signature must be detached (separate `.asc` file, not inline)

Hybrid `.asc` files meet all these requirements — the classic signature is v4 and appears first.
