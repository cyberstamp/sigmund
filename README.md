# Sigmund — Hybrid PQC Signing for Maven Artifacts

## Overview

This tool adds post-quantum cryptographic (PQC) signatures to Maven artifacts alongside classic OpenPGP signatures. Each `.asc` signature file can contain any number of OpenPGP signature blocks. A typical hybrid file contains:

- A **classic v4 signature** (RSA/EdDSA) — backward-compatible, verifiable by all existing tools
- A **PQC v6 signature** (ML-DSA-87+Ed448 via Sequoia, default; configurable) — quantum-resistant, CNSA 2.0 compliant, per [RFC 9980](https://datatracker.ietf.org/doc/draft-ietf-openpgp-pqc/)

The signatures are stored as **separate armored blocks** in the same `.asc` file, classic first. Existing tools (GPG, Maven Central) see only the classic signature and work as before. PQC-aware tools can verify all blocks.

## Prerequisites

### Required

**JDK 17+**

Required for building and running.

```bash
java -version
```

**Maven 3.9+**

Required for building the project and using the Maven plugin.

```bash
mvn -version
```

### Optional External Tools

Sigmund includes a pure-Java Bouncy Castle backend that requires no external tools. GnuPG and Sequoia sq are optional and only needed for specific use cases:

**GnuPG** — required only if you want to sign with existing GPG keys or verify legacy GPG signatures that BC cannot handle.

```bash
# Check installation
gpg --version

# List your signing keys
gpg --list-secret-keys
```

If you don't have a GPG key and want to use GPG for signing, generate one:

```bash
gpg --full-generate-key
```

**Sequoia sq (PQC-enabled)** — required only for PQC hybrid signing (classic + PQC in one file).

**Version 1.4.0-pqc.1 or later is required.** The standard `sq` release (1.3.x) does not include PQC cipher suites. You need the PQC-enabled pre-release built from the `pqc` branch.

**Verify your installation supports PQC:**

```bash
sq version
# Must show 1.4.0-pqc.1 or later

sq key generate --help | grep mldsa
# Must show mldsa87-ed448 in the cipher-suite options
```

**Important:** If both a system `sq` (e.g., `/usr/bin/sq`) and the PQC-enabled `sq` (e.g., `~/.cargo/bin/sq`) are installed, make sure `~/.cargo/bin` comes first on your `PATH`:

```bash
export PATH=~/.cargo/bin:$PATH
```

#### Building Sequoia sq from source

The PQC-enabled `sequoia-openpgp` crate is not yet published on crates.io, so a simple `cargo install --git` does not resolve dependencies correctly. You must clone the repository and add a `[patch]` section to point Cargo at the PQC-enabled `sequoia-openpgp` from the main Sequoia repository:

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
# 2. Clone the PQC branch of sequoia-sq
git clone --branch pqc --depth 1 \
  https://gitlab.com/sequoia-pgp/sequoia-sq.git /tmp/sequoia-sq-pqc

# 3. Patch Cargo.toml to resolve PQC dependencies from the main Sequoia repo
cat >> /tmp/sequoia-sq-pqc/Cargo.toml << 'EOF'

[patch.crates-io]
sequoia-openpgp = { git = "https://gitlab.com/sequoia-pgp/sequoia.git", branch = "pqc" }
buffered-reader = { git = "https://gitlab.com/sequoia-pgp/sequoia.git", branch = "pqc" }
sequoia-autocrypt = { git = "https://gitlab.com/sequoia-pgp/sequoia.git", branch = "pqc" }
sequoia-net = { git = "https://gitlab.com/sequoia-pgp/sequoia.git", branch = "pqc" }
sequoia-ipc = { git = "https://gitlab.com/sequoia-pgp/sequoia.git", branch = "pqc" }
EOF

# 4. Build and install with OpenSSL backend
cd /tmp/sequoia-sq-pqc
cargo install --path . --features crypto-openssl --no-default-features
```

**Troubleshooting:**

- **`Disk quota exceeded` during build** — The build produces ~2 GB of intermediate artifacts. If `/tmp` has a quota, redirect the temp and target directories:
  ```bash
  mkdir -p ~/tmp-build
  TMPDIR=~/tmp-build CARGO_TARGET_DIR=~/cargo-sq-build \
    cargo install --path . --features crypto-openssl --no-default-features
  ```
  Clean up after installation: `rm -rf ~/tmp-build ~/cargo-sq-build`

- **`Could not find directory of OpenSSL installation`** — Install `openssl-devel` (Fedora) or `libssl-dev` (Debian).

- **`cannot find -lsqlite3`** — Install `sqlite-devel` (Fedora) or `libsqlite3-dev` (Debian).

- **`cc failed with exit status 1`** — Check that `gcc` is installed (`which cc`).

**On RHEL 10.1+**, a PQC-enabled Sequoia package may be available as a system package.

## Quick Start

### BC-only (zero dependencies, programmatic API)

Sign and verify using only the pure-Java Bouncy Castle backend — no external tools required.

```java
// Generate a v6 Ed25519 key
Sigmund sigmund = Sigmund.builder().build();
KeyGenerator keygen = sigmund.findTool(KeyGenerator.class, "bc");
String fingerprint = keygen.generateKey("You <you@example.com>", "ed25519");

// Sign an artifact (uses all available signing tools)
Signer signer = sigmund.signer();
SigningOutput output = signer.sign(artifactPath, outputDir);

// Verify a signature
SignatureVerificationReport report = sigmund.verify(artifactPath, signaturePath);
```

The BC tool is discovered automatically and takes priority over external tools. No `gpg` or `sq` installation needed.

### Build the project

```bash
mvn clean install -DskipTests
```

### Hybrid signing (classic GPG + PQC, CLI)

Combine a classic GPG signature with a PQC signature in one `.asc` file. Requires GnuPG and PQC-enabled Sequoia sq.

```bash
# 1. Generate a PQC key
java -jar cli/target/sigmund.jar keygen \
  --userid "Your Name <you@example.com>"
# Outputs: Generated key: D62AAB339E45E5EA2FD036872B01D46A517A2991...

# 2. Sign with hybrid classic+PQC
java -jar cli/target/sigmund.jar sign \
  --file target/my-artifact-1.0.jar \
  --pqc-fingerprint D62AAB339E45E5EA2FD036872B01D46A517A2991...

# 3. Verify all signatures
java -jar cli/target/sigmund.jar verify-signature \
  --file target/my-artifact-1.0.jar \
  --signature target/my-artifact-1.0.jar.asc
```

Output:

```
Signature Verification Report:
  [1] PASS (RSA) [key: 41A21977...]
  [2] PASS (ML-DSA-87+Ed448) [key: D62AAB33...]
  Overall: ALL_PASS
```

### Verify backward compatibility

Standard GPG can verify hybrid `.asc` files — it reads the classic v4 packet and ignores the PQC v6 packet:

```bash
gpg --verify target/my-artifact-1.0.jar.asc target/my-artifact-1.0.jar
```

GPG will print a warning about the unknown v6 packet but still report "Good signature" and exit successfully:

```
gpg: packet(2) with unknown version 6
gpg: Signature made Wed 15 Apr 2026 10:44:00 AM CEST
gpg:                using RSA key 41A2197725BD63EB00D071D46A7F5DB1C68BDB81
gpg: Good signature from "Your Name <you@example.com>" [ultimate]
```

## Architecture

### Three-Tool System

Sigmund supports three OpenPGP backends, each with distinct capabilities:

| Tool | Availability | v4 Support | v6 Support | PQC Support | Process Deps |
|------|--------------|------------|------------|-------------|--------------|
| **BC** | Always (pure Java) | Sign, verify | Sign, verify (classic algos) | Phase 2 planned | None |
| **sq** | Optional | Verify | Sign, verify | Sign, verify (RFC 9980) | Sequoia CLI |
| **gpg** | Optional | Sign, verify | None | None | GnuPG CLI |

**BC (Bouncy Castle)** is the default first-choice tool. It requires no external process dependencies and works on any JVM. BC generates v6 keys for Ed25519, Ed448, and RSA using Bouncy Castle 1.85's `BcOpenPGPApi`. ECDSA keys (P-256, P-384, P-521) use a JCA-based fallback and produce v4 keys.

**sq (Sequoia)** is used for PQC hybrid signing when available. The PQC-enabled version (1.4.0-pqc.1+) implements RFC 9980 and can generate and verify ML-DSA composite signatures.

**gpg (GnuPG)** provides compatibility with existing GPG-based workflows and reads GPG keyrings. GnuPG follows LibrePGP and does not support v6 keys.

### Tool Priority

Verification units are routed to tools based on a configurable priority list. The default priority is:

```
[bc, sq, gpg]
```

BC attempts verification first. If BC cannot verify a signature (e.g., missing key or unsupported algorithm), the next tool in the priority list is tried. This ensures maximum use of the zero-dependency backend while maintaining compatibility with external tools when needed.

Configure priority in `sigmund.yaml`:

```yaml
discovery:
  tool-priority: [bc, sq, gpg]
```

### OpenPGP Key Structure

**EdDSA keys** (Ed25519, Ed448) have a three-key structure:
- **Primary key** — Certify-only, signs subkeys
- **Encryption subkey** — X25519 or X448, used for encryption
- **Signing subkey** — Ed25519 or Ed448, used for signatures

**RSA keys** are singleton keys with all flags (certify + sign + encrypt) on the primary key.

**ECDSA keys** (P-256, P-384, P-521) generated by BC use a singleton structure similar to RSA.

Key flags determine which key in the ring is used for each operation. Sigmund's signing flow prefers subkeys over the primary key, selecting the first signing-capable subkey if one exists, otherwise falling back to the primary key if it has the sign flag.

### Key Management

**BC key store** manages keys across three sources, searched in order:

1. **GnuPG pubring** (`~/.gnupg/pubring.gpg`) — read-only. BC can read public keys from GnuPG's keyring for verification.

2. **Shared cert-d** (`~/.local/share/openpgp-cert-d/`) — read/write for public certificates. Uses the standard OpenPGP cert-d two-level directory layout (fingerprint `ABCDEF...` is stored at `AB/CDEF...`). Public certificates written here are visible to `sq` and other tools that support cert-d.

3. **BC private store** (`~/.local/share/openpgp-cert-d/bc-private/`) — read/write for private keys. BC-generated private keys are stored in standard OpenPGP transferable secret key format in a subdirectory under cert-d.

**Sequoia keystore** is managed by `sq` and controlled by the `SEQUOIA_HOME` environment variable (defaults to `~/.local/share/sequoia`). Keys generated with `sq key generate` are stored here and used for signing with the `sq` tool.

**GnuPG keyring** is the standard GnuPG keyring at `~/.gnupg/`. Keys managed by `gpg` are stored here.

### Interoperability Matrix

| From → To | BC | sq | gpg |
|-----------|----|----|-----|
| **BC v6 keys** | Yes | Yes | No (v6 not supported) |
| **BC v4 keys** | Yes | Yes | Yes |
| **sq v6 classic** | Yes | Yes | No |
| **sq v6 PQC** | Phase 2 | Yes | No |
| **gpg v4** | Yes | Yes | Yes |

**BC → sq interop** works for v6 keys because both support RFC 9580 (OpenPGP v6). BC-generated public certs are written to the shared cert-d so `sq` can see them.

**BC → gpg interop** works only for v4 keys. BC can read GPG's `pubring.gpg` for verification. BC v6 keys cannot be imported into GPG because GPG follows LibrePGP and does not support v6.

**sq → BC interop** works for v6 classic algorithm signatures (Ed25519, Ed448, RSA). PQC signatures (algorithm IDs 30-36) cannot be parsed by BC yet (Phase 2).

## Configuration

Sigmund configuration uses a `sigmund.yaml` file with four main sections: `signing`, `discovery`, `trust`, and `signers`.

### Signing Configuration

The `signing` section configures which identity to sign as and which tools to use.

```yaml
signing:
  signer: my-identity
  tools:
    bc:
      signing-fingerprint: "ABCDEF1234567890ABCDEF1234567890ABCDEF12"
      cipher-suite: ed448
    sq:
      home: ~/.local/share/sequoia
    gpg:
      key: 0x12345678
  profiles:
    classic:
      - openpgp4
    v6-only:
      - openpgp6
    hybrid:
      - openpgp4
      - openpgp6
  default-profile: hybrid
```

**BC tool settings:**

| Setting | Default | Description |
|---------|---------|-------------|
| `gnupg-home` | `~/.gnupg` | GnuPG home for reading `pubring.gpg` |
| `cert-d-home` | `~/.local/share/openpgp-cert-d` | Shared cert-d directory |
| `bc-private-home` | `<cert-d-home>/bc-private` | BC private key store |
| `signing-fingerprint` | — | Fingerprint of key to sign with |
| `tsk-file` | — | Path to exported TSK file for signing |
| `cipher-suite` | `ed25519` | Default algorithm for key generation |

**Supported cipher suites (BC):**

Classic algorithms (Phase 1):
- `ed25519` — EdDSA with Ed25519 curve (default)
- `ed448` — EdDSA with Ed448 curve
- `rsa4096` — RSA with 4096-bit modulus
- `nistp256` — ECDSA with P-256 curve
- `nistp384` — ECDSA with P-384 curve
- `nistp521` — ECDSA with P-521 curve

PQC composite (Phase 2, in development):
- `mldsa87-ed448` — ML-DSA-87 + Ed448 hybrid
- `mldsa65-ed25519` — ML-DSA-65 + Ed25519 hybrid

### Discovery Configuration

The `discovery` section controls tool priority, keyserver access, and per-tool verification settings.

```yaml
discovery:
  tool-priority: [bc, sq, gpg]
  fetch-signer-info: true
  import-to-keyring: false
  keyservers:
    - hkps://keys.openpgp.org
  tools:
    bc:
      gnupg-home: /custom/gnupg
      cert-d-home: /custom/cert-d
```

**Discovery settings:**

| Setting | Default | Description |
|---------|---------|-------------|
| `tool-priority` | `[bc, sq, gpg]` | Tools to use and their order. When set, only listed tools are used. When omitted, all available tools are initialized in the default order. |
| `fetch-signer-info` | `true` | Fetch missing keys from keyservers during verification |
| `import-to-keyring` | `false` | Persist fetched keys into tool keyrings. When `false` (default), BC caches keys in memory for the session without writing to disk. GPG cannot do ephemeral imports, so key fetch is skipped entirely — use `true` if GPG is the primary tool and you want key auto-fetch. Note: `keys.openpgp.org` may serve keys without user IDs; BC can use these for verification, but GPG cannot import them. |
| `keyservers` | `hkps://keys.openpgp.org` | Keyserver URLs for key discovery |

### Trust Configuration

The `trust` section maps artifact patterns to trusted signers. See the [Maven Plugin](#maven-plugin) section for details.

## How It Works

### Signing Pipeline

```
artifact.jar
    |
    +-- bc / gpg --detach-sign --> classic.asc  (v4 or v6 signature packet)
    |
    +-- sq sign --signature-file --> pqc.sig    (v6 PQC signature packet)
    |
    +-- OpenPgpSignatureFormat.combine() -> artifact.jar.asc
```

**Stage 1 — Classic signature.** The signing tool (BC by default, or GPG if configured) produces a detached ASCII-armored signature. BC uses Bouncy Castle's `PGPSignatureGenerator` to create the signature in pure Java. GPG invokes the external `gpg` process:

```
gpg --batch --yes --armor --detach-sign [--local-user <keyId>] --output <sig> <artifact>
```

The signature version (v4 or v6) is determined by the key version. BC generates v6 signatures for v6 keys and v4 signatures for v4 keys. GPG always produces v4 signatures.

**Stage 2 — PQC signature (optional).** If PQC signing is configured and `sq` is available, `SqRunner` invokes Sequoia `sq` as an external process:

```
sq --overwrite sign --signer <fingerprint> --signature-file <sig> <artifact>
```

Sequoia produces a detached ASCII-armored signature containing a v6 OpenPGP signature packet with the configured PQC hybrid cipher suite (ML-DSA-87+Ed448 by default) per RFC 9980. The `--overwrite` flag is always passed to handle cases where the output file already exists.

**Stage 3 — Combine.** `OpenPgpSignatureFormat` concatenates the signatures into a single `.asc` file as separate armored blocks, classic first:

```
-----BEGIN PGP SIGNATURE-----
(classic signature — exactly as the tool produced it)
-----END PGP SIGNATURE-----
-----BEGIN PGP SIGNATURE-----
(PQC signature — exactly as Sequoia produced it)
-----END PGP SIGNATURE-----
```

Neither signature is re-armored — each is preserved byte-for-byte as its respective tool produced it. Verifiers that parse only the first armored block (including Maven Central) see only the classic signature and succeed. PQC-aware tools process all blocks.

### Verification Pipeline

```
artifact.jar + artifact.jar.asc
    |
    +-- extract all armored blocks
    |
    +-- for each block:
    |     route to tool based on priority and canVerify()
    |     bc / sq / gpg verify --> VerifyResult (PASS/FAIL/NO_KEY/SKIPPED)
    |
    +-- SignatureVerificationReport (all results)
```

Each armored block is parsed into a `VerificationUnit` and routed to the first available tool in the priority list that can handle it (via `canVerify()`).

**BC verification.** BC handles any `OpenPgpVerificationUnit` (v4 or v6 classic algorithms). Verification steps:

1. Extract issuer fingerprint from the signature packet's Issuer Fingerprint subpacket (type 33)
2. Search for the signer's public key in GnuPG pubring, cert-d, or BC private store
3. If key not found, return `NO_KEY`
4. Parse the signature packet using Bouncy Castle's `BcPGPObjectFactory`
5. Verify the signature against the artifact using BC's `PGPSignature.verify()`
6. Return `PASS` or `FAIL`

**sq verification (v5+ packets).** The issuer fingerprint is extracted from the signature packet, used to look up the signer's certificate in the Sequoia cert store (`sq inspect --cert`), locate the cert file in cert-d, and verify with `sq verify --signer-file`. If the certificate is not in the store, the result is `NO_KEY`. If `sq` is not available or the fingerprint cannot be extracted, the result is `SKIPPED`.

**gpg verification (v1-v4 packets).** Runs `gpg --verify` against the local keyring. GPG exit codes are interpreted as:
- **Exit 0** — signature valid (`PASS`)
- **Exit 2 with "Good signature" in stderr** — signature valid but GPG encountered an unknown packet (`PASS`). This is the expected result for hybrid `.asc` files containing v6 PQC packets.
- **Exit 1** — bad signature (`FAIL`)
- **stderr contains "No public key"** — signer's key not in keyring (`NO_KEY`)

The block's public-key algorithm ID is used to classify the signature as PQC or classical in the report. PQC algorithm IDs are 30-36 per the IANA OpenPGP Public Key Algorithms registry (RFC 9980).

**Verification modes:**

- **Default:** Every signature in the file must pass for the overall result to be `PASS`.
- **Lenient (`--lenient`):** At least one signature must pass and none may fail. Skipped or no-key signatures are tolerated.

## CLI Reference

### `sigmund keygen`

Generate a PQC hybrid keypair using Sequoia sq.

```
sigmund keygen --userid <USER_ID> [--cipher-suite <SUITE>] [--sq-home <DIR>]
```

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--userid` | Yes | — | User ID in canonical form (e.g., `"Alice <alice@example.com>"`) |
| `--cipher-suite` | No | `mldsa87-ed448` | PQC cipher suite (e.g., `mldsa65-ed25519` for ML-DSA-65) |
| `--sq-home` | No | `~/.local/share/sequoia` | Sequoia keystore directory |

Note: the user ID must be in canonical form (`Name <email>`). Bare email addresses are not accepted by `sq`.

### `sigmund sign`

Create a hybrid signature (classic GPG + PQC).

```
sigmund sign --file <FILE> --pqc-fingerprint <FP> [options]
```

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--file` | Yes | — | Artifact file to sign |
| `--pqc-fingerprint` | Yes | — | PQC key fingerprint (from keygen) |
| `--gpg-key` | No | GPG default | GPG key ID for classic signing |
| `--sq-home` | No | `~/.local/share/sequoia` | Sequoia keystore directory |
| `--output` | No | `<file>.asc` | Output signature file path |

### `sigmund verify-signature`

Verify a signature using all available tools according to tool priority.

```
sigmund verify-signature --file <FILE> --signature <ASC> [options]
```

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--file` | Yes | — | Artifact file to verify |
| `--signature` | Yes | — | Signature `.asc` file |
| `--sq-home` | No | `~/.local/share/sequoia` | Sequoia keystore directory |
| `--lenient` | No | `false` | Pass if at least one signature is valid and none failed |

### `sigmund export-cert`

Export a PQC public certificate for distribution.

```
sigmund export-cert --fingerprint <FP> [options]
```

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--fingerprint` | Yes | — | PQC key fingerprint to export |
| `--sq-home` | No | `~/.local/share/sequoia` | Sequoia keystore directory |
| `--output`, `-o` | No | stdout | Output file path |

## Maven Plugin

### Configuration

Add to your project's `pom.xml`:

```xml
<plugin>
  <groupId>io.github.cyberstamp.sigmund</groupId>
  <artifactId>sigmund-maven-plugin</artifactId>
  <version>0.0.1-SNAPSHOT</version>
  <executions>
    <execution>
      <goals><goal>sign</goal></goals>
    </execution>
  </executions>
  <configuration>
    <pqcFingerprint>${sigmund.fingerprint}</pqcFingerprint>
    <!-- optional: <gpgKeyName>0xABCD1234</gpgKeyName> -->
  </configuration>
</plugin>
```

**Using an environment variable.** If you stored the fingerprint in `PQC_FINGERPRINT`, reference it directly in the plugin configuration:

```xml
<configuration>
  <pqcFingerprint>${env.PQC_FINGERPRINT}</pqcFingerprint>
</configuration>
```

This way `mvn verify` picks up the fingerprint automatically — no `-D` flag needed.

### `sigmund:sign`

Bound to the `verify` phase. Signs all project artifacts (JAR, POM, sources, javadoc) with classic GPG and PQC, and attaches the `.asc` files for deployment. The `pqcFingerprint` parameter is required — the build will fail if it is not configured.

```bash
mvn verify -Dsigmund.fingerprint=<FINGERPRINT>
```

| Property | Required | Default | Description |
|----------|----------|---------|-------------|
| `sigmund.fingerprint` | Yes | — | PQC key fingerprint (from keygen) |
| `gpg.keyname` | No | GPG default | GPG key ID or email for classic signing |
| `sigmund.sqHome` | No | `~/.local/share/sequoia` | Sequoia keystore directory |

### `sigmund:verify-signature`

Verify a single signed artifact (standalone, no project required):

```bash
mvn sigmund:verify-signature \
  -Dfile=artifact.jar \
  -Dsignature=artifact.jar.asc
```

| Property | Required | Default | Description |
|----------|----------|---------|-------------|
| `file` | Yes | — | Artifact file to verify |
| `signature` | Yes | — | Signature `.asc` file |
| `sigmund.sqHome` | No | `~/.local/share/sequoia` | Sequoia keystore directory |
| `sigmund.lenient` | No | `false` | Pass if at least one signature is valid and none failed |

### `sigmund:verify`

Verifies that all project dependencies are signed by trusted signers as defined in a `trust-config.yaml` file. Matching is done by GPG/PQC fingerprint when available, falling back to signer user ID. Artifacts listed in the `unsigned` section are skipped.

```bash
mvn sigmund:verify
```

The goal looks for `trust-config.yaml` in the project root by default. The config file uses YAML and has five sections:

```yaml
settings:
  keyservers:
    - hkps://keys.openpgp.org
  on-untrusted: fail
  verify-all-signatures: true
  fetch-signer-info: true

signers:
  # Full form: organization with multiple members
  apache:
    name: "Apache Software Foundation"
    members:
      - pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
        email: "dev@maven.apache.org"
      - pgp4: "BBE7232D7991050B54C8EA0ADC08637CA615D22C"

  # Short form: single-key signer
  jane:
    pgp4: "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
    email: "jane@example.com"

  # Minimal form: email only
  jackson-dev: "tatu@fasterxml.com"

artifacts:
  apache-stack:
    - org.apache.maven.*
    - org.apache.commons.*

trust:
  apache-stack: apache
  quarkus-stack: [redhat, jboss-community]
  com.fasterxml.jackson.*: jackson-dev
  com.example:lib: jane

unsigned:
  - com.internal.*
```

**Signers** define trusted identities in three forms: full (organization with multiple members), short (single key), or minimal (email string only). Each member can specify a PGP4 fingerprint (`pgp4`), PGP6 fingerprint (`pgp6`), and/or email address (`email`). Fingerprints are matched first; email is used as a fallback.

**Artifacts** define named groups of coordinate patterns, referenced by name in `trust`.

**Trust** maps artifact patterns or artifact group names to signer references. If a key matches a name in `artifacts`, it is expanded; otherwise it is treated as a Maven coordinate pattern. Patterns support: `groupId`, `groupId:artifactId`, `groupId:artifactId:version`, or `groupId:artifactId:type:classifier:version`. Wildcards (`*`) and group prefixes (`org.apache.*`) are supported. When multiple patterns match, the most specific wins.

**Keyservers** default to `hkps://keys.openpgp.org` because it is the only major keyserver that verifies email addresses before publishing, preventing impersonation via unverified key uploads. Other keyservers (e.g. `keyserver.ubuntu.com`) accept uploads without identity verification and can be added explicitly if needed.

**Unsigned** lists artifact patterns for which no signature is expected.

**Generating the config.** Use `dependency-signers` with `-Dsigmund.generateTrustConfig=true` to generate an initial `trust-config.yaml` from your project's actual dependency signatures.

**Updating the config.** Use `dependency-signers` with `-Dsigmund.updateTrustConfig=true` to append any newly added dependencies to an existing config.

Example output:

```
Signer: Jane Doe <jane@example.com>
   PGP4 (RSA): DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF
     com.example:lib:1.0

UNTRUSTED
  Signer: Unknown <unknown@example.com> (not trusted)
     PGP4: DEADBEEFDEADBEEF
       com.other:tool:3.0

  UNSIGNED
       org.wildfly.common:wildfly-common:2.0.1

TRUSTED UNSIGNED
     com.internal:util:1.0

Summary: 1 passed, 2 failed
```

| Property | Required | Default | Description |
|----------|----------|---------|-------------|
| `sigmund.trustConfig` | No | `${project.basedir}/trust-config.yaml` | Path to the trust configuration file |
| `sigmund.onUntrusted` | No | — | Policy for untrusted artifacts: `fail` or `warn`. Overrides the config file setting. |
| `sigmund.verifyAllSignatures` | No | — | When `true`, unverified signatures on trusted artifacts are reported. Overrides the config file setting. |
| `sigmund.fetchSignerInfo` | No | `false` | Fetch unknown GPG keys from keyservers. Overrides the config file setting. |
| `sigmund.keyservers` | No | `hkps://keys.openpgp.org` | Comma-separated keyserver list. Used when `fetchSignerInfo` is enabled. |
| `sigmund.verifyPomFiles` | No | `false` | Also verify signatures on POM files for each dependency |
| `sigmund.skip` | No | `false` | Skip verification |
| `sigmund.sqHome` | No | `~/.local/share/sequoia` | Sequoia keystore directory |
| `sigmund.includeTestDependencies` | No | `false` | Include test-scoped dependencies |

### `sigmund:dependency-signers`

Reports signer information for all project dependencies by downloading and inspecting their `.asc` signature files. Each armored block is reported separately with its OpenPGP version (v4 for classical GPG, v6 for PQC). Classical signatures are verified via GPG or BC; PQC signatures are verified via Sequoia when the signer's certificate is available in the local cert store.

Dependencies are grouped by signer, sorted alphabetically. Each signer block shows the signature type (GPG/PQC) and key ID, followed by the artifacts signed by that signer. Unsigned artifacts and unverified signatures are reported separately.

```bash
# Report signers
mvn sigmund:dependency-signers

# Generate trust-config.yaml from actual signatures
mvn sigmund:dependency-signers -Dsigmund.generateTrustConfig=true -Dsigmund.fetchSignerInfo=true

# Update an existing trust-config.yaml with newly added dependencies
mvn sigmund:dependency-signers -Dsigmund.updateTrustConfig=true -Dsigmund.fetchSignerInfo=true
```

**Generating a trust config.** Use `-Dsigmund.generateTrustConfig=true` to create an initial `trust-config.yaml` from your project's actual dependency signatures. The generated file groups artifacts by signer, collapses common groupId prefixes into wildcard patterns (e.g., `io.quarkus.*`), and lists unsigned artifacts in the `unsigned` section. The file can be used directly with the `verify` goal.

**Updating a trust config.** Use `-Dsigmund.updateTrustConfig=true` to add new dependency signers to an existing `trust-config.yaml`. This is useful after adding new dependencies — existing content including comments and formatting is preserved, and new entries are inserted at the end of each section. Review the changes with `git diff`.

Example output:

```
Signer: Alice <alice@example.com>
   PGP4 (RSA): 4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12
   PGP6 (ML-DSA-65+Ed25519): D62AAB339E45E5EA2FD036872B01D46A517A2991...
     com.example:lib-a:1.0
     com.example:lib-b:2.0

Signer: UNKNOWN (key not in keyring)
   PGP4 (RSA): DEADBEEFDEADBEEFDEADBEEF
     com.other:tool:3.0

UNSIGNED
  com.internal:util:1.0

Summary: All clear: 4 dependencies, 3 GPG signature(s), 1 PQC signature(s), 2 unique key(s)
```

| Property | Required | Default | Description |
|----------|----------|---------|-------------|
| `sigmund.skip` | No | `false` | Skip the report |
| `sigmund.fetchSignerInfo` | No | `false` | Fetch unknown GPG keys from keyservers to resolve signer identities |
| `sigmund.keyservers` | No | `hkps://keys.openpgp.org` | Comma-separated list of keyservers for fetching GPG keys |
| `sigmund.sqHome` | No | `~/.local/share/sequoia` | Sequoia keystore directory for PQC cert lookup |
| `sigmund.includeTestDependencies` | No | `false` | Include test-scoped dependencies |
| `sigmund.generateTrustConfig` | No | — | Generate a `trust-config.yaml`. Set to `true` to write to the project root, or provide a file path. Fails if the file already exists unless `sigmund.overwrite=true`. |
| `sigmund.overwrite` | No | `false` | Allow overwriting an existing generated trust config file |
| `sigmund.updateTrustConfig` | No | — | Update an existing `trust-config.yaml` by appending unconfigured signers and artifacts. Set to `true` for the default location, or provide a file path. |

## Testing

### Unit Tests

Unit tests run without any external tools (no GPG or sq required):

```bash
mvn test
```

The BC backend is always available and does not require external tool installation.

### Integration Tests

Integration tests require both GnuPG and PQC-enabled Sequoia sq installed. They are automatically skipped if either tool is unavailable or if `sq` does not support the default PQC cipher suite (`mldsa87-ed448`).

Make sure the PQC-enabled `sq` is first on your PATH:

```bash
export PATH=~/.cargo/bin:$PATH
mvn test -pl core -Dtest=RoundTripIntegrationTest
```

The integration tests cover full round-trip signing and verification, GPG backward compatibility (verifying that `gpg --verify` succeeds on hybrid `.asc` files despite the unknown v6 PQC packet), and tamper detection.

### Maven Plugin Integration Tests

The Maven plugin includes invoker tests under `maven-plugin/src/it/` covering dependency signer reporting, trust config generation and update, and end-to-end sign-verify round trips (the latter requires GPG + PQC-enabled sq).

## Known Limitations

### BC v6 keys incompatible with GPG

BC-generated v6 keys (Ed25519, Ed448, RSA) cannot be imported into GnuPG. GnuPG follows LibrePGP and does not support OpenPGP v6. BC v4 keys (ECDSA) work with GPG.

### BC ECDSA keys are v4, not v6

BC generates v4 keys for ECDSA (P-256, P-384, P-521) via JCA-based fallback. Bouncy Castle 1.85's `BcOpenPGPApi` does not provide ECDSA key generation, so a JCA-based implementation is used instead, which produces v4 keys.

### PQC signature parsing by BC (Phase 2)

BC cannot parse PQC composite signatures (algorithm IDs 30-36) in Phase 1. Support for ML-DSA-87+Ed448 and ML-DSA-65+Ed25519 will be added first in Phase 2 via custom RFC 9980 packet handling on top of Bouncy Castle's raw ML-DSA primitives.

### GPG ephemeral key fetch not supported

When `import-to-keyring` is `false` (default), GPG cannot fetch keys ephemerally — key fetch is skipped entirely, and verification returns `NO_KEY`. BC handles this case by caching fetched keys in memory. GPG could support ephemeral fetch using `--no-default-keyring --keyring <tmpfile>` for both `--recv-keys` and `--verify`, but this is not yet implemented.

### GPG exit code 2 for hybrid `.asc` files

GnuPG returns exit code 2 (rather than 0) when verifying an `.asc` file that contains a v6 PQC packet. GPG processes all armored blocks in the file and warns about the unknown packet version. The signature itself is valid — GPG reports "Good signature" in its output.

`GpgRunner` handles this by checking for "Good signature" in stderr when the exit code is 2. However, other tools or CI systems that check GPG's exit code strictly may interpret exit code 2 as a failure.

### PQC key passphrase protection

The PoC generates PQC keys with `--without-password` to support non-interactive use (CI/CD, tests, headless environments). In a production deployment, keys should be passphrase-protected. This requires either a TTY for interactive passphrase entry or a password file passed via `--new-password-file`.

### Sequoia sq is pre-release

The PQC-enabled Sequoia (`sq 1.4.0-pqc.1`) is a pre-release. The underlying [RFC 9980](https://datatracker.ietf.org/doc/draft-ietf-openpgp-pqc/) (Post-Quantum Cryptography in OpenPGP) has been approved by the IESG as a Proposed Standard and is in AUTH48 (final author review at the RFC Editor). When stable Sequoia releases include PQC, the only change needed in this tool is updating the `sq` binary.

The Sequoia PGP team [plans to release stable PQC support](https://sequoia-pgp.org/blog/2025/11/15/202511-post-quantum-cryptography/) shortly after the RFC is published. RHEL 10.1 has already shipped Sequoia with PQC support enabled as a system package.

### PQC algorithm ID range

The verifier classifies v5+ signature packets as PQC based on the public-key algorithm ID in the IANA OpenPGP Public Key Algorithms registry. As of RFC 9980, PQC algorithm IDs are 30-36 (ML-DSA, SLH-DSA, ML-KEM composites). This range is hardcoded in `Algorithms.isPqcAlgorithm()` and will need updating if IANA registers additional PQC algorithms beyond this range.

### `sequoia-openpgp` PQC crate not on crates.io

The PQC-enabled `sequoia-openpgp` (version `2.2.0-pqc.1`) is not published on crates.io. Building `sq` from source requires a `[patch.crates-io]` section in `Cargo.toml` to redirect dependency resolution to the PQC branch of the main Sequoia repository. This is expected to be resolved once the PQC support is merged into mainline Sequoia.

## Maven Central Compatibility

The `.asc` file starts with a standard armored block containing only the classic v4 signature. Maven Central's upload validation parses the first armored block, verifies the classic signature against public keyservers, and ignores the second block (the PQC signature). No changes to Maven Central are required.

## Project Structure

```
core/                                    Core signing and verification library
cli/                                     CLI tools (picocli)
maven-plugin/                            Maven plugin (sign, verify, verify-signature, dependency-signers goals)
```

## PQC Signature Sizes

| Component | ML-DSA-87 (default) | ML-DSA-65 |
|-----------|---------------------|-----------|
| Public key | ~2,592 bytes | ~1,952 bytes |
| Private key | ~4,896 bytes | ~4,032 bytes |
| Signature | ~4,627 bytes | ~3,309 bytes |
| Ed25519/Ed448 (for comparison) | 114 bytes | 64 bytes |

With the default ML-DSA-87+Ed448 cipher suite, the PQC signature adds ~4.6 KB per artifact to the `.asc` file. For a typical Maven module with 4 artifacts (JAR, POM, sources, javadoc), this adds ~18 KB total.

## Releasing

The project includes a `release` profile in the parent POM that handles GPG signing, source/javadoc JARs, and version management. The release plugin is configured with `pushChanges=false`, `localCheckout=true`, and `remoteTagging=false` — commits and tags stay local until you push manually.

### Release commands

```bash
# Prepare the release (bumps version, creates tag)
mvn release:prepare -Prelease

# Perform the release (builds from tag, signs, deploys)
mvn release:perform -Prelease
```

### What the release profile does

- **maven-release-plugin** — version bumps, git tag (format: `0.0.1`), local checkout
- **maven-source-plugin** — attaches `-sources.jar`
- **maven-javadoc-plugin** — attaches `-javadoc.jar`
- **maven-gpg-plugin** — GPG signing of all artifacts

### After the release

The release plugin does not push to the remote. Review the commits and tag, then push manually:

```bash
git push origin main --tags
```

## Verifying Releases

If your project signs artifacts with this plugin, publish your PQC fingerprint so consumers can verify signatures. Recommended practices:

### Publishing the fingerprint

Make the fingerprint available in multiple independent channels so consumers can cross-check:

- **README** — include the fingerprint in a "Verifying Signatures" section
- **KEYS file** — follow the [Apache KEYS convention](https://www.apache.org/dev/release-signing.html#keys-policy), adding the PQC fingerprint alongside classic GPG key IDs
- **Release notes** — repeat the fingerprint in each release announcement
- **Project website** — publish on a page served from a different infrastructure than the repository

If any source shows a different fingerprint, the artifact should not be trusted.

### Verifying a downloaded artifact

Consumers need the signer's GPG public key in their keyring and the PQC certificate in their Sequoia cert store. Then verify with:

**CLI:**

```bash
java -jar sigmund.jar verify-signature \
  --file my-artifact-1.0.jar \
  --signature my-artifact-1.0.jar.asc
```

**Maven plugin:**

```bash
mvn sigmund:verify-signature \
  -Dfile=my-artifact-1.0.jar \
  -Dsignature=my-artifact-1.0.jar.asc
```

By default, every signature in the `.asc` file must pass verification. Use `--lenient` / `sigmund.lenient=true` to tolerate skipped or no-key signatures (at least one must pass and none may fail).

## References

- [FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) — NIST standard for ML-DSA (Dilithium)
- [RFC 9980 (draft-ietf-openpgp-pqc)](https://datatracker.ietf.org/doc/draft-ietf-openpgp-pqc/) — PQC algorithms for OpenPGP
- [RFC 9580](https://www.rfc-editor.org/rfc/rfc9580) — OpenPGP v6 (Crypto Refresh)
- [Sequoia PGP PQC blog post](https://sequoia-pgp.org/blog/2025/11/15/202511-post-quantum-cryptography/)
- [Sequoia PQC source](https://gitlab.com/sequoia-pgp/sequoia-sq/-/tree/pqc) — PQC branch
- [maven-gpg-plugin](https://maven.apache.org/plugins/maven-gpg-plugin/) — upstream target for contribution
