# PQC Hybrid Signing for Maven Artifacts

## Overview

This tool adds post-quantum cryptographic (PQC) signatures to Maven artifacts alongside classic GPG signatures. Every `.asc` signature file contains two OpenPGP signatures:

- A **classic v4 signature** (RSA/EdDSA via GnuPG) — backward-compatible, verifiable by all existing tools
- A **PQC v6 signature** (ML-DSA-87+Ed448 via Sequoia, default; configurable) — quantum-resistant, CNSA 2.0 compliant, per [RFC 9980](https://datatracker.ietf.org/doc/draft-ietf-openpgp-pqc/)

The two signatures are stored as **two separate armored blocks** in the same `.asc` file, classic first. Existing tools (GPG, Maven Central) see only the classic signature and work as before. PQC-aware tools can verify both.

## Prerequisites

### JDK 17+

Required for building and running.

```bash
java -version
```

### GnuPG

Required for classic GPG signing. You must have at least one signing key configured.

```bash
# Check installation
gpg --version

# List your signing keys
gpg --list-secret-keys
```

If you don't have a GPG key, generate one:

```bash
gpg --full-generate-key
```

### Sequoia sq (PQC-enabled)

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

#### Building from source

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

### Maven 3.9+

Required for building the project and using the Maven plugin.

## Quick Start

### 1. Build the project

```bash
mvn clean install -DskipTests
```

### 2. Generate a PQC key

```bash
java -jar cli/target/pqc-sign.jar keygen \
  --userid "Your Name <you@example.com>"
```

This generates a PQC hybrid keypair (ML-DSA-87+Ed448 by default) in Sequoia's keystore and prints the fingerprint. Save the fingerprint — you'll need it for signing. Use `--cipher-suite mldsa65-ed25519` to generate a key with the ML-DSA-65 cipher suite instead.

**Storing the fingerprint.** Add it to your shell profile for convenient reuse:

```bash
export PQC_FINGERPRINT=<FINGERPRINT>
```

Then pass it as `--pqc-fingerprint $PQC_FINGERPRINT` in subsequent commands. For team or CI environments, consider storing it in a secret manager and injecting it at runtime:

```bash
# 1Password
--pqc-fingerprint $(op read "op://Vault/PQC Key/fingerprint")

# Bitwarden
--pqc-fingerprint $(bw get notes pqc-fingerprint)
```

Note: the user ID must be in canonical form (`Name <email>`). Bare email addresses are not accepted by `sq`.

### 3. Sign an artifact

```bash
java -jar cli/target/pqc-sign.jar sign \
  --file target/my-artifact-1.0.jar \
  --pqc-fingerprint <FINGERPRINT>
```

This produces `my-artifact-1.0.jar.asc` containing both the classic GPG and PQC signatures as two separate armored blocks (Maven Central compatible).

### 4. Verify a signature

```bash
java -jar cli/target/pqc-sign.jar verify \
  --file target/my-artifact-1.0.jar \
  --signature target/my-artifact-1.0.jar.asc \
  --pqc-fingerprint <FINGERPRINT>
```

Output:

```
Signature Verification Report:
  Classic (GPG):             PASS
  PQC (ML-DSA-87+Ed448):    PASS    [key: <fingerprint>]
  Overall: PASS (both signatures valid)
```

### 5. Verify backward compatibility

Standard GPG can verify the hybrid `.asc` — it reads the classic v4 packet and ignores the PQC v6 packet:

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

## How It Works

### Signing Pipeline

```
artifact.jar
    |
    +-- gpg --detach-sign --armor --> classic.asc  (v4 signature packet)
    |
    +-- sq sign --signature-file --> pqc.sig       (v6 PQC signature packet)
    |
    +-- AscCombiner.combine() -----> artifact.jar.asc
```

**Stage 1 — Classic GPG signature.** `GpgRunner` invokes GnuPG as an external process:

```
gpg --batch --yes --armor --detach-sign [--local-user <keyId>] --output <sig> <artifact>
```

This produces a standard ASCII-armored `.asc` file containing a v4 OpenPGP signature packet. The user's existing GPG keyring and configuration are used as-is.

**Stage 2 — PQC signature.** `SqRunner` invokes Sequoia `sq` as an external process:

```
sq --overwrite sign --signer <fingerprint> --signature-file <sig> <artifact>
```

Sequoia produces a detached ASCII-armored signature containing a v6 OpenPGP signature packet with the configured PQC hybrid cipher suite (ML-DSA-87+Ed448 by default) per RFC 9980. The PQC key must be in Sequoia's keystore (set via the `SEQUOIA_HOME` environment variable). The `--overwrite` flag is always passed to handle cases where the output file already exists (e.g., temp files).

**Stage 3 — Combine.** `AscCombiner` concatenates both signatures into a single `.asc` file as two separate armored blocks, classic first:

```
-----BEGIN PGP SIGNATURE-----
(classic v4 signature — exactly as GPG produced it)
-----END PGP SIGNATURE-----
-----BEGIN PGP SIGNATURE-----
(PQC v6 signature — exactly as Sequoia produced it)
-----END PGP SIGNATURE-----
```

Neither signature is re-armored — both are preserved byte-for-byte as their respective tools produced them. Verifiers that parse only the first armored block (including Maven Central) see only the classic v4 signature and succeed. PQC-aware tools process all blocks and find the v6 signature.

### Verification Pipeline

```
artifact.jar + artifact.jar.asc
    |
    +-- gpg --verify ------------> classic result (PASS/FAIL)
    |
    +-- sq verify ---------------> PQC result     (PASS/FAIL)
    |
    +-- VerificationReport ------> combined report
```

Verification delegates to each tool independently:

**Classic verification.** `HybridVerifier` runs:

```
gpg --verify <signature.asc> <artifact>
```

GPG parses the `.asc`, finds the v4 signature packet, verifies it against its keyring, and skips the v6 PQC packet (printing a warning: `packet(2) with unknown version 6`).

GPG exit codes are interpreted as:
- **Exit 0** — signature valid (PASS)
- **Exit 2 with "Good signature" in stderr** — signature valid but GPG encountered the unknown v6 packet (PASS). This is the expected result for hybrid `.asc` files.
- **Exit 1** — bad signature (FAIL)
- **Other** — error (FAIL)

**PQC verification.** `HybridVerifier` delegates to `SqRunner`, which runs:

```
sq verify --signer <fingerprint> --signature-file <signature.asc> <artifact>
```

Sequoia finds the v6 PQC signature packet and verifies it against its cert-store. Since the `.asc` contains two separate armored blocks and `sq` only processes the first armored block in a file, the verifier automatically extracts the PQC block (second block) into a temporary file for Sequoia. If `sq` is not available, PQC verification is skipped and the result is `NOT_PRESENT`.

**Verification modes:**

- **Transitional (default):** Classic GPG must pass. PQC result is informational — the overall result is PASS as long as the classic signature is valid.
- **Strict (`--strict`):** Both classic GPG and PQC must pass for the overall result to be PASS.

### Key Management

PQC keys are managed by Sequoia's built-in keystore, controlled by the `SEQUOIA_HOME` environment variable (defaults to `~/.local/share/sequoia`):

- **Key generation** calls `sq key generate --cipher-suite <suite> --profile rfc9580 --own-key --without-password`, where `<suite>` defaults to `mldsa87-ed448` (CNSA 2.0 compliant). The `--without-password` flag is required for non-interactive use (CI/CD, headless environments) since `sq` otherwise prompts for a passphrase on `/dev/tty`.
- **Key lookup** during signing uses the key fingerprint to locate the key in Sequoia's keystore.
- **Certificate export** for sharing with verifiers: `sq cert export --cert <fingerprint>`.
- **Key isolation** — each `SqRunner` instance sets `SEQUOIA_HOME` to its configured directory, allowing multiple independent keystores.

### Maven Central Compatibility

The `.asc` file starts with a standard armored block containing only the classic v4 signature. Maven Central's upload validation parses the first armored block, verifies the classic signature against public keyservers, and ignores the second block (the PQC signature). No changes to Maven Central are required.

## CLI Reference

### `pqc-sign keygen`

Generate a PQC hybrid keypair.

```
pqc-sign keygen --userid <USER_ID> [--cipher-suite <SUITE>] [--sq-home <DIR>]
```

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--userid` | Yes | — | User ID in canonical form (e.g., `"Alice <alice@example.com>"`) |
| `--cipher-suite` | No | `mldsa87-ed448` | PQC cipher suite (e.g., `mldsa65-ed25519` for ML-DSA-65) |
| `--sq-home` | No | `~/.local/share/sequoia` | Sequoia keystore directory |

### `pqc-sign sign`

Create a hybrid signature (classic GPG + PQC).

```
pqc-sign sign --file <FILE> --pqc-fingerprint <FP> [options]
```

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--file` | Yes | — | Artifact file to sign |
| `--pqc-fingerprint` | Yes | — | PQC key fingerprint (from keygen) |
| `--gpg-key` | No | GPG default | GPG key ID for classic signing |
| `--sq-home` | No | `~/.local/share/sequoia` | Sequoia keystore directory |
| `--output` | No | `<file>.asc` | Output signature file path |

### `pqc-sign verify`

Verify a hybrid signature.

```
pqc-sign verify --file <FILE> --signature <ASC> [options]
```

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--file` | Yes | — | Artifact file to verify |
| `--signature` | Yes | — | Signature `.asc` file |
| `--pqc-fingerprint` | No | — | Expected PQC signer fingerprint. If omitted, any valid PQC signature is accepted. |
| `--pqc-cert-file` | No | — | PQC certificate file for verification (takes precedence over `--pqc-fingerprint`) |
| `--sq-home` | No | `~/.local/share/sequoia` | Sequoia keystore directory |
| `--strict` | No | `false` | Require both classic and PQC to pass |

### `pqc-sign export-cert`

Export a PQC public certificate for distribution.

```
pqc-sign export-cert --fingerprint <FP> [options]
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
  <groupId>io.github.aloubyansky.pqc.maven</groupId>
  <artifactId>pqc-sign-maven-plugin</artifactId>
  <version>0.0.2</version>
  <executions>
    <execution>
      <goals><goal>sign</goal></goals>
    </execution>
  </executions>
  <configuration>
    <pqcFingerprint>${pqc.fingerprint}</pqcFingerprint>
    <!-- optional: <gpgKeyName>0xABCD1234</gpgKeyName> -->
  </configuration>
</plugin>
```

**Using an environment variable.** If you stored the fingerprint in `PQC_FINGERPRINT` (see [Generate a PQC key](#2-generate-a-pqc-key)), reference it directly in the plugin configuration:

```xml
<configuration>
  <pqcFingerprint>${env.PQC_FINGERPRINT}</pqcFingerprint>
</configuration>
```

This way `mvn verify` picks up the fingerprint automatically — no `-D` flag needed.

### `pqc-sign:sign`

Bound to the `verify` phase. Signs all project artifacts (JAR, POM, sources, javadoc) with both classic GPG and PQC, and attaches the `.asc` files for deployment. The `pqcFingerprint` parameter is required — the build will fail if it is not configured.

```bash
mvn verify -Dpqc.fingerprint=<FINGERPRINT>
```

| Property | Required | Default | Description |
|----------|----------|---------|-------------|
| `pqc.fingerprint` | Yes | — | PQC key fingerprint (from keygen) |
| `gpg.keyname` | No | GPG default | GPG key ID or email for classic signing |
| `pqc.sqHome` | No | `~/.local/share/sequoia` | Sequoia keystore directory |

### `pqc-sign:verify-artifact`

Verify a single signed artifact (standalone, no project required):

```bash
mvn pqc-sign:verify-artifact \
  -Dfile=artifact.jar \
  -Dsignature=artifact.jar.asc \
  -Dpqc.fingerprint=<FINGERPRINT> \
  -Dpqc.strict=true
```

| Property | Required | Default | Description |
|----------|----------|---------|-------------|
| `file` | Yes | — | Artifact file to verify |
| `signature` | Yes | — | Signature `.asc` file |
| `pqc.fingerprint` | No | — | Expected PQC signer fingerprint. If omitted, any valid PQC signature is accepted. |
| `pqc.certFile` | No | — | PQC certificate file for verification (takes precedence over `pqc.fingerprint`) |
| `pqc.sqHome` | No | `~/.local/share/sequoia` | Sequoia keystore directory |
| `pqc.strict` | No | `false` | Require both signatures to pass |

### `pqc-sign:verify`

Verifies that all project dependencies are signed by trusted signers as defined in a `trust-config.yaml` file. Matching is done by GPG/PQC fingerprint when available, falling back to signer user ID. Artifacts listed in the `unsigned` section are skipped.

```bash
mvn pqc-sign:verify
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
      - gpg: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
        uid: "Maven PMC <dev@maven.apache.org>"
      - gpg: "BBE7232D7991050B54C8EA0ADC08637CA615D22C"

  # Short form: single-key signer
  jane:
    gpg: "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
    uid: "Jane Doe <jane@example.com>"

  # Minimal form: uid only
  jackson-dev: "Tatu Saloranta <tatu@fasterxml.com>"

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

**Signers** define trusted identities in three forms: full (organization with multiple members), short (single key), or minimal (uid string only). Each member can specify a GPG fingerprint (`gpg`), PQC fingerprint (`pqc`), and/or user ID (`uid`). Fingerprints are matched first; uid is used as a fallback.

**Artifacts** define named groups of coordinate patterns, referenced by name in `trust`.

**Trust** maps artifact patterns or artifact group names to signer references. If a key matches a name in `artifacts`, it is expanded; otherwise it is treated as a Maven coordinate pattern. Patterns support: `groupId`, `groupId:artifactId`, `groupId:artifactId:version`, or `groupId:artifactId:type:classifier:version`. Wildcards (`*`) and group prefixes (`org.apache.*`) are supported. When multiple patterns match, the most specific wins.

**Unsigned** lists artifact patterns for which no signature is expected.

**Generating the config.** Use `dependency-signers` with `-Dpqc.generateTrustConfig=true` to generate an initial `trust-config.yaml` from your project's actual dependency signatures.

**Updating the config.** Use `dependency-signers` with `-Dpqc.updateTrustConfig=true` to append any newly added dependencies to an existing config.

Example output:

```
Signer: Jane Doe <jane@example.com>
   GPG: DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF
     com.example:lib:1.0

UNTRUSTED
  Signer: Unknown <unknown@example.com> (not trusted)
     GPG: DEADBEEFDEADBEEF
       com.other:tool:3.0

  UNSIGNED
       org.wildfly.common:wildfly-common:2.0.1

TRUSTED UNSIGNED
     com.internal:util:1.0

Summary: 1 passed, 2 failed
```

| Property | Required | Default | Description |
|----------|----------|---------|-------------|
| `pqc.trustConfig` | No | `${project.basedir}/trust-config.yaml` | Path to the trust configuration file |
| `pqc.onUntrusted` | No | — | Policy for untrusted artifacts: `fail` or `warn`. Overrides the config file setting. |
| `pqc.verifyAllSignatures` | No | — | When `true`, unverified signatures on trusted artifacts are reported. Overrides the config file setting. |
| `pqc.fetchSignerInfo` | No | `false` | Fetch unknown GPG keys from keyservers. Overrides the config file setting. |
| `pqc.keyservers` | No | `hkps://keyserver.ubuntu.com,hkps://keys.openpgp.org` | Comma-separated keyserver list. Used when `fetchSignerInfo` is enabled. |
| `pqc.verifyPomFiles` | No | `false` | Also verify signatures on POM files for each dependency |
| `pqc.skip` | No | `false` | Skip verification |
| `pqc.sqHome` | No | `~/.local/share/sequoia` | Sequoia keystore directory |
| `pqc.includeTestDependencies` | No | `false` | Include test-scoped dependencies |

### `pqc-sign:dependency-signers`

Reports signer information for all project dependencies by downloading and inspecting their `.asc` signature files. Each armored block is reported separately with its OpenPGP version (v4 for classical GPG, v6 for PQC). Classical signatures are verified via GPG; PQC signatures are verified via Sequoia when the signer's certificate is available in the local cert store.

Dependencies are grouped by signer, sorted alphabetically. Each signer block shows the signature type (GPG/PQC) and key ID, followed by the artifacts signed by that signer. Unsigned artifacts and unverified signatures are reported separately.

```bash
# Report signers
mvn pqc-sign:dependency-signers

# Generate trust-config.yaml from actual signatures
mvn pqc-sign:dependency-signers -Dpqc.generateTrustConfig=true -Dpqc.fetchSignerInfo=true

# Update an existing trust-config.yaml with newly added dependencies
mvn pqc-sign:dependency-signers -Dpqc.updateTrustConfig=true -Dpqc.fetchSignerInfo=true
```

**Generating a trust config.** Use `-Dpqc.generateTrustConfig=true` to create an initial `trust-config.yaml` from your project's actual dependency signatures. The generated file groups artifacts by signer, collapses common groupId prefixes into wildcard patterns (e.g., `io.quarkus.*`), and lists unsigned artifacts in the `unsigned` section. The file can be used directly with the `verify` goal.

**Updating a trust config.** Use `-Dpqc.updateTrustConfig=true` to add new dependency signers to an existing `trust-config.yaml`. This is useful after adding new dependencies — existing content including comments and formatting is preserved, and new entries are inserted at the end of each section. Review the changes with `git diff`.

Example output:

```
Signer: Alice <alice@example.com>
   GPG: 4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12
   PQC: D62AAB339E45E5EA2FD036872B01D46A517A2991...
     com.example:lib-a:1.0
     com.example:lib-b:2.0

Signer: NOT VERIFIED
   GPG: DEADBEEFDEADBEEFDEADBEEF
     com.other:tool:3.0

UNSIGNED
  com.internal:util:1.0

Summary: All clear: 4 dependencies, 3 GPG signature(s), 1 PQC signature(s), 2 unique key(s)
```

| Property | Required | Default | Description |
|----------|----------|---------|-------------|
| `pqc.skip` | No | `false` | Skip the report |
| `pqc.fetchSignerInfo` | No | `false` | Fetch unknown GPG keys from keyservers to resolve signer identities |
| `pqc.keyservers` | No | `hkps://keyserver.ubuntu.com,hkps://keys.openpgp.org` | Comma-separated list of keyservers for fetching GPG keys |
| `pqc.sqHome` | No | `~/.local/share/sequoia` | Sequoia keystore directory for PQC cert lookup |
| `pqc.includeTestDependencies` | No | `false` | Include test-scoped dependencies |
| `pqc.generateTrustConfig` | No | — | Generate a `trust-config.yaml`. Set to `true` to write to the project root, or provide a file path. Fails if the file already exists unless `pqc.overwrite=true`. |
| `pqc.overwrite` | No | `false` | Allow overwriting an existing generated trust config file |
| `pqc.updateTrustConfig` | No | — | Update an existing `trust-config.yaml` by appending unconfigured signers and artifacts. Set to `true` for the default location, or provide a file path. |

## Testing

### Unit Tests

The unit tests run without any external tools (no GPG or sq required):

**Core module:**
- **CliToolTest** (4 tests) — process execution, stdout/stderr capture, exit code handling, checked execution
- **AscCombinerTest** (7 tests) — two-block output, ordering, `extractBlock()` (first/second/out-of-range extraction), dearmoring
- **HybridSignerTest** (1 test) — orchestration with mock signers, verifies two-block output
- **HybridVerifierTest** (7 tests) — VerificationReport formatting, strict vs transitional modes, PASS/FAIL/NO_KEY/NOT_PRESENT scenarios

**Maven plugin module:**
- **TrustConfigParserTest** (23 tests) — YAML parsing of all signer forms (minimal/short/full), settings defaults and overrides, artifact groups, trust mappings, unsigned section, validation errors
- **ArtifactMatcherTest** (10 tests) — unsigned patterns, artifact groups, group prefix matching, specificity scoring, multiple signer refs, wildcard matching
- **TrustPatternCollapseTest** (12 tests) — within-group wildcard collapse, majority signer with exceptions, cross-group prefix merging, deeply nested hierarchies
- **VerifyMojoTest** (15 tests) — fingerprint matching (exact, suffix, case insensitive), member-to-signature matching (GPG, PQC, uid, precedence rules)
- **DependencySignersMojoTest** (8 tests) — signer reporting logic

Run unit tests:

```bash
mvn test
```

### Integration Tests

The integration tests (`RoundTripIntegrationTest`) require both GnuPG and PQC-enabled Sequoia sq installed. They are automatically skipped if either tool is unavailable or if `sq` does not support the default PQC cipher suite (`mldsa87-ed448`).

Make sure the PQC-enabled `sq` is first on your PATH:

```bash
export PATH=~/.cargo/bin:$PATH
mvn test -pl core -Dtest=RoundTripIntegrationTest
```

**Test setup (`@BeforeAll`):**

A fresh Sequoia keystore is created in a JUnit `@TempDir`. A PQC key is generated with `--without-password` (required for non-interactive test execution). The key fingerprint is shared across all test methods.

**Test 1 — Full round-trip (`fullRoundTrip_signAndVerify`):**

1. Creates a test artifact file
2. Signs with `HybridSigner` — produces an `.asc` with two separate armored blocks
3. Verifies with `HybridVerifier` — asserts classic PASS and PQC PASS
4. Asserts `isStrictPass()` is true

**Test 2 — GPG backward compatibility (`backwardCompat_gpgVerifiesCombinedAsc`):**

1. Creates and signs a test artifact (hybrid `.asc`)
2. Runs `gpg --verify` directly via `CliTool.run()` on the combined `.asc`
3. Asserts GPG reports "Good signature" — accepts exit code 0 or exit code 2 (exit 2 is expected because GPG prints a warning about the unknown v6 PQC packet but still validates the classic signature)

**Test 3 — Tamper detection (`tamperedArtifact_verificationFails`):**

1. Creates and signs a test artifact
2. Overwrites the artifact file with different content
3. Verifies the tampered artifact — asserts both classic and PQC results are FAIL

### Maven Plugin Integration Tests

The Maven plugin includes invoker tests under `maven-plugin/src/it/`:

- **dependency-signers** — reports signer information for a real dependency (commons-lang3)
- **verify** — generates a `trust-config.yaml` via `dependency-signers`, then verifies dependencies against it
- **update-trust-config** — creates a partial trust config, updates it with missing signers, verifies comments are preserved and no duplicate YAML sections exist
- **sign-verify-roundtrip** — signs a sample project and verifies `.asc` structure (requires GPG + PQC-enabled sq)

## Known Limitations

### GPG exit code 2 for hybrid `.asc` files

GnuPG returns exit code 2 (rather than 0) when verifying an `.asc` file that contains a v6 PQC packet. GPG processes all armored blocks in the file and warns about the unknown packet version. The signature itself is valid — GPG reports "Good signature" in its output.

The `HybridVerifier` handles this by checking for "Good signature" in stderr when the exit code is 2. However, other tools or CI systems that check GPG's exit code strictly may interpret exit code 2 as a failure.

### PQC key passphrase protection

The PoC generates PQC keys with `--without-password` to support non-interactive use (CI/CD, tests, headless environments). In a production deployment, keys should be passphrase-protected. This requires either a TTY for interactive passphrase entry or a password file passed via `--new-password-file`.

### Sequoia sq is pre-release

The PQC-enabled Sequoia (`sq 1.4.0-pqc.1`) is a pre-release. The underlying [RFC 9980](https://datatracker.ietf.org/doc/draft-ietf-openpgp-pqc/) (Post-Quantum Cryptography in OpenPGP) has been approved by the IESG as a Proposed Standard and is in AUTH48 (final author review at the RFC Editor). When stable Sequoia releases include PQC, the only change needed in this tool is updating the `sq` binary.

The Sequoia PGP team [plans to release stable PQC support](https://sequoia-pgp.org/blog/2025/11/15/202511-post-quantum-cryptography/) shortly after the RFC is published. RHEL 10.1 has already shipped Sequoia with PQC support enabled as a system package.

### `sequoia-openpgp` PQC crate not on crates.io

The PQC-enabled `sequoia-openpgp` (version `2.2.0-pqc.1`) is not published on crates.io. Building `sq` from source requires a `[patch.crates-io]` section in `Cargo.toml` to redirect dependency resolution to the PQC branch of the main Sequoia repository. This is expected to be resolved once the PQC support is merged into mainline Sequoia.

## Project Structure

```
pom.xml                                  Parent POM
core/                                    Core library
  src/main/java/io/github/aloubyansky/maven/pqc/
    CliTool.java                         External process execution
    GpgRunner.java                       GnuPG CLI wrapper (signing + verification)
    SqRunner.java                        Sequoia sq CLI wrapper
    AscCombiner.java                     OpenPGP armor operations (via BC bcpg)
    HybridSigner.java                    Orchestrates classic + PQC signing
    HybridVerifier.java                  Dual verification (gpg + sq)
    PqcKeyConfig.java                    PQC key identification (fingerprint or cert file)
    SignatureInfo.java                   Signature metadata (version, key ID, algorithm, signer)
    VerificationResult.java              Result enum (PASS, FAIL, NO_KEY, NOT_PRESENT, SKIPPED)
    VerificationReport.java              Formatted verification report
cli/                                     CLI tools (picocli)
maven-plugin/                            Maven plugin (sign, verify, verify-artifact, dependency-signers goals)
```

## PQC Signature Sizes

| Component | ML-DSA-87 (default) | ML-DSA-65 |
|-----------|---------------------|-----------|
| Public key | ~2,592 bytes | ~1,952 bytes |
| Private key | ~4,896 bytes | ~4,032 bytes |
| Signature | ~4,627 bytes | ~3,309 bytes |
| Ed25519/Ed448 (for comparison) | 114 bytes | 64 bytes |

With the default ML-DSA-87+Ed448 cipher suite, the PQC signature adds ~4.6 KB per artifact to the `.asc` file. For a typical Maven module with 4 artifacts (JAR, POM, sources, javadoc), this adds ~18 KB total.

## Upstream Contribution Path

This PoC uses `io.github.aloubyansky.pqc.maven` as its groupId. The code is structured for future contribution to `maven-gpg-plugin`:

- `HybridSigner` would extend `AbstractGpgSigner` as a new `signer=hybrid` option
- Configuration parameters (`pqcFingerprint`, `sqHome`) would be added to the existing `sign` goal
- The `verify` goal would be contributed as a new goal
- Sequoia `sq` would become an optional dependency alongside GnuPG

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

Consumers can verify using the CLI or Maven plugin with the published fingerprint:

**CLI:**

```bash
java -jar pqc-sign.jar verify \
  --file my-artifact-1.0.jar \
  --signature my-artifact-1.0.jar.asc \
  --pqc-fingerprint <FINGERPRINT> \
  --strict
```

**Maven plugin:**

```bash
mvn pqc-sign:verify-artifact \
  -Dfile=my-artifact-1.0.jar \
  -Dsignature=my-artifact-1.0.jar.asc \
  -Dpqc.fingerprint=<FINGERPRINT> \
  -Dpqc.strict=true
```

The `--strict` / `pqc.strict=true` flag requires both the classic GPG and PQC signatures to be present and valid. Without it, only the classic GPG signature is required (transitional mode).

## References

- [FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) — NIST standard for ML-DSA (Dilithium)
- [RFC 9980 (draft-ietf-openpgp-pqc)](https://datatracker.ietf.org/doc/draft-ietf-openpgp-pqc/) — PQC algorithms for OpenPGP
- [RFC 9580](https://www.rfc-editor.org/rfc/rfc9580) — OpenPGP v6 (Crypto Refresh)
- [Sequoia PGP PQC blog post](https://sequoia-pgp.org/blog/2025/11/15/202511-post-quantum-cryptography/)
- [Sequoia PQC source](https://gitlab.com/sequoia-pgp/sequoia-sq/-/tree/pqc) — PQC branch
- [maven-gpg-plugin](https://maven.apache.org/plugins/maven-gpg-plugin/) — upstream target for contribution
