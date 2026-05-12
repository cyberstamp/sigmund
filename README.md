# PQC Hybrid Signing for Maven Artifacts

## Overview

This tool adds post-quantum cryptographic (PQC) signatures to Maven artifacts alongside classic GPG signatures. Every `.asc` signature file contains two OpenPGP signatures:

- A **classic v4 signature** (RSA/EdDSA via GnuPG) — backward-compatible, verifiable by all existing tools
- A **PQC v6 signature** (ML-DSA-65+Ed25519 via Sequoia) — quantum-resistant, per [draft-ietf-openpgp-pqc](https://datatracker.ietf.org/doc/draft-ietf-openpgp-pqc/)

The two signatures can be stored as **two separate armored blocks** (default, Maven Central compatible) or **merged into a single armored block** with concatenated raw packets. See [Combine Modes](#combine-modes) for details.

Existing tools (GPG, Maven Central) see only the classic signature and work as before. PQC-aware tools can verify both.

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
# Must show mldsa65-ed25519 in the cipher-suite options
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

This generates a composite ML-DSA-65+Ed25519 keypair in Sequoia's keystore and prints the fingerprint. Save the fingerprint — you'll need it for signing.

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

This produces `my-artifact-1.0.jar.asc` containing both the classic GPG and PQC signatures.

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
  PQC (ML-DSA-65+Ed25519):  PASS    [key: <fingerprint>]
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

**Stage 1 — Classic GPG signature.** `GpgSigner` invokes GnuPG as an external process:

```
gpg --batch --yes --armor --detach-sign [--local-user <keyId>] --output <sig> <artifact>
```

This produces a standard ASCII-armored `.asc` file containing a v4 OpenPGP signature packet. The user's existing GPG keyring and configuration are used as-is.

**Stage 2 — PQC signature.** `SqRunner` invokes Sequoia `sq` as an external process:

```
sq --overwrite sign --signer <fingerprint> --signature-file <sig> <artifact>
```

Sequoia produces a detached ASCII-armored signature containing a v6 OpenPGP signature packet with composite ML-DSA-65+Ed25519 per draft-ietf-openpgp-pqc. The PQC key must be in Sequoia's keystore (set via the `SEQUOIA_HOME` environment variable). The `--overwrite` flag is always passed to handle cases where the output file already exists (e.g., temp files).

**Stage 3 — Combine.** `AscCombiner` merges both signatures into a single `.asc` file. The combine behavior depends on the selected mode (see [Combine Modes](#combine-modes)).

### Combine Modes

The `combineMode` setting controls how the classic and PQC signatures are stored in the `.asc` file.

#### `SEPARATE_BLOCKS` (default)

The classic GPG signature and PQC signature are kept as **two separate ASCII-armored blocks** concatenated in the same file, classic first:

```
-----BEGIN PGP SIGNATURE-----
(classic v4 signature — exactly as GPG produced it)
-----END PGP SIGNATURE-----
-----BEGIN PGP SIGNATURE-----
(PQC v6 signature — exactly as Sequoia produced it)
-----END PGP SIGNATURE-----
```

Neither signature is re-armored — both are preserved byte-for-byte as their respective tools produced them. Verifiers that parse only the first armored block (including Maven Central) see only the classic v4 signature and succeed. PQC-aware tools process all blocks and find the v6 signature.

This is the recommended mode for publishing to Maven Central and other repositories with standard OpenPGP verification.

#### `MERGED_PACKETS`

Both signatures are dearmored, their raw OpenPGP packets concatenated, and re-armored into a **single armored block** using Bouncy Castle's bcpg library:

```
-----BEGIN PGP SIGNATURE-----
Version: BCPG v1.84

(base64-encoded v4 packet bytes + v6 packet bytes)
-----END PGP SIGNATURE-----
```

The steps are:

1. Dearmor the classic `.asc` via `ArmoredInputStream` → raw v4 packet bytes
2. Dearmor the PQC `.sig` via `ArmoredInputStream` → raw v6 packet bytes
3. Concatenate v4 bytes + v6 bytes
4. Re-armor via `ArmoredOutputStream` → single `.asc` file

This produces a more compact output and is a valid OpenPGP armored message with two signature packets in sequence. GPG can verify the classic signature within it (exit code 2 with "Good signature" due to the unknown v6 packet warning). However, some verifiers — including Maven Central — may reject the file because they cannot handle the v6 PQC packet.

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

Sequoia finds the v6 PQC signature packet and verifies it against its cert-store. When the `.asc` contains two separate armored blocks (`SEPARATE_BLOCKS` mode), the verifier automatically extracts the PQC block (second block) into a temporary file for Sequoia, since `sq` only processes the first armored block in a file. In `MERGED_PACKETS` mode, Sequoia reads the single block and finds the v6 packet directly. If `sq` is not available, PQC verification is skipped and the result is `NOT_PRESENT`.

**Verification modes:**

- **Transitional (default):** Classic GPG must pass. PQC result is informational — the overall result is PASS as long as the classic signature is valid.
- **Strict (`--strict`):** Both classic GPG and PQC must pass for the overall result to be PASS.

### Key Management

PQC keys are managed by Sequoia's built-in keystore, controlled by the `SEQUOIA_HOME` environment variable (defaults to `~/.local/share/sequoia`):

- **Key generation** calls `sq key generate --cipher-suite mldsa65-ed25519 --profile rfc9580 --own-key --without-password`. The `--without-password` flag is required for non-interactive use (CI/CD, headless environments) since `sq` otherwise prompts for a passphrase on `/dev/tty`.
- **Key lookup** during signing uses the key fingerprint to locate the key in Sequoia's keystore.
- **Certificate export** for sharing with verifiers: `sq cert export --cert <fingerprint>`.
- **Key isolation** — each `SqRunner` instance sets `SEQUOIA_HOME` to its configured directory, allowing multiple independent keystores.

### Maven Central Compatibility

With `SEPARATE_BLOCKS` mode (the default), the `.asc` file starts with a standard armored block containing only the classic v4 signature. Maven Central's upload validation parses the first armored block, verifies the classic signature against public keyservers, and ignores the second block (the PQC signature). No changes to Maven Central are required.

With `MERGED_PACKETS` mode, the single armored block contains both v4 and v6 packets. Maven Central's verifier rejects this because it encounters the v6 PQC packet it does not understand. **Use `SEPARATE_BLOCKS` (the default) for publishing to Maven Central.**

## CLI Reference

### `pqc-sign keygen`

Generate a PQC keypair (composite ML-DSA-65+Ed25519).

```
pqc-sign keygen --userid <USER_ID> [--sq-home <DIR>]
```

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--userid` | Yes | — | User ID in canonical form (e.g., `"Alice <alice@example.com>"`) |
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
| `--combine-mode` | No | `SEPARATE_BLOCKS` | `SEPARATE_BLOCKS` (Maven Central compatible) or `MERGED_PACKETS` (single armored block) |

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
| `--sq-home` | No | `~/.local/share/sequoia` | Sequoia keystore directory |
| `--strict` | No | `false` | Require both classic and PQC to pass |

## Maven Plugin

### Configuration

Add to your project's `pom.xml`:

```xml
<plugin>
  <groupId>io.github.aloubyansky.pqc.maven</groupId>
  <artifactId>pqc-sign-maven-plugin</artifactId>
  <version>0.1.0-SNAPSHOT</version>
  <executions>
    <execution>
      <goals><goal>sign</goal></goals>
    </execution>
  </executions>
  <configuration>
    <pqcFingerprint>${pqc.fingerprint}</pqcFingerprint>
    <!-- optional: <gpgKeyName>0xABCD1234</gpgKeyName> -->
    <!-- optional: <combineMode>MERGED_PACKETS</combineMode> -->
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

# Use merged packets mode (single armored block):
mvn verify -Dpqc.fingerprint=<FINGERPRINT> -Dpqc.combineMode=MERGED_PACKETS
```

### `pqc-sign:verify`

Verify a signed artifact:

```bash
mvn pqc-sign:verify \
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
| `pqc.sqHome` | No | `~/.local/share/sequoia` | Sequoia keystore directory |
| `pqc.strict` | No | `false` | Require both signatures to pass |

## Testing

### Unit Tests

The unit tests run without any external tools (no GPG or sq required):

- **CliToolTest** (4 tests) — process execution, stdout/stderr capture, exit code handling, checked execution
- **AscCombinerTest** (11 tests) — `SEPARATE_BLOCKS` mode (two-block output, ordering, default-equals-explicit), `MERGED_PACKETS` mode (single-block output, packet concatenation, size), `extractBlock()` (first/second/out-of-range extraction), dearmoring
- **HybridSignerTest** (2 tests) — orchestration with mock signers for both `SEPARATE_BLOCKS` (two blocks) and `MERGED_PACKETS` (single block) modes
- **HybridVerifierTest** (7 tests) — VerificationReport formatting, strict vs transitional modes, PASS/FAIL/NO_KEY/NOT_PRESENT scenarios

Run unit tests:

```bash
mvn test -pl core
```

### Integration Tests

The integration tests (`RoundTripIntegrationTest`) require both GnuPG and PQC-enabled Sequoia sq installed. They are automatically skipped if either tool is unavailable or if `sq` does not support PQC cipher suites (checked by looking for `mldsa65-ed25519` in `sq key generate --help` output).

Make sure the PQC-enabled `sq` is first on your PATH:

```bash
export PATH=~/.cargo/bin:$PATH
mvn test -pl core -Dtest=RoundTripIntegrationTest
```

**Test setup (`@BeforeAll`):**

A fresh Sequoia keystore is created in a JUnit `@TempDir`. A PQC key is generated with `--without-password` (required for non-interactive test execution). The key fingerprint is shared across all test methods.

**Test 1 — Full round-trip, `SEPARATE_BLOCKS` (`fullRoundTrip_signAndVerify`):**

1. Creates a test artifact file
2. Signs with `HybridSigner` using the default `SEPARATE_BLOCKS` mode — produces an `.asc` with two separate armored blocks
3. Verifies with `HybridVerifier` — asserts classic PASS and PQC PASS
4. Asserts `isStrictPass()` is true

**Test 2 — Full round-trip, `MERGED_PACKETS` (`fullRoundTrip_mergedPackets`):**

1. Creates a test artifact file
2. Signs with `HybridSigner` using `MERGED_PACKETS` mode — produces an `.asc` with a single armored block
3. Verifies with `HybridVerifier` — asserts classic PASS and PQC PASS
4. Asserts `isStrictPass()` is true
5. Asserts the `.asc` file contains exactly one armored block

**Test 3 — GPG backward compatibility (`backwardCompat_gpgVerifiesCombinedAsc`):**

1. Creates and signs a test artifact (hybrid `.asc`)
2. Runs `gpg --verify` directly via `CliTool.run()` on the combined `.asc`
3. Asserts GPG reports "Good signature" — accepts exit code 0 or exit code 2 (exit 2 is expected because GPG prints a warning about the unknown v6 PQC packet but still validates the classic signature)

**Test 4 — Tamper detection (`tamperedArtifact_verificationFails`):**

1. Creates and signs a test artifact
2. Overwrites the artifact file with different content
3. Verifies the tampered artifact — asserts both classic and PQC results are FAIL

### Maven Plugin Integration Tests

The Maven plugin includes invoker tests under `maven-plugin/src/it/`. These require GPG, sq, and a configured PQC key. The invoker test signs a sample project and verifies that `.asc` files are produced with the expected structure.

## Known Limitations

### GPG exit code 2 for hybrid `.asc` files

GnuPG returns exit code 2 (rather than 0) when verifying an `.asc` file that contains a v6 PQC packet. This applies to both combine modes — GPG processes all armored blocks in the file and warns about the unknown packet version. The signature itself is valid — GPG reports "Good signature" in its output.

The `HybridVerifier` handles this by checking for "Good signature" in stderr when the exit code is 2. However, other tools or CI systems that check GPG's exit code strictly may interpret exit code 2 as a failure.

### PQC key passphrase protection

The PoC generates PQC keys with `--without-password` to support non-interactive use (CI/CD, tests, headless environments). In a production deployment, keys should be passphrase-protected. This requires either a TTY for interactive passphrase entry or a password file passed via `--new-password-file`.

### Sequoia sq is pre-release

The PQC-enabled Sequoia (`sq 1.4.0-pqc.1`) is a pre-release. The underlying [draft-ietf-openpgp-pqc](https://datatracker.ietf.org/doc/draft-ietf-openpgp-pqc/) is not yet an RFC. Algorithm IDs and packet formats may change before standardization. When the standard is finalized and stable Sequoia releases include PQC, the only change needed in this tool is updating the `sq` binary.

**Finalization timeline (as of April 2026):** The IESG has approved `draft-ietf-openpgp-pqc` (at version -16) as a Proposed Standard, and the document (now at version -17, dated January 2026) is headed to the RFC Editor for final publication. The Sequoia PGP team [plans to release stable PQC support](https://sequoia-pgp.org/blog/2025/11/15/202511-post-quantum-cryptography/) shortly after the RFC is published, targeting the first half of 2026. RHEL 10.1 has already shipped Sequoia with PQC support enabled as a system package.

### `sequoia-openpgp` PQC crate not on crates.io

The PQC-enabled `sequoia-openpgp` (version `2.2.0-pqc.1`) is not published on crates.io. Building `sq` from source requires a `[patch.crates-io]` section in `Cargo.toml` to redirect dependency resolution to the PQC branch of the main Sequoia repository. This is expected to be resolved once the PQC support is merged into mainline Sequoia.

### No classic key ID extraction from GPG output

The `HybridVerifier` does not currently parse the GPG signing key ID from `gpg --verify` output. The `classicKeyId` field in the `VerificationReport` is always `null`. This is a cosmetic limitation — the verification itself works correctly.

### HybridVerifier hardcodes `gpg` executable path

`HybridVerifier.verifyClassic()` calls `gpg --verify` directly via `CliTool.run()` rather than using the `GpgSigner` instance's configured executable path. If the user configured a custom GPG path in `GpgSigner`, it would be used for signing but not for verification. This should be addressed before upstream contribution.

### Bouncy Castle re-armoring adds `Version` header (`MERGED_PACKETS` only)

In `MERGED_PACKETS` mode, `AscCombiner` re-armors the combined packets via Bouncy Castle, which adds a `Version: BCPG v1.84` header to the armored output. This does not affect functionality — GPG and sq both ignore armor headers — but it means the re-armored `.asc` looks slightly different from what GPG or sq would produce natively. In `SEPARATE_BLOCKS` mode (the default), both signatures are preserved exactly as their respective tools produced them, so this does not apply.

### `MERGED_PACKETS` mode incompatible with Maven Central

Maven Central's signature verification rejects `.asc` files produced with `MERGED_PACKETS` mode because its verifier cannot handle the v6 PQC packet inside the single armored block. Use the default `SEPARATE_BLOCKS` mode for publishing to Maven Central.

## Project Structure

```
pom.xml                                  Parent POM
core/                                    Core library
  src/main/java/io/github/aloubyansky/maven/pqc/
    CliTool.java                         External process execution
    GpgSigner.java                       GnuPG CLI wrapper
    SqRunner.java                        Sequoia sq CLI wrapper
    AscCombiner.java                     OpenPGP armor operations (via BC bcpg)
    HybridSigner.java                    Orchestrates classic + PQC signing
    HybridVerifier.java                  Dual verification (gpg + sq)
    VerificationResult.java              Result enum (PASS, FAIL, NO_KEY, NOT_PRESENT)
    VerificationReport.java              Formatted verification report
cli/                                     CLI tools (picocli)
maven-plugin/                            Maven plugin (sign + verify goals)
```

## PQC Signature Sizes

| Component | Size |
|-----------|------|
| ML-DSA-65 public key | ~1,952 bytes |
| ML-DSA-65 private key | ~4,032 bytes |
| ML-DSA-65 signature | ~3,309 bytes |
| Ed25519 signature (for comparison) | 64 bytes |

The PQC signature adds ~3.3 KB per artifact to the `.asc` file. For a typical Maven module with 4 artifacts (JAR, POM, sources, javadoc), this adds ~13 KB total.

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
mvn pqc-sign:verify \
  -Dfile=my-artifact-1.0.jar \
  -Dsignature=my-artifact-1.0.jar.asc \
  -Dpqc.fingerprint=<FINGERPRINT> \
  -Dpqc.strict=true
```

The `--strict` / `pqc.strict=true` flag requires both the classic GPG and PQC signatures to be present and valid. Without it, only the classic GPG signature is required (transitional mode).

## References

- [FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) — NIST standard for ML-DSA (Dilithium)
- [draft-ietf-openpgp-pqc](https://datatracker.ietf.org/doc/draft-ietf-openpgp-pqc/) — PQC algorithms for OpenPGP
- [RFC 9580](https://www.rfc-editor.org/rfc/rfc9580) — OpenPGP v6 (Crypto Refresh)
- [Sequoia PGP PQC blog post](https://sequoia-pgp.org/blog/2025/11/15/202511-post-quantum-cryptography/)
- [Sequoia PQC source](https://gitlab.com/sequoia-pgp/sequoia-sq/-/tree/pqc) — PQC branch
- [maven-gpg-plugin](https://maven.apache.org/plugins/maven-gpg-plugin/) — upstream target for contribution
