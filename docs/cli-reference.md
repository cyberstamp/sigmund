# CLI Reference

The Sigmund CLI provides command-line tools for key management, artifact signing, and signature verification. While the **Maven plugin is the primary interface** for project-level signing and trust verification, the CLI is useful for:

- **Key management** — Generating signing keys and exporting public certificates
- **Standalone workflows** — Signing and verifying artifacts outside Maven builds
- **Integration** — Scripting custom signing pipelines
- **Exploration** — Testing signature operations before integrating with Maven

## Contents

- [Getting the CLI](#getting-the-cli)
- [Global Options](#global-options)
- [Commands](#commands)
  - [sigmund keygen](#sigmund-keygen)
  - [sigmund signer-info](#sigmund-signer-info)
  - [sigmund sign](#sigmund-sign)
  - [sigmund verify-signature](#sigmund-verify-signature)
  - [sigmund inspect-signer](#sigmund-inspect-signer)
  - [sigmund export-cert](#sigmund-export-cert)
- [Configuration File](#configuration-file)
- [CLI vs Maven Plugin](#cli-vs-maven-plugin)

## Getting the CLI

Download `sigmund.jar` from the [latest GitHub release](https://github.com/aloubyansky/sigmund/releases).

Alternatively, build from source:

```bash
mvn clean install -DskipTests
```

The CLI is packaged as a Quarkus application. After building, the runnable JAR is located at:

```
cli/target/sigmund.jar
```

Run commands using:

```bash
java -jar cli/target/sigmund.jar <command> [options]
```

For convenience, the examples below use `sigmund` as the command name. You can create an alias:

```bash
alias sigmund='java -jar /path/to/sigmund.jar'
```

**Native compilation:** The CLI is built with Quarkus, which supports native compilation via GraalVM for faster startup and lower memory footprint. See the [Quarkus native guide](https://quarkus.io/guides/building-native-image) for details.

## Global Options

These options are available for all commands:

| Option | Description |
|--------|-------------|
| `--config <path>` | Path to `sigmund.yaml` configuration file (default: looks in current directory and parent directories). Available on all commands except `export-cert`. |
| `--help` | Display help information for the command |
| `--version` | Display Sigmund version |

All commands (except `export-cert`) read configuration from `sigmund.yaml` in the current directory or its parents unless `--config` specifies a different location. Command-line options override configuration file values.

## Commands

### `sigmund keygen`

Generate a new signing key using Sequoia (`sq`) or Bouncy Castle (`bc`).

```bash
sigmund keygen --userid <USER_ID> [options]
```

**Options:**

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--userid` | Yes | — | User ID in canonical form (e.g., `"Alice <alice@example.com>"`) |
| `--tool` | Yes | — | Backend: `sq` (PQC/hybrid support) or `bc` (classic OpenPGP) |
| `--cipher-suite` | No | `mldsa87-ed448` (sq)<br/>`ed25519` (bc) | Cipher suite for the key |
| `--passphrase-env` | No | `SIGMUND_BC_PASSPHRASE` | Environment variable containing the BC key passphrase (bc keygen only) |
| `--sq-home` | No | `~/.local/share/sequoia` | Sequoia keystore directory (overrides `SEQUOIA_HOME`) (sq only) |

**Bouncy Castle cipher suites:** `ed25519`, `ed448`, `rsa4096`, `nistp256`, `nistp384`, `nistp521`

**Note:** The user ID must be in canonical form (`Name <email>`). Bare email addresses are not accepted by `sq`.

**Examples:**

Generate a PQC key with the default ML-DSA-87 + Ed448 hybrid cipher suite:

```bash
sigmund keygen --tool sq --userid "Alice <alice@example.com>"
```

Generate a classic Ed25519 key using Bouncy Castle:

```bash
sigmund keygen --userid "Alice <alice@example.com>" --tool bc --cipher-suite ed25519
```

Generate a passphrase-protected BC key:

```bash
export SIGMUND_BC_PASSPHRASE="my-secure-passphrase"
sigmund keygen --userid "Alice <alice@example.com>" --tool bc
```

The command outputs the fingerprint of the generated key. Save this fingerprint — it's required for signing operations.

---

### `sigmund signer-info`

Display the effective signing configuration and signer identities without performing any signing.

```bash
sigmund signer-info [options]
```

**Options:**

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--profile` | No | default profile | Signing profile to display |
| `--sq-home` | No | `~/.local/share/sequoia` | Sequoia keystore directory (overrides `SEQUOIA_HOME`) |

**Examples:**

```bash
# Show default signing configuration
sigmund signer-info

# Show configuration for a specific profile
sigmund signer-info --profile hybrid
```

**Output:**

```
gpg: RSA 41A2197725BD63EB00D071D46A7F5DB1C68BDB81 (Alice <alice@example.com>)
sq: ML-DSA-87+Ed448 D62AAB339E45E5EA2FD036872B01D46A517A2991... (Alice <alice@example.com>)
```

---

### `sigmund sign`

Create a signature for an artifact. The signing tool(s) and key fingerprints are read from `sigmund.yaml` unless overridden by command-line options.

```bash
sigmund sign --file <FILE> [options]
```

**Options:**

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--file` | Yes | — | Artifact file to sign |
| `--sq-home` | No | `~/.local/share/sequoia` | Sequoia keystore directory (overrides `SEQUOIA_HOME`) |
| `--output` | No | `<file>.asc` | Output signature file path |

**Example:**

Sign an artifact:

```bash
sigmund sign --file target/my-artifact-1.0.jar
```

The command creates a `.asc` signature file next to the artifact (or at the path specified by `--output`). Signing keys and passphrases are configured in `sigmund.yaml`.

---

### `sigmund verify-signature`

Verify a signature using all available tools according to tool priority configured in `sigmund.yaml`.

```bash
sigmund verify-signature --file <FILE> --signature <ASC> [options]
```

**Options:**

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--file` | Yes | — | Artifact file to verify |
| `--signature` | Yes | — | Signature `.asc` file |
| `--sq-home` | No | `~/.local/share/sequoia` | Sequoia keystore directory (overrides `SEQUOIA_HOME`) |
| `--lenient` | No | `false` | Pass if at least one signature is valid and none failed |

**Verification modes:**

- **Default mode:** All signatures in the file must pass verification.
- **Lenient mode** (`--lenient`): At least one signature must pass; none may fail. This allows verification to succeed when some signatures cannot be verified due to missing keys or unsupported algorithms, as long as at least one valid signature is found.

**Example:**

Verify an artifact signature:

```bash
sigmund verify-signature --file target/my-artifact-1.0.jar \
  --signature target/my-artifact-1.0.jar.asc
```

Sample output:

```
Signature Verification Report:
  [1] VERIFIED (ML-DSA-87+Ed448) [key: D62AAB33...] [signer: Alice <alice@example.com>]
  [2] VERIFIED (EdDSA) [key: 4AEE18F8...] [signer: Alice <alice@example.com>]
  Overall: 2 VERIFIED
```

The last line counts outcomes rather than naming a verdict of its own. A block
left undecided reads as `INDETERMINATE` followed by the reason, for example
`INDETERMINATE [KEY_UNAVAILABLE]`.

Exit codes:
- `0` — Verification passed
- `1` — Verification failed

---

### `sigmund inspect-signer`

Inspect a signer identity across all available sources (local keystores and keyservers). Useful for verifying that a signer's key is reachable before configuring trust mappings.

```bash
sigmund inspect-signer <IDENTIFIER> [options]
```

The identifier is auto-detected by default: hex strings are treated as fingerprints, strings containing `@` as emails. Use explicit flags to override auto-detection.

**Options:**

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `<identifier>` | No | — | Signer identifier (fingerprint or email, auto-detected) |
| `--fingerprint` | No | — | Treat identifier as a fingerprint |
| `--email` | No | — | Treat identifier as an email |
| `--sigstore-issuer` | No | — | Sigstore certificate OIDC issuer URL |
| `--sigstore-subject` | No | — | Sigstore certificate SAN subject |
| `--keyservers` | No | from config | Keyservers to query (comma-separated) |
| `--tool` | No | all | Restrict inspection to a specific tool (`bc`, `sq`, `gpg`) |
| `--sq-home` | No | `~/.local/share/sequoia` | Sequoia keystore directory |

Either a positional `<identifier>` or `--sigstore-issuer` + `--sigstore-subject` is required.

**Examples:**

Inspect a fingerprint:

```bash
sigmund inspect-signer 4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12
```

Inspect an email:

```bash
sigmund inspect-signer alice@example.com
```

Inspect a Sigstore identity:

```bash
sigmund inspect-signer \
  --sigstore-issuer "https://token.actions.githubusercontent.com" \
  --sigstore-subject "https://github.com/org/repo"
```

---

### `sigmund export-cert`

Export a PQC public certificate from the Sequoia keystore for distribution to others.

```bash
sigmund export-cert --fingerprint <FP> [options]
```

**Options:**

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--fingerprint` | Yes | — | PQC key fingerprint to export |
| `--sq-home` | No | `~/.local/share/sequoia` | Sequoia keystore directory (overrides `SEQUOIA_HOME`) |
| `--output`, `-o` | No | stdout | Output file path |

**Example:**

Export a certificate to a file:

```bash
sigmund export-cert --fingerprint D62AAB339E45E5EA2FD036872B01D46A517A2991... \
  --output alice-pqc.cert
```

Export to stdout (for piping):

```bash
sigmund export-cert --fingerprint D62AAB339E45E5EA2FD036872B01D46A517A2991...
```

The exported certificate can be shared with others so they can verify signatures you create. Recipients import the certificate into their keyring using:

```bash
sq cert import < alice-pqc.cert
```

---

## Configuration File

The CLI reads `sigmund.yaml` from the current directory (or the path specified by `--config`) to determine tool settings and defaults. This is the same configuration file used by the Maven plugin.

Example `sigmund.yaml` for CLI usage:

```yaml
signing:
  toolchain: [sq, gpg]

discovery:
  toolchain: [bc, sq, gpg]

tools:
  sq:
    signing-fingerprint: D62AAB339E45E5EA2FD036872B01D46A517A2991...
    home: ~/.local/share/sequoia
  
  gpg:
    key-name: alice@example.com
```

See [configuration.md](configuration.md) for full configuration reference.

## CLI vs Maven Plugin

| Use Case | Tool | Reason |
|----------|------|--------|
| Sign artifacts during Maven build | Maven plugin | Integrates with Maven lifecycle, automatic artifact handling |
| Verify dependencies during build | Maven plugin | Access to Maven dependency graph and repositories |
| Inspect signing configuration | Both | `sigmund:signer-info` or `sigmund signer-info` |
| Generate signing keys | CLI | One-time key management task |
| Sign individual files | CLI | No Maven project needed |
| Export certificates | CLI | Key management utility |
| Custom signing pipelines | CLI | Script-friendly command-line interface |

For most development workflows, use the Maven plugin. The CLI complements the plugin by handling key management and enabling standalone signing workflows.
