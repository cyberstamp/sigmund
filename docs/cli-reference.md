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

Download `sigmund.jar` from the [latest GitHub release](https://github.com/cyberstamp/sigmund/releases/latest).

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
| `--config <path>` | Path to `sigmund.yaml` configuration file (default: `sigmund.yaml` in the current directory, else `~/.config/sigmund/sigmund.yaml`; without either, commands run without configuration). A named file that does not exist is an error. |
| `--help` | Display help information for the command |
| `--version` | Display Sigmund version |

All commands read `sigmund.yaml` from the current directory, else `~/.config/sigmund/sigmund.yaml`, unless `--config` names a file. Parent directories are not searched. Command-line options override configuration file values.

## Commands

### `sigmund keygen`

Generate a new Bouncy Castle (`bc`) signing key. bc has no command-line tool of its own; keys for `sq` and `gpg` are generated with those tools (`sq key generate`, `gpg --quick-gen-key`), which also cover passphrases, expiry and profiles — see [Generating a PQC Key](signing.md#generating-a-pqc-key).

```bash
sigmund keygen --userid <USER_ID> [options]
```

**Options:**

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--userid` | Yes | — | User ID in canonical form (e.g., `"Alice <alice@example.com>"`) |
| `--cipher-suite` | No | `tools.bc.cipher-suite`, else `ed25519` | Cipher suite for the key |
| `--credential-type` | No | `pgp4` | Key version: `pgp4` or `pgp6`. v4 is the default — the version keyservers serve and GnuPG signs with; v6 is available for `ed25519`, `ed448` (v6 only) and `rsa4096`; ECDSA suites are v4 only |
| `--passphrase-env` | No | `SIGMUND_BC_PASSPHRASE` | Environment variable containing the key passphrase |

**Bouncy Castle cipher suites:** `ed25519`, `ed448`, `rsa4096`, `nistp256`, `nistp384`, `nistp521`

**Examples:**

Generate a classic Ed25519 key using Bouncy Castle (v4, publishable on keys.openpgp.org and usable by GnuPG):

```bash
sigmund keygen --userid "Alice <alice@example.com>" --cipher-suite ed25519
```

Generate a v6 Ed25519 key using Bouncy Castle:

```bash
sigmund keygen --userid "Alice <alice@example.com>" --credential-type pgp6
```

Generate a passphrase-protected BC key:

```bash
export SIGMUND_BC_PASSPHRASE="my-secure-passphrase"
sigmund keygen --userid "Alice <alice@example.com>"
```

The command outputs the fingerprint of the generated key. Name it under `tools.bc.signing-fingerprint` to sign with it, and publish its public certificate with [`sigmund export-cert`](#sigmund-export-cert).

---

### `sigmund signer-info`

Display the effective signing configuration and signer identities without performing any signing.

```bash
sigmund signer-info [options]
```

**Options:**

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--profile` | No | — | One of `signing.profiles`: its credential types choose the keys shown. Without it, `signing.credential-types` chooses them, or every key is shown |
| `--sq-home` | No | — | Sequoia home directory: overrides `tools.sq.home`; unset, sq uses `SEQUOIA_HOME` or its own default |

**Examples:**

```bash
# Show default signing configuration
sigmund signer-info

# Show configuration for a specific profile
sigmund signer-info --profile hybrid
```

**Output:**

```
gpg: pgp4 RSA 41A2197725BD63EB00D071D46A7F5DB1C68BDB81 (Alice <alice@example.com>)
sq: pgp6 ML-DSA-87+Ed448 D62AAB339E45E5EA2FD036872B01D46A517A2991... (Alice <alice@example.com>)
```

When the signing plan has problems, such as a profile requesting a credential type no key covers, `signer-info` prints each problem on its own line after the keys, as `Problem: <message>`, and exits with status 1:

```
Profile: hybrid
sq: pgp4 A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2
Problem: no signing key for requested credential type pgp6; keys in the run: sq pgp4
```

---

### `sigmund sign`

Sign an artifact with the keys the signing plan selects: `signing.toolchain` names the tools, each tool's `tools.<name>` settings name its keys, and `--profile`, or `signing.credential-types`, chooses which of them sign. See [Signing](signing.md).

```bash
sigmund sign --file <FILE> [options]
```

**Options:**

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--file` | Yes | — | Artifact file to sign |
| `--profile` | No | — | One of `signing.profiles`: its credential types choose the keys that sign. Without it, `signing.credential-types` chooses them, or every key signs |
| `--sq-home` | No | — | Sequoia home directory: overrides `tools.sq.home`; unset, sq uses `SEQUOIA_HOME` or its own default |
| `--output` | No | `<file>.asc` | Output signature file path |

**Example:**

Sign an artifact:

```bash
sigmund sign --file target/my-artifact-1.0.jar
```

The command creates a `.asc` signature file next to the artifact (or at the path specified by `--output`). Signing keys and passphrases are configured in `sigmund.yaml`.

---

### `sigmund verify-signature`

Verify each signature in an artifact's signature file — every block of an `.asc`, or a Sigstore bundle — with the tools `verification.toolchain` names, in order.

```bash
sigmund verify-signature --file <FILE> --signature <ASC> [options]
```

**Options:**

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--file` | Yes | — | Artifact file to verify |
| `--signature` | Yes | — | Signature file: `.asc` or `.sigstore.json` |
| `--sq-home` | No | — | Sequoia home directory: overrides `tools.sq.home`; unset, sq uses `SEQUOIA_HOME` or its own default |
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
  [1] VERIFIED (EdDSA) [key: 8B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C] [signer: Alice <alice@example.com>]
  [2] VERIFIED (ML-DSA-87+Ed448) [key: D62AAB339E45E5EA2FD036872B01D46A517A29911A2B3C4D5E6F7A8B9C0D1E2F] [signer: Alice <alice@example.com>]
  Overall: 2 VERIFIED
```

Blocks are listed in file order, classic first. `key` is the key that verified the block — often a signing subkey, so it can differ from the primary fingerprint your key is known by.

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
| `<identifier>` | Yes | — | Signer identifier: a full fingerprint or an email, auto-detected |
| `--fingerprint` | No | — | Treat identifier as a fingerprint |
| `--email` | No | — | Treat identifier as an email |
| `--keyservers`, `--keyserver` | No | `verification.keyservers`, else `hkps://keys.openpgp.org` | Keyservers to query, comma-separated; giving them turns fetching on even when `resolve-signers` is `false` |
| `--tool` | No | all | Restrict inspection to a specific tool (`bc`, `sq`, `gpg`) |
| `--sq-home` | No | — | Sequoia home directory: overrides `tools.sq.home`; unset, sq uses `SEQUOIA_HOME` or its own default |

A Sigstore keyless identity has no key material to look up, so it cannot be inspected.

**Examples:**

Inspect a fingerprint:

```bash
sigmund inspect-signer 4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12
```

Inspect an email:

```bash
sigmund inspect-signer alice@example.com
```

---

### `sigmund export-cert`

Export the public certificate of a key Bouncy Castle holds — typically one `sigmund keygen` generated — so you can publish it (to keys.openpgp.org, say) and others can verify what you sign. It looks in the stores `tools.bc` names in `sigmund.yaml`, as `keygen` does. For keys sq or gpg hold, use `sq cert export` or `gpg --export`.

```bash
sigmund export-cert --fingerprint <FP> [options]
```

**Options:**

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--fingerprint` | Yes | — | Fingerprint of the key whose certificate to export |
| `--output`, `-o` | No | stdout | Output file path |

**Example:**

Export a certificate to a file:

```bash
sigmund export-cert --fingerprint 4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12 \
  --output alice.asc
```

Export to stdout (for piping):

```bash
sigmund export-cert --fingerprint 4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12
```

The file holds the public key only, ASCII-armored, ready to upload to a keyserver or to hand to someone who imports it with `gpg --import alice.asc` or `sq cert import alice.asc`.

---

## Configuration File

The CLI reads `sigmund.yaml` from the current directory, else `~/.config/sigmund/sigmund.yaml` (or the file `--config` names) to determine tool settings and defaults. This is the same configuration file used by the Maven plugin.

Example `sigmund.yaml` for CLI usage:

```yaml
signing:
  toolchain: [sq, gpg]

verification:
  toolchain: [bc, sq, gpg]

tools:
  sq:
    signing-fingerprint: "D62AAB339E45E5EA2FD036872B01D46A517A29911A2B3C4D5E6F7A8B9C0D1E2F"
    home: ~/.local/share/sequoia
  
  gpg:
    signing-fingerprint: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
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
