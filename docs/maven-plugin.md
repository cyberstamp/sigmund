# Maven Plugin Reference

The Sigmund Maven plugin provides goals for signing artifacts and verifying dependency signatures.

## Contents

- [Plugin Coordinates](#plugin-coordinates)
- [Enabling Sigstore Support](#enabling-sigstore-support)
- [Goals](#goals)
  - [sigmund:sign](#sigmundsign)
  - [sigmund:signer-info](#sigmundsigner-info)
  - [sigmund:verify](#sigmundverify)
  - [sigmund:verify-signature](#sigmundverify-signature)
  - [sigmund:dependency-signers](#sigmunddependency-signers)
  - [sigmund:inspect-signer](#sigmundinspect-signer)
- [Configuration Precedence](#configuration-precedence)
- [CI/CD Integration](#cicd-integration)
  - [Passphrases](#passphrases)
  - [Ephemeral CI Runners](#ephemeral-ci-runners)
  - [Skipping Verification](#skipping-verification)

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

## Plugin Coordinates

```xml
<plugin>
  <groupId>dev.cyberstamp.sigmund</groupId>
  <artifactId>sigmund-maven-plugin</artifactId>
  <version>0.0.2</version>
  <executions>
    <execution>
      <goals>
        <goal>verify</goal>
      </goals>
      <phase>verify</phase>
    </execution>
  </executions>
</plugin>
```

## Enabling Sigstore Support

The Maven plugin does not include Sigstore support by default. To enable it, add `sigmund-sigstore` as a plugin dependency:

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
</plugin>
```

Once on the classpath, `SigstoreToolFactory` is discovered automatically via `ServiceLoader`. No additional configuration is needed — Sigstore signing and verification are available to all plugin goals.

For the CLI, Sigstore support is bundled automatically.

## Goals

### sigmund:sign

**Default Phase:** `verify`

Signs all project artifacts (JAR, POM, sources, javadoc) with hybrid GPG and PQC signatures, and attaches the `.asc` files for deployment.

**Parameters:**

| Property | Required | Default | Description |
|----------|----------|---------|-------------|
| `sigmund.sqHome` | No | `~/.local/share/sequoia` | Sequoia keystore directory |
| `sigmund.skip` | No | `false` | Skip signing |

**Configuration:**

Tool-specific settings (key fingerprints, passphrases) are configured in `sigmund.yaml`. See [Configuration Reference](configuration.md).

### sigmund:signer-info

**Default Phase:** none (standalone goal)

Displays the effective signing configuration and signer identities without performing any signing. Useful for verifying which keys and tools will be used before a signing operation.

**Parameters:**

| Property | Required | Default | Description |
|----------|----------|---------|-------------|
| `sigmund.profile` | No | default profile | Signing profile to display |
| `sigmund.sqHome` | No | `~/.local/share/sequoia` | Sequoia keystore directory |
| `sigmund.skip` | No | `false` | Skip this goal |

**Examples:**

```bash
# Show default signing configuration
mvn sigmund:signer-info

# Show configuration for a specific profile
mvn sigmund:signer-info -Dsigmund.profile=hybrid
```

**Output:**

```
gpg: RSA 41A2197725BD63EB00D071D46A7F5DB1C68BDB81 (Alice <alice@example.com>)
sq: ML-DSA-87+Ed448 D62AAB339E45E5EA2FD036872B01D46A517A2991... (Alice <alice@example.com>)
```

### sigmund:verify

**Default Phase:** `validate`

Verifies that all project dependencies are signed by trusted signers as defined in `sigmund.yaml`. Matching is done by fingerprint when available, falling back to email. Artifacts listed in the `signature-optional` section are allowed to carry no signature.

**Parameters:**

| Property | Required | Default | Description |
|----------|----------|---------|-------------|
| `sigmund.trustConfig` | No | `${project.basedir}/sigmund.yaml` | Path to the trust configuration file |
| `sigmund.onUntrusted` | No | — | Policy for untrusted artifacts: `fail` or `warn`. Overrides config file setting. |
| `sigmund.listedEvidence` | No | — | Overrides `policy.listed-evidence` in `sigmund.yaml`. Values: `all` (all listed evidence must match) or `any` (at least one match sufficient). |
| `sigmund.resolveSigners` | No | `true` | Fetch unknown GPG keys from keyservers. Overrides config file setting. |
| `sigmund.keyservers` | No | `hkps://keys.openpgp.org` | Comma-separated keyserver list. Used when `resolveSigners` is enabled. |
| `sigmund.verifyPomFiles` | No | `false` | Also verify signatures on POM files for each dependency |
| `sigmund.detail` | No | `false` | Add the credentials proven and the trust root to each attester group, and the evidence file and claim time to each artifact. Results are grouped by outcome and then by attester either way |
| `sigmund.sqHome` | No | `~/.local/share/sequoia` | Sequoia keystore directory |
| `sigmund.gpgHome` | No | — | GnuPG home directory, overrides GPG and BC home paths |
| `sigmund.importToKeyring` | No | — | Persist fetched keys to keyrings. Overrides config file setting. |
| `sigmund.includeTestDependencies` | No | `false` | Include test-scoped dependencies |
| `sigmund.skip` | No | `false` | Skip verification |

**Example:**

```bash
mvn sigmund:verify
```

**Output:**

Results are grouped by outcome, and within an outcome by who attested them, so a
dependency tree signed by a handful of signers reads as a handful of blocks:

```
SATISFIED (2)
  openpgp VERIFIED by bc (Ed25519) - Jane Doe <jane@example.com>
    com.example:lib:1.0
    com.example:lib-b:2.0

UNSATISFIED (1)
  openpgp VERIFIED by gpg (RSA) - Unknown <unknown@example.com>
    com.other:tool:3.0

NO_CLAIM (1)
    org.wildfly.common:wildfly-common:2.0.1
```

Artifacts nothing attested carry no group header. When an outcome blocks, the
build fails naming each artifact and its outcome:

```
Verification blocked the build for 1 artifact(s): com.other:tool:3.0 (UNSATISFIED)
```

With `-Dsigmund.detail`, each group also states what it proved and what it was
checked against, and each artifact the evidence it was read from:

```
SATISFIED (2)
  openpgp VERIFIED by bc (Ed25519) - Jane Doe <jane@example.com>
    credential openpgp4 DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF
    trust root openpgp-keyring /home/jane/.local/share/pgp.cert.d
    com.example:lib:1.0
      evidence lib-1.0.jar.asc sha256:ba7816bf8f01 (sidecar)
      claimed 2026-03-12T10:04:11Z (signer)
```

See [Outcomes](trust-verification.md#outcomes) for what each outcome means.

See [Trust Verification](trust-verification.md) for details on the `sigmund.yaml` format.

### sigmund:verify-signature

**Default Phase:** none (standalone goal)

Verifies a single signed artifact without requiring a project. This is a standalone verification tool that can be used to verify any artifact/signature pair.

**Parameters:**

| Property | Required | Default | Description |
|----------|----------|---------|-------------|
| `file` | Yes | — | Artifact file to verify |
| `signature` | Yes | — | Signature `.asc` file |
| `sigmund.sqHome` | No | `~/.local/share/sequoia` | Sequoia keystore directory |
| `sigmund.lenient` | No | `false` | Pass if at least one signature is valid and none failed |

**Example:**

```bash
mvn dev.cyberstamp.sigmund:sigmund-maven-plugin:0.0.2:verify-signature \
  -Dfile=artifact.jar \
  -Dsignature=artifact.jar.asc
```

In **lenient mode** (`sigmund.lenient=true`), the goal passes if at least one signature is valid and no signatures are invalid. In strict mode (default), all signatures must pass.

### sigmund:dependency-signers

**Default Phase:** `validate`

Reports signer information for all project dependencies by downloading and inspecting their `.asc` signature files. Each armored block is reported separately with its OpenPGP version (v4 for classical GPG, v6 for PQC).

Dependencies are grouped by signer, sorted alphabetically. Unsigned artifacts and unverified signatures are reported separately.

**Parameters:**

| Property | Required | Default | Description |
|----------|----------|---------|-------------|
| `sigmund.trustConfig` | No | `${project.basedir}/sigmund.yaml` | Path to the trust configuration file |
| `sigmund.resolveSigners` | No | `true` | Fetch unknown GPG keys from keyservers to resolve signer identities |
| `sigmund.keyservers` | No | `hkps://keys.openpgp.org` | Comma-separated list of keyservers for fetching GPG keys |
| `sigmund.sqHome` | No | `~/.local/share/sequoia` | Sequoia keystore directory for PQC cert lookup |
| `sigmund.gpgHome` | No | — | GnuPG home directory, overrides GPG and BC home paths |
| `sigmund.importToKeyring` | No | — | Persist fetched keys to keyrings. Overrides config file setting. |
| `sigmund.includeTestDependencies` | No | `false` | Include test-scoped dependencies |
| `sigmund.generateTrustConfig` | No | — | Generate a `sigmund.yaml`. Set to `true` to write to the project root, or provide a file path. Fails if the file already exists unless `sigmund.overwrite=true`. |
| `sigmund.overwrite` | No | `false` | Allow overwriting an existing generated trust config file |
| `sigmund.updateTrustConfig` | No | — | Update an existing `sigmund.yaml` by appending unconfigured signers and artifacts. Set to `true` for the default location, or provide a file path. |
| `sigmund.skip` | No | `false` | Skip the report |

**Examples:**

```bash
# Report signers
mvn sigmund:dependency-signers

# Generate sigmund.yaml from actual signatures
mvn sigmund:dependency-signers \
  -Dsigmund.generateTrustConfig=true \
  -Dsigmund.resolveSigners=true

# Update an existing sigmund.yaml with newly added dependencies
mvn sigmund:dependency-signers \
  -Dsigmund.updateTrustConfig=true \
  -Dsigmund.resolveSigners=true
```

**Output:**

```
Signer: Alice Developer <alice@example.com>
   PGP4 (EdDSA): 4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12
     com.example:lib-a:1.0
     com.example:lib-b:2.0

Signer: NOT VERIFIED
   PGP4 (RSA): B2A3CF1E8D4F5A6B7C9D0E1F2A3B4C5D6E7F8A9B
     com.other:tool:3.0

Signer: UNKNOWN (key not in keyring)
   PGP4 (DSA): D1031D14464180E0
     com.internal:messaging:2.1

UNSIGNED
  com.internal:util:1.0

Summary: All clear: 4 dependencies, 3 PGP4 signature(s), 0 PQC signature(s), 2 unique key(s)
```

Many signers appear as `NOT VERIFIED` because the default keyserver (`keys.openpgp.org`) only publishes identity information for keys whose owners have verified their email. See [Why Many Signers Appear as NOT VERIFIED](getting-started.md#why-many-signers-appear-as-not-verified) for details and how to resolve more names using additional keyservers.

**Generating a trust config:**

Use `-Dsigmund.generateTrustConfig=true` to create an initial `sigmund.yaml` from your project's actual dependency signatures. The generated file groups artifacts by signer, collapses common groupId prefixes into wildcard patterns (e.g., `io.quarkus.*`), and lists artifacts with no signature in the `signature-optional` section. The file can be used directly with the `verify` goal.

**Updating a trust config:**

Use `-Dsigmund.updateTrustConfig=true` to add new dependency signers to an existing `sigmund.yaml`. This is useful after adding new dependencies — existing content including comments and formatting is preserved, and new entries are inserted at the end of each section. Review the changes with `git diff`.

### sigmund:inspect-signer

**Default Phase:** none (standalone goal)

Inspects a signer identity across all available sources (local keystores and keyservers). Does not require a project — only needs tool configuration and a signer credential.

**Parameters:**

| Property | Required | Default | Description |
|----------|----------|---------|-------------|
| `sigmund.fingerprint` | No | — | Signer fingerprint to inspect |
| `sigmund.email` | No | — | Signer email to inspect |
| `sigmund.sigstoreIssuer` | No | — | Sigstore certificate OIDC issuer URL |
| `sigmund.sigstoreSubject` | No | — | Sigstore certificate SAN subject |
| `sigmund.tool` | No | all | Restrict inspection to a specific tool (`bc`, `sq`, `gpg`) |
| `sigmund.keyservers` | No | `hkps://keys.openpgp.org` | Comma-separated keyserver list |
| `sigmund.resolveSigners` | No | `true` | Fetch keys from keyservers |
| `sigmund.skip` | No | `false` | Skip this goal |

At least one of `sigmund.fingerprint`, `sigmund.email`, or `sigmund.sigstoreIssuer` + `sigmund.sigstoreSubject` is required.

**Examples:**

```bash
# Inspect a fingerprint
mvn sigmund:inspect-signer -Dsigmund.fingerprint=4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12

# Inspect an email
mvn sigmund:inspect-signer -Dsigmund.email=alice@example.com

# Inspect a Sigstore identity
mvn sigmund:inspect-signer \
  -Dsigmund.sigstoreIssuer=https://token.actions.githubusercontent.com \
  -Dsigmund.sigstoreSubject=https://github.com/org/repo
```

## Configuration Precedence

Maven properties (`-Dsigmund.*`) override `sigmund.yaml` values, which override defaults.

**Properties that override config file settings:**

- `sigmund.onUntrusted` overrides `policy.on-untrusted` in `sigmund.yaml`
- `sigmund.listedEvidence` overrides `policy.listed-evidence` in `sigmund.yaml` (`all` or `any`)
- `sigmund.resolveSigners` overrides `discovery.resolve-signers` in `sigmund.yaml`
- `sigmund.keyservers` overrides `discovery.keyservers` in `sigmund.yaml`

**Example:**

```bash
# Override the failure policy from the config file
mvn verify -Dsigmund.onUntrusted=warn

# Enable fetching unknown keys from keyservers
mvn verify -Dsigmund.resolveSigners=true
```

## CI/CD Integration

### Passphrases

Each backend checks a default environment variable — no `sigmund.yaml` configuration needed:

| Backend | Default env var | Fallback |
|---------|----------------|----------|
| BC | `SIGMUND_BC_PASSPHRASE` | Interactive console prompt |
| GPG | `SIGMUND_GPG_PASSPHRASE` | `gpg-agent` |
| Sigstore | `SIGSTORE_JAVA_ID_TOKEN` (optional) | Ambient OIDC (env var or GitHub Actions) or interactive browser login |

```bash
export SIGMUND_BC_PASSPHRASE="your-passphrase"
mvn sigmund:sign
```

To use a different env var name (e.g., reuse an existing CI secret), set `passphrase-env` in `sigmund.yaml`:

```yaml
signing:
  tools:
    gpg:
      passphrase-env: GPG_PASSPHRASE
```

### Ephemeral CI Runners

For CI runners without persistent key storage, inject the BC signing key via environment variable:

```bash
export SIGMUND_BC_SIGNING_KEY="$CI_SECRET_KEY"
export SIGMUND_BC_PASSPHRASE="$CI_SECRET_PASSPHRASE"
mvn sigmund:sign
```

The key is parsed in memory — no files on disk. See the [Signing Guide](signing.md#ephemeral-ci-signing) for details.

### Skipping Verification

Use `sigmund.skip=true` to skip verification or signing in specific builds:

```bash
mvn verify -Dsigmund.skip=true
```
