# Migrating from sign-maven-plugin

This guide helps you migrate from `sign-maven-plugin` (org.simplify4u.plugins) to Sigmund's Maven plugin. Both sign in pure Java with Bouncy Castle, without an external GnuPG installation; Sigmund adds dependency trust verification, hybrid post-quantum (PQC) signing, and a CLI for key management. The comparison below is against `sign-maven-plugin` 1.2.0.

`sign-maven-plugin` is retired: its maintainers recommend [maven-gpg-plugin](https://maven.apache.org/plugins/maven-gpg-plugin/), which now signs with Bouncy Castle too. If you only need signing, that is the path they suggest; for moving from it to Sigmund, see [Migrating from maven-gpg-plugin](migrating-from-gpg-plugin.md).

## Contents

- [Why migrate](#why-migrate)
- [Feature comparison](#feature-comparison)
- [Security comparison](#security-comparison)
- [Step-by-step migration](#step-by-step-migration)
  - [1. Replace the plugin](#1-replace-the-plugin)
  - [2. Configuration mapping](#2-configuration-mapping)
  - [3. Generate a signing key](#3-generate-a-signing-key)
  - [4. Configure sigmund.yaml](#4-configure-sigmundyaml)
  - [5. Update CI configuration](#5-update-ci-configuration)
  - [6. Verify the migration](#6-verify-the-migration)
- [What you gain](#what-you-gain)
- [Next steps](#next-steps)

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

## Why migrate

Consider Sigmund when you want, beyond signing:

- **Dependency trust verification** — enforce that dependencies are signed by the signers you name
- **Post-quantum cryptography** — an ML-DSA signature alongside the classic one, in the same `.asc`
- **Signing profiles** — switch the credential types a build signs with
- **CLI** — key generation, signing, verification, and certificate export outside Maven

## Feature comparison

| Feature | sign-maven-plugin | sigmund-maven-plugin |
|---------|-------------------|----------------------|
| Pure-Java signing (Bouncy Castle) | Yes | Yes |
| PQC hybrid signing | No | Yes (ML-DSA via Sequoia) |
| Signature verification | No | Yes |
| Dependency trust verification | No | Yes |
| Key from env var | Yes (`SIGN_KEY`) | Yes (`SIGMUND_BC_SIGNING_KEY`) |
| Subkey support | Yes | Yes |
| Key from `settings.xml` (`serverId`) | Yes | No |
| Skip when no key is found | Yes (`skipNoKey`, the default) | No: signing fails |
| Key generation | No | Yes (CLI) |
| Trust policies | No | Yes (`sigmund.yaml`) |

## Security comparison

| Dimension | sign-maven-plugin | sigmund-maven-plugin |
|-----------|-------------------|----------------------|
| **Passphrase handling** | `SIGN_KEY_PASS` env var, POM `<keyPass>` (which can use Maven password encryption), or a `settings.xml` server entry. | Reads from the `SIGMUND_BC_PASSPHRASE` env var by default, or the env var `passphrase-env` names in `sigmund.yaml`, else prompts on a terminal. A passphrase cannot be written in configuration. |
| **Key material on disk** | Optional — `SIGN_KEY` env var avoids key files entirely | Optional — `SIGMUND_BC_SIGNING_KEY` env var avoids key files entirely |
| **Key material in memory** | In-process via Bouncy Castle — key on Java heap, cannot be pinned | Same — Bouncy Castle on Java heap |
| **Supply chain verification** | Signing only | Dependency trust verification and enforcement |
| **Quantum resistance** | None | Hybrid ML-DSA + classic signatures (RFC 9980) |

Both plugins take the signing key from an environment variable for ephemeral CI runners.

## Step-by-step migration

### 1. Replace the plugin

**Before (sign-maven-plugin):**

```xml
<plugin>
  <groupId>org.simplify4u.plugins</groupId>
  <artifactId>sign-maven-plugin</artifactId>
  <version>1.2.0</version>
  <executions>
    <execution>
      <goals>
        <goal>sign</goal>
      </goals>
    </execution>
  </executions>
</plugin>
```

**After (sigmund-maven-plugin):**

```xml
<plugin>
  <groupId>dev.cyberstamp.sigmund</groupId>
  <artifactId>sigmund-maven-plugin</artifactId>
  <version>0.0.2</version>
  <executions>
    <execution>
      <goals>
        <goal>sign</goal>
      </goals>
    </execution>
  </executions>
</plugin>
```

### 2. Configuration mapping

`sign-maven-plugin` uses POM configuration and environment variables. Sigmund uses `sigmund.yaml` for tool-specific settings.

| sign-maven-plugin | Sigmund equivalent | Notes |
|--------------------|-------------------|-------|
| `SIGN_KEY` (env var with key content) | `SIGMUND_BC_SIGNING_KEY` env var | Set `signing-key-env: SIGN_KEY` in `sigmund.yaml` to keep using the same env var name |
| `SIGN_KEY_ID` (env var) | None when the key comes from an environment variable | Sigmund signs with the first key the variable holds; export only the key to sign with |
| `SIGN_KEY_PASS` (env var) | `sigmund.yaml` → `tools.bc.passphrase-env` | Set to `SIGN_KEY_PASS` to keep using the same env var |
| `<keyFile>` (POM), default `~/.m2/sign-key.asc` | `sigmund.yaml` → `tools.bc.tsk-file` | Like the environment variable, signs with the first key the file holds. `signing-fingerprint` selects among keys `sigmund keygen` generated instead |
| `<keyId>` (POM) | `sigmund.yaml` → `tools.bc.signing-fingerprint` | The full fingerprint; selects a key `sigmund keygen` generated, and is ignored with `tsk-file` or a key from the environment |
| `<serverId>` (POM) | None | Use the environment variables instead |
| `sign.skip` | `sigmund.skip` | |
| `<keyPass>` (POM) | `sigmund.yaml` → `tools.bc.passphrase-env` | Env var name, not the passphrase itself. Default: `SIGMUND_BC_PASSPHRASE` |

### 3. Generate a signing key

If you're starting fresh (not reusing an existing key), generate a new BC key:

```bash
sigmund keygen --userid "Your Name <you@example.com>" --cipher-suite ed25519
```

See the [CLI Reference](cli-reference.md) for getting `sigmund`.

Save the fingerprint from the output.

### 4. Configure sigmund.yaml

Create a `sigmund.yaml` in your project root:

```yaml
tools:
  bc:
    signing-fingerprint: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"   # the fingerprint keygen printed
    passphrase-env: SIGN_KEY_PASS
```

You can keep using `SIGN_KEY_PASS` as the environment variable name for a smoother migration.

### 5. Update CI configuration

**Before (sign-maven-plugin):**

```bash
export SIGN_KEY="$(cat private-key.pgp)"
export SIGN_KEY_ID=0xABCD1234
export SIGN_KEY_PASS=mysecret
mvn verify
```

**After (sigmund-maven-plugin) — reuse existing env vars:**

```yaml
# sigmund.yaml
tools:
  bc:
    signing-key-env: SIGN_KEY
    passphrase-env: SIGN_KEY_PASS
```

```bash
export SIGN_KEY="$(cat private-key.pgp)"
export SIGN_KEY_PASS=mysecret
mvn sigmund:sign
```

`SIGN_KEY_ID` is not needed: Sigmund signs with the first key in `SIGN_KEY`.

**After (sigmund-maven-plugin) — use defaults:**

```bash
export SIGMUND_BC_SIGNING_KEY="$(cat private-key.pgp)"
export SIGMUND_BC_PASSPHRASE=mysecret
mvn sigmund:sign
```

No `sigmund.yaml` configuration is needed when using the default env var names. The key is parsed in memory and never written to disk.

### 6. Verify the migration

Check the signing configuration:

```bash
mvn sigmund:signer-info
```

Sign an artifact and verify the signature:

```bash
mvn sigmund:sign
mvn sigmund:verify-signature \
  -Dfile=target/myproject-1.0.jar \
  -Dsignature=target/myproject-1.0.jar.asc
```

## What you gain

After migrating, you can:

- **Verify dependencies:** `mvn sigmund:verify` — enforce that all dependencies are signed by trusted parties
- **Add PQC signatures:** Generate a Sequoia key and configure hybrid signing for quantum resistance
- **Inspect signers:** `mvn sigmund:dependency-signers` — see who signed each dependency

## Next steps

- [Getting Started](getting-started.md) — Dependency trust verification walkthrough
- [Signing Guide](signing.md) — Signing artifacts with Bouncy Castle or hybrid PQC
- [Trust Verification](trust-verification.md) — Enforcing dependency trust policies
