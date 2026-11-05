# Migrating from maven-gpg-plugin

This guide helps you migrate from `maven-gpg-plugin` to Sigmund's Maven plugin. Sigmund is a superset of `maven-gpg-plugin` — it provides the same GPG signing capabilities plus dependency trust verification, hybrid post-quantum cryptography (PQC), and multiple signing backends.

## Contents

- [Why migrate](#why-migrate)
- [Feature comparison](#feature-comparison)
- [Security comparison](#security-comparison)
- [Step-by-step migration](#step-by-step-migration)
  - [1. Replace the plugin](#1-replace-the-plugin)
  - [2. Configuration mapping](#2-configuration-mapping)
  - [3. Passphrase handling](#3-passphrase-handling)
  - [4. Verify existing GPG-signed artifacts](#4-verify-existing-gpg-signed-artifacts)
  - [5. (Optional) Add PQC hybrid signing](#5-optional-add-pqc-hybrid-signing)
- [Maven Central compatibility](#maven-central-compatibility)
- [CI/CD considerations](#cicd-considerations)
  - [GPG key import](#gpg-key-import)
  - [Passphrase in CI](#passphrase-in-ci)
  - [Skipping signing](#skipping-signing)
- [Configuration with sigmund.yaml](#configuration-with-sigmundyaml)
- [Troubleshooting](#troubleshooting)
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

Sigmund offers everything `maven-gpg-plugin` does, plus:

- **Dependency trust verification** — enforce that dependencies are signed by known trusted parties
- **Post-quantum cryptography** — add quantum-resistant ML-DSA signatures alongside classic GPG signatures
- **Multiple signing backends** — use GPG, Bouncy Castle, or Sequoia sq interchangeably
- **Signing profiles** — configure different signing strategies per project
- **Trust policies** — declare which signers are trusted for which artifacts

**Drop-in replacement:** For basic GPG signing, Sigmund works exactly like `maven-gpg-plugin` with minimal configuration changes.

## Feature comparison

| Feature | maven-gpg-plugin | sigmund-maven-plugin |
|---------|------------------|----------------------|
| GPG signing (v4 signatures) | Yes | Yes |
| Signature verification | No | Yes |
| Dependency trust verification | No | Yes |
| PQC hybrid signing (v6 + ML-DSA) | No | Yes |
| Multiple signing backends | No | Yes (GPG, BC, Sequoia) |
| Key generation | No | Yes (CLI) |
| Signing profiles | No | Yes (`sigmund.yaml`) |
| Trust policies | No | Yes (`sigmund.yaml`) |

## Security comparison

| Dimension | maven-gpg-plugin | sigmund-maven-plugin |
|-----------|------------------|----------------------|
| **Passphrase handling** | `gpg.passphrase` Maven property — the secret appears in process listings (`ps aux`), Maven debug output, and CI build logs. Alternatively, requires manual `gpg-agent` loopback setup. | Reads the passphrase from `SIGMUND_GPG_PASSPHRASE` env var by default (no config needed). Sigmund handles `--passphrase-fd` and `--pinentry-mode loopback` automatically. Falls back to `gpg-agent` when the env var is not set. |
| **Key material in memory** | GPG runs as a separate process; `gpg-agent` can use `mlock` to pin key material in RAM | Same — Sigmund delegates to the same `gpg` process with the same memory model. |
| **Supply chain verification** | Signing only — no way to verify who signed your dependencies | Dependency trust verification and enforcement |
| **Quantum resistance** | None | Hybrid ML-DSA + classic signatures (RFC 9980) |

When using the GPG backend, the signing security model is identical to `maven-gpg-plugin` — Sigmund delegates to the same `gpg` process. For high-security environments that rely on hardware tokens or `gpg-agent`'s memory protections, the GPG backend preserves those guarantees.

## Step-by-step migration

### 1. Replace the plugin

**Before (maven-gpg-plugin):**

```xml
<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-gpg-plugin</artifactId>
  <version>3.2.8</version>
  <executions>
    <execution>
      <id>sign-artifacts</id>
      <phase>verify</phase>
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
      <id>sign-artifacts</id>
      <phase>verify</phase>
      <goals>
        <goal>sign</goal>
      </goals>
    </execution>
  </executions>
</plugin>
```

Both plugins bind to the `verify` phase by default and sign all project artifacts (main JAR/WAR, POM, sources, javadoc).

### 2. Configuration mapping

Map your existing `maven-gpg-plugin` properties to Sigmund equivalents:

| maven-gpg-plugin property | Sigmund equivalent | Notes |
|---------------------------|-------------------|-------|
| `gpg.keyname` | `sigmund.yaml` → `tools.gpg.signing-fingerprint` | The key's full fingerprint; a key ID or email is not accepted, since it can match more than one key. Configured in `sigmund.yaml`, not as a Maven property. |
| `gpg.passphrase` | `sigmund.yaml` → `tools.gpg.passphrase-env` | Env var name, not the passphrase itself. See [Passphrase handling](#3-passphrase-handling). |
| `gpg.executable` | `sigmund.yaml` → `tools.gpg.executable` | Path to GPG binary. Set in config file, not as Maven property. |
| `gpg.skip` | `sigmund.skip` | Skip signing when `true`. |
| `gpg.useagent` | Implicit | Sigmund always uses GPG agent when no `passphrase-env` is configured. |

**Example: specifying GPG key in sigmund.yaml**

```yaml
tools:
  gpg:
    signing-fingerprint: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
```

**Example: skipping signing**

```bash
mvn verify -Dsigmund.skip=true
```

### 3. Passphrase handling

Sigmund invokes `gpg` as an external process. GPG uses its agent for passphrase handling.

**Desktop (interactive):** GPG agent prompts for the passphrase via pinentry and caches it. No extra configuration needed.

**Headless / CI:** Set the `SIGMUND_GPG_PASSPHRASE` environment variable. Sigmund checks it by default — no `sigmund.yaml` change needed. When set, Sigmund passes the passphrase to GPG via `--passphrase-fd` with `--pinentry-mode loopback`:

```bash
export SIGMUND_GPG_PASSPHRASE=mysecret
mvn sigmund:sign
```

To reuse an existing env var (e.g., `GPG_PASSPHRASE` from your current CI setup), set `passphrase-env` in `sigmund.yaml`:

```yaml
tools:
  gpg:
    passphrase-env: GPG_PASSPHRASE
```

**Headless / CI (alternative):** If you prefer to use `gpg-agent` directly, configure it for non-interactive passphrase input:

1. Add to `~/.gnupg/gpg-agent.conf`:

   ```
   allow-loopback-pinentry
   allow-preset-passphrase
   ```

2. Add to `~/.gnupg/gpg.conf`:

   ```
   pinentry-mode loopback
   ```

3. Reload the agent and cache the passphrase:

   ```bash
   gpg-connect-agent reloadagent /bye
   echo "$GPG_PASSPHRASE" | gpg --batch --pinentry-mode loopback --passphrase-fd 0 --sign /dev/null
   mvn sigmund:sign
   ```

   **Security note:** `allow-loopback-pinentry` lets any process with access to the `gpg-agent` socket supply passphrases programmatically, bypassing the pinentry UI. This is the standard approach for CI but should not be enabled on shared machines where untrusted processes run.

### 4. Verify existing GPG-signed artifacts

After switching to Sigmund, verify that it can correctly verify artifacts you signed with `maven-gpg-plugin`:

```bash
mvn sigmund:verify-signature \
  -Dfile=target/myproject-1.0.jar \
  -Dsignature=target/myproject-1.0.jar.asc
```

### 5. (Optional) Add PQC hybrid signing

Once you have a PQC key, Sigmund automatically creates hybrid signatures — each `.asc` file contains two armored blocks:

1. **Classic signature** (v4 RSA, EdDSA, or ECDSA) — backward-compatible with Maven Central and all existing GPG tools
2. **PQC signature** (v6 ML-DSA-87+Ed448 or ML-DSA-65+Ed25519) — quantum-resistant, per [RFC 9980](https://datatracker.ietf.org/doc/rfc9980/)

The classic signature comes first, so tools that read only the first block — Maven Central, `sq verify` — see and verify it. Sigmund verifies both.

See the [signing guide](signing.md) for details on generating PQC keys and configuring hybrid signing.

## Maven Central compatibility

Hybrid `.asc` files are fully backward compatible with Maven Central. The `.asc` file structure:

```
-----BEGIN PGP SIGNATURE-----
<classic v4 signature>
-----END PGP SIGNATURE-----
-----BEGIN PGP SIGNATURE-----
<PQC v6 signature>
-----END PGP SIGNATURE-----
```

Maven Central's upload validation:

1. Parses the first armored block (classic v4 signature)
2. Verifies the classic signature against keyservers
3. Ignores subsequent blocks (the PQC signature)
4. Accepts the upload

No changes to Maven Central infrastructure are required.

## CI/CD considerations

### GPG key import

Import your GPG key in CI:

```bash
echo "$GPG_PRIVATE_KEY" | gpg --batch --import
```

### Passphrase in CI

Set `SIGMUND_GPG_PASSPHRASE` as a CI secret. Sigmund checks it by default — no `sigmund.yaml` change needed:

```bash
export SIGMUND_GPG_PASSPHRASE="$GPG_SECRET"
mvn sigmund:sign
```

To reuse an existing CI secret variable under a different name, set `passphrase-env` in `sigmund.yaml`:

```yaml
tools:
  gpg:
    passphrase-env: GPG_PASSPHRASE
```

### Skipping signing

```bash
mvn verify -Dsigmund.skip=true
```

## Configuration with sigmund.yaml

For more control, create a `sigmund.yaml` file in your project root:

```yaml
tools:
  gpg:
    signing-fingerprint: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
    passphrase-env: GPG_PASSPHRASE
```

Maven properties (e.g. `sigmund.sqHome`) override `sigmund.yaml` values where applicable.

## Troubleshooting

### "GPG signing failed" or "Cannot find GPG key"

Check that your GPG key exists:

```bash
gpg --list-secret-keys
```

If the key exists, specify its full fingerprint explicitly:

```yaml
# sigmund.yaml
tools:
  gpg:
    signing-fingerprint: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
```

### Hybrid signatures fail Maven Central upload

This should not happen — hybrid signatures are backward-compatible. Maven Central only validates the first (classic) signature block. If you encounter issues:

1. Verify the classic signature separately:

   ```bash
   gpg --verify artifact.jar.asc artifact.jar
   ```

2. Check that the classic signature comes first in the `.asc` file:

   ```bash
   head -20 artifact.jar.asc
   ```

3. Report the issue at https://github.com/cyberstamp/sigmund/issues

## Next steps

- **Verify dependencies:** Use `mvn sigmund:verify` to enforce trust policies on your dependencies — see [Trust Verification](trust-verification.md)
- **Advanced signing:** Configure multiple signing backends and profiles — see [Signing Guide](signing.md)
- **Check signing config:** Use `mvn sigmund:signer-info` to display effective signing configuration
