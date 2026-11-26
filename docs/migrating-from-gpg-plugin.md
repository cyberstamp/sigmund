# Migrating from maven-gpg-plugin

This guide helps you migrate from `maven-gpg-plugin` to Sigmund's Maven plugin. Both sign a project's artifacts with OpenPGP keys; Sigmund adds verification of dependency signatures against a trust policy, hybrid post-quantum (PQC) signing with Sequoia, and Sigstore. The comparison below is against `maven-gpg-plugin` 3.2.8.

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
>       <version>0.0.3</version>
>     </plugin>
>   </plugins>
> </pluginManagement>
> ```
>
> Alternatively, replace `sigmund` with the full plugin coordinates, e.g.:
> `mvn dev.cyberstamp.sigmund:sigmund-maven-plugin:0.0.3:sign`

## Why migrate

`maven-gpg-plugin` signs; Sigmund signs and verifies. Consider it when you want:

- **Dependency trust verification** — enforce that dependencies are signed by the signers you name
- **Post-quantum cryptography** — an ML-DSA signature alongside the classic one, in the same `.asc`
- **Sigstore** — keyless signing from CI, alongside or instead of OpenPGP
- **A checked signer** — `signing.signer` fails the build when a signature does not prove the identity you sign as

For plain GnuPG signing, the change is the plugin coordinates plus moving a few settings into `sigmund.yaml`.

## Feature comparison

| Feature | maven-gpg-plugin | sigmund-maven-plugin |
|---------|------------------|----------------------|
| OpenPGP v4 signing | Yes | Yes |
| Signing backends | GnuPG, Bouncy Castle (`gpg.signer`) | GnuPG, Bouncy Castle, Sequoia `sq` |
| Signing key from an environment variable | Yes (`MAVEN_GPG_KEY`, Bouncy Castle signer) | Yes (`SIGMUND_BC_SIGNING_KEY`, Bouncy Castle) |
| Passphrase from an environment variable | Yes (`MAVEN_GPG_PASSPHRASE`) | Yes (`SIGMUND_GPG_PASSPHRASE`, `SIGMUND_BC_PASSPHRASE`) |
| PQC hybrid signing (v6 + ML-DSA) | No | Yes, with `sq` |
| Sigstore signing | No | Yes, with `sigmund-sigstore` |
| Signature verification | No | Yes |
| Dependency trust verification | No | Yes |
| Key generation | No | Yes (CLI) |
| Extra `gpg` arguments, lock mode, file excludes | Yes (`gpgArguments`, `lockMode`, `excludes`) | No |

## Security comparison

| Dimension | maven-gpg-plugin | sigmund-maven-plugin |
|-----------|------------------|----------------------|
| **Passphrase handling** | Read from `MAVEN_GPG_PASSPHRASE` by default, else from `gpg-agent`. The `gpg.passphrase` and `passphraseServerId` parameters are deprecated, and `bestPractices` makes using them a build failure. | Read from `SIGMUND_GPG_PASSPHRASE` by default, else from `gpg-agent`. A passphrase cannot be set in the POM or `sigmund.yaml`, only by naming an environment variable. |
| **Key material in memory** | With the GnuPG signer, keys stay in `gpg`/`gpg-agent` | The same with the GnuPG backend: Sigmund runs the same `gpg` process |
| **Supply chain verification** | Signing only | Dependency trust verification and enforcement |
| **Quantum resistance** | None | Hybrid ML-DSA + classic signatures (RFC 9980) |

With the GnuPG backend, signing works as with `maven-gpg-plugin`'s GnuPG signer: Sigmund runs the same `gpg` process, so hardware tokens and `gpg-agent`'s protections keep working.

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
  <version>0.0.3</version>
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
| `gpg.keyname` | `sigmund.yaml` → `tools.gpg.signing-fingerprint` | The key's full fingerprint; a key ID or email is not accepted, since it can match more than one key. |
| `gpg.passphraseEnvName` | `sigmund.yaml` → `tools.gpg.passphrase-env` | Defaults differ: `MAVEN_GPG_PASSPHRASE` versus `SIGMUND_GPG_PASSPHRASE`. Set `passphrase-env: MAVEN_GPG_PASSPHRASE` to keep your CI secret as it is. |
| `gpg.passphrase`, `gpg.passphraseServerId` | `sigmund.yaml` → `tools.gpg.passphrase-env` | Not supported; name an environment variable instead. See [Passphrase handling](#3-passphrase-handling). |
| `gpg.executable` | `sigmund.yaml` → `tools.gpg.executable` | Path to the GnuPG binary. |
| `gpg.homedir` | `sigmund.gpgHome`, or `sigmund.yaml` → `tools.gpg.home` | GnuPG home directory. |
| `gpg.skip` | `sigmund.skip` | Skip signing when `true`. |
| `gpg.useagent` | Implicit | Sigmund uses `gpg-agent` whenever no passphrase environment variable is set. |
| `gpg.signer=bc` with `gpg.keyEnvName` / `gpg.keyFilePath` | `signing.toolchain: [bc]` with `tools.bc.signing-key-env` / `tools.bc.tsk-file` | Sigmund's Bouncy Castle signer reads `SIGMUND_BC_SIGNING_KEY` by default; its passphrase comes from `SIGMUND_BC_PASSPHRASE`, not from `gpg-agent`. |
| `gpg.keyFingerprint` | `sigmund.yaml` → `tools.bc.signing-fingerprint` | Ignored when the key comes from an environment variable or file, which sign with their first key. |

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

Maven properties override `sigmund.yaml` values where both exist, such as `-Dsigmund.gpgHome` over `tools.gpg.home`.

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
