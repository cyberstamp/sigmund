# Migrating from sigstore-maven-plugin

This guide helps you migrate from `sigstore-maven-plugin` (dev.sigstore) to Sigmund's Maven plugin. Both sign keylessly with sigstore-java; Sigmund makes Sigstore one backend among OpenPGP ones, and adds identity checks at signing, bundle and dependency verification, and OpenPGP plus Sigstore signing in one build. The comparison below is against `sigstore-maven-plugin` 2.4.0.

## Contents

- [Why migrate](#why-migrate)
- [Feature comparison](#feature-comparison)
- [Security comparison](#security-comparison)
- [Step-by-step migration](#step-by-step-migration)
  - [1. Replace the plugin](#1-replace-the-plugin)
  - [2. Configuration mapping](#2-configuration-mapping)
  - [3. GitHub Actions workflow](#3-github-actions-workflow)
  - [4. Verify existing Sigstore-signed artifacts](#4-verify-existing-sigstore-signed-artifacts)
  - [5. (Optional) Add OpenPGP signing alongside Sigstore](#5-optional-add-openpgp-signing-alongside-sigstore)
- [Maven Central compatibility](#maven-central-compatibility)
- [Known limitations](#known-limitations)
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

- **Identity checks at signing** — with `signing.signer`, the OIDC token's issuer, and its subject when the signer names one, are checked before Fulcio is asked, and every attribute the signer names is checked on the issued certificate before a signature is written
- **Signature verification** — verify Sigstore bundles (and OpenPGP signatures) from the same tool
- **Dependency trust verification** — enforce that dependencies are signed by the signers you name
- **One identity across formats** — a signer's `email` matches both an OpenPGP key (through an address `keys.openpgp.org` verified for it) and a Sigstore certificate, from the issuers the policy trusts
- **OpenPGP and Sigstore together** — `.asc` and `.sigstore.json` from one `sign` execution, with post-quantum OpenPGP signatures if you want them
- **CLI** — sign, verify, and inspect signatures outside Maven

## Feature comparison

| Feature | sigstore-maven-plugin | sigmund-maven-plugin |
|---------|----------------------|----------------------|
| Sigstore keyless signing | Yes | Yes |
| `.sigstore.json` bundle output | Yes | Yes |
| Staging instance support | Yes (`public-staging`) | Yes (`tools.sigstore.staging`) |
| Identity checked at signing time | No | Yes, with `signing.signer` |
| Sigstore bundle verification | No | Yes |
| OpenPGP signing | No | Yes (GPG, Bouncy Castle, Sequoia) |
| Hybrid OpenPGP + Sigstore signing | No | Yes |
| PQC hybrid signing | No | Yes (ML-DSA via Sequoia) |
| Dependency trust verification | No | Yes |
| Custom trusted root for verification | — (no verification) | Yes (`tools.sigstore.trusted-root`) |
| File excludes | Yes (`excludes`) | No |
| Interactive browser OIDC flow | On, unless `CI=true` | Opt-in (`tools.sigstore.interactive`) |
| CLI tool | No | Yes |
| Pure Java (no external CLI) | Yes | Yes (Sigstore backend) |

## Security comparison

| Dimension | sigstore-maven-plugin | sigmund-maven-plugin |
|-----------|----------------------|----------------------|
| **OIDC identity validation** | None — signs with whatever identity the OIDC flow returns, so a misconfigured workflow signs as an unexpected identity. | With `signing.signer`: the token's issuer, and its subject when named, are checked before Fulcio is asked; every attribute the signer names (`source-repository-uri`, `build-config-uri`, …) is checked on the issued certificate before the signature is written. Verification checks them again. |
| **Browser flow in CI** | Skipped when `CI=true`; otherwise, if no ambient token is found, the plugin opens a browser, which can hang a build on a runner that does not set `CI`. | Disabled by default (`interactive: false`): only `SIGSTORE_JAVA_ID_TOKEN` and GitHub Actions are tried. |
| **Supply chain verification** | Signing only | Dependency trust verification and enforcement with Sigstore and OpenPGP evidence |
| **Quantum resistance** | None | Hybrid ML-DSA + classic signatures (RFC 9980) |

## Step-by-step migration

### 1. Replace the plugin

**Before (sigstore-maven-plugin):**

```xml
<plugin>
  <groupId>dev.sigstore</groupId>
  <artifactId>sigstore-maven-plugin</artifactId>
  <version>2.4.0</version>
  <executions>
    <execution>
      <id>sign</id>
      <goals>
        <goal>sign</goal>
      </goals>
    </execution>
  </executions>
</plugin>
```

**After (sigmund-maven-plugin):**

```xml
<properties>
  <sigmund.version>0.0.2</sigmund.version>
</properties>

<plugin>
  <groupId>dev.cyberstamp.sigmund</groupId>
  <artifactId>sigmund-maven-plugin</artifactId>
  <version>${sigmund.version}</version>
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

Note the `sigmund-sigstore` plugin dependency, at the plugin's own version — this enables the Sigstore backend in the Maven plugin. The CLI bundles it automatically, but the Maven plugin keeps it optional so projects that only need OpenPGP don't pull in sigstore-java's transitive dependencies.

### 2. Configuration mapping

`sigstore-maven-plugin` uses Maven `<configuration>` properties. Sigmund uses `sigmund.yaml`.

| sigstore-maven-plugin | Sigmund equivalent | Notes |
|----------------------|-------------------|-------|
| `<publicStaging>` / `-Dpublic-staging` | `sigmund.yaml` → `tools.sigstore.staging: true` | Configured once, applies to both signing and verification |
| `<skip>` / `-Dsigstore.skip` | `sigmund.skip` | `mvn verify -Dsigmund.skip=true` |
| (no equivalent) | `sigmund.yaml` → `tools.sigstore.interactive: true` | Enables the browser OIDC flow, which `sigstore-maven-plugin` uses outside CI |
| (no equivalent) | `sigmund.yaml` → `tools.sigstore.trusted-root` | Custom trusted root for verifying bundles |
| (no equivalent) | `sigmund.yaml` → `signing.signer` + `signers.<name>.identities` | The identity every signature must prove, checked at signing and again at verification |

**Minimal sigmund.yaml for Sigstore-only signing (CI):**

```yaml
signing:
  toolchain: [sigstore]
```

No `tools` section needed — Sigstore uses production defaults.

**With staging:**

```yaml
tools:
  sigstore:
    staging: true

signing:
  toolchain: [sigstore]
```

**With the signing identity checked** (`source-repository-uri` with `build-config-uri` is stable across releases; `subject` carries the git ref and changes with each one):

```yaml
signers:
  ci-pipeline:
    identities:
      - issuer: "https://token.actions.githubusercontent.com"
        source-repository-uri: "https://github.com/myorg/myrepo"
        build-config-uri: "https://github.com/myorg/myrepo/.github/workflows/release.yml@refs/heads/main"

signing:
  signer: ci-pipeline
  toolchain: [sigstore]
```

A token from another issuer is refused before Fulcio is asked; a certificate from another repository or workflow fails signing before any bundle is written. See [`identities`](configuration.md#object-form) for every attribute.

### 3. GitHub Actions workflow

The workflow configuration is nearly identical. The key difference is the plugin coordinates and the `sigmund-sigstore` dependency.

**Before (sigstore-maven-plugin):**

```yaml
permissions:
  id-token: write
  contents: read

steps:
  - uses: actions/checkout@v4
  - name: Sign artifacts
    run: mvn verify
```

**After (sigmund-maven-plugin):**

```yaml
permissions:
  id-token: write
  contents: read

steps:
  - uses: actions/checkout@v4
  - name: Build and sign artifacts
    run: mvn verify
```

Both require `id-token: write` for GitHub Actions OIDC token generation. The `sigmund:sign` goal is bound to the `verify` phase in the POM, so `mvn verify` builds the project and then signs all produced artifacts.

### 4. Verify existing Sigstore-signed artifacts

Sigmund can verify `.sigstore.json` bundles produced by `sigstore-maven-plugin`:

```bash
mvn sigmund:verify-signature \
  -Dfile=target/myproject-1.0.jar \
  -Dsignature=target/myproject-1.0.jar.sigstore.json
```

The bundle format is identical — both plugins use sigstore-java's `Bundle.toJson()` serialization.

### 5. (Optional) Add OpenPGP signing alongside Sigstore

Sigmund can produce both `.asc` (OpenPGP) and `.sigstore.json` (Sigstore) in a single `sign` execution:

```yaml
signers:
  release:
    pgp4: "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234"  # full 40-character fingerprint
    identities:
      - issuer: "https://token.actions.githubusercontent.com"
        source-repository-uri: "https://github.com/myorg/myrepo"

signing:
  signer: release
  toolchain: [bc, sigstore]
```

Each artifact gets two signature files:
- `artifact.jar.asc` — OpenPGP signature (backward-compatible with Maven Central)
- `artifact.jar.sigstore.json` — Sigstore bundle (verified by Maven Central's Sigstore validation)

## Maven Central compatibility

Both plugins produce the same `.sigstore.json` bundle format. Maven Central validates Sigstore bundles from either plugin identically.

## Known limitations

- **Multi-module builds** — sigstore-java caches the Fulcio certificate and reuses it across modules until it has less than 5 minutes of remaining validity (10-minute certificate lifetime by default). Builds that take longer than this trigger a new OIDC authentication mid-build.
- **Network dependency** — signing requires access to the OIDC provider, Fulcio, and Rekor. No offline signing mode exists.
- **CI OIDC support** — ambient OIDC works automatically on GitHub Actions. Other CI systems can set the `SIGSTORE_JAVA_ID_TOKEN` environment variable to an OIDC identity token.

## Next steps

- **Verify dependencies:** Use `mvn sigmund:verify` to enforce trust policies on your dependencies — see [Trust Verification](trust-verification.md)
- **Hybrid signing:** Add OpenPGP alongside Sigstore for maximum compatibility — see [Signing Guide](signing.md)
- **Inspect signers:** Use `mvn sigmund:dependency-signers` to see who signed each dependency
- **Advanced configuration:** See [Configuration Guide](configuration.md) for all tool settings and signing profiles
