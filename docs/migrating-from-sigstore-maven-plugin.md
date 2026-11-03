# Migrating from sigstore-maven-plugin

This guide helps you migrate from `sigstore-maven-plugin` (dev.sigstore) to Sigmund's Maven plugin. Both plugins support Sigstore keyless signing via sigstore-java, but Sigmund integrates Sigstore as one backend within a multi-format signing and verification framework — adding identity matching, dependency trust verification, cross-backend credential matching, and OpenPGP+Sigstore hybrid signing in a single build.

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

Sigmund offers everything `sigstore-maven-plugin` does, plus:

- **Identity matching** — configure expected Sigstore identities and verify them against signed artifacts. When `subject` + `issuer` are both set, the OIDC token is also validated at signing time before artifacts ship.
- **Signature verification** — verify Sigstore bundles (and OpenPGP signatures) from the same tool
- **Dependency trust verification** — enforce that dependencies are signed by known trusted parties
- **Cross-backend identity matching** — a signer configured with an `email` credential matches both OpenPGP (via an address `keys.openpgp.org` verified for the key) and Sigstore (via the Fulcio certificate SAN), from the issuers the policy trusts
- **Hybrid signing** — produce both `.asc` (OpenPGP) and `.sigstore.json` (Sigstore) in a single `sign` goal execution
- **Post-quantum cryptography** — add ML-DSA signatures alongside classic OpenPGP and Sigstore
- **CLI** — sign, verify, and inspect signatures outside Maven

## Feature comparison

| Feature | sigstore-maven-plugin | sigmund-maven-plugin |
|---------|----------------------|----------------------|
| Sigstore keyless signing | Yes | Yes |
| `.sigstore.json` bundle output | Yes | Yes |
| Staging instance support | Yes (`public-staging`) | Yes (`tools.sigstore.staging`) |
| Identity validation at signing time | No | Yes, when `subject` + `issuer` are configured |
| Sigstore bundle verification | No | Yes |
| OpenPGP signing | No | Yes (GPG, Bouncy Castle, Sequoia) |
| Hybrid OpenPGP + Sigstore signing | No | Yes |
| PQC hybrid signing | No | Yes (ML-DSA via Sequoia) |
| Dependency trust verification | No | Yes |
| Custom trusted root (air-gapped) | No | Yes (`tools.sigstore.trusted-root`) |
| Interactive browser OIDC flow | Always enabled | Opt-in (`tools.sigstore.interactive`) |
| CLI tool | No | Yes |
| Pure Java (no external CLI) | Yes | Yes (Sigstore backend) |

## Security comparison

| Dimension | sigstore-maven-plugin | sigmund-maven-plugin |
|-----------|----------------------|----------------------|
| **OIDC identity validation** | None — accepts whatever identity the OIDC flow returns. A misconfigured CI workflow could sign with an unexpected identity. | Configurable via signer credentials. **Signing time:** `subject` + `issuer` rejects mismatched OIDC tokens before Fulcio is contacted. **Verification time:** other fields (`source-repository-uri`, `build-trigger`, etc.) are matched against the Fulcio certificate. Use `issuer` + `source-repository-uri` for stable CI matching — `subject` includes the git ref and changes per release. |
| **Browser flow in CI** | Always included — if ambient OIDC fails and `CI` env var is not set, the plugin opens a browser, potentially hanging the build. | Disabled by default (`interactive: false`). Only ambient providers (GitHub Actions) are tried. Browser flow requires explicit opt-in. |
| **KeylessSigner lifecycle** | Signer is not explicitly closed — ephemeral key material on the Java heap until GC. | `Sigmund` implements `AutoCloseable` and calls `KeylessSigner.close()`, which clears cached certificate material immediately. |
| **Supply chain verification** | Signing only | Dependency trust verification and enforcement with Sigstore and OpenPGP evidence |
| **Quantum resistance** | None | Hybrid ML-DSA + classic signatures (RFC 9980) |

## Step-by-step migration

### 1. Replace the plugin

**Before (sigstore-maven-plugin):**

```xml
<plugin>
  <groupId>dev.sigstore</groupId>
  <artifactId>sigstore-maven-plugin</artifactId>
  <version>2.2.0</version>
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
| `<publicStaging>true</publicStaging>` | `sigmund.yaml` → `tools.sigstore.staging: true` | Configured once, applies to both signing and verification |
| `<skip>true</skip>` | `sigmund.skip` system property | `mvn verify -Dsigmund.skip=true` |
| (no equivalent) | `sigmund.yaml` → `tools.sigstore.interactive: true` | Enables browser OIDC flow. `sigstore-maven-plugin` always enables it. |
| (no equivalent) | `sigmund.yaml` → `tools.sigstore.trusted-root` | Custom trusted root for air-gapped environments |
| (no equivalent) | `sigmund.yaml` → `signing.signer` + `signers.<name>.sigstore` | Identity matching (verification-time; signing-time when `subject` + `issuer` are set) |

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

**With verification-time identity matching** (recommended for CI — `source-repository-uri` is stable across releases):

```yaml
signers:
  ci-pipeline:
    identities:
      - issuer: "https://token.actions.githubusercontent.com"
        source-repository-uri: "https://github.com/myorg/myrepo"

signing:
  signer: ci-pipeline
  toolchain: [sigstore]
```

**With signing-time identity validation** (requires `subject`, which includes the git ref and changes per release):

```yaml
signers:
  ci-pipeline:
    identities:
      - issuer: "https://token.actions.githubusercontent.com"
        subject: "https://github.com/myorg/myrepo/.github/workflows/release.yml@refs/tags/v1.0.0"

signing:
  signer: ci-pipeline
  toolchain: [sigstore]
```

> **Note:** See the [security comparison](#security-comparison) above for details on when identity matching happens at signing time vs verification time.

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
