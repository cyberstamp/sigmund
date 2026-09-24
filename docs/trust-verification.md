# Trust Verification

This guide covers identity-based trust verification for Maven dependencies using Sigmund. Trust verification goes beyond checking that signatures are valid — it answers the question: **"Is this artifact from someone I trust?"**

**Note:** This is distinct from signature verification, which only confirms that signatures are cryptographically valid. For basic signature verification, see [Signature Verification](verification.md).

## Contents

- [Concept](#concept)
  - [How It Works](#how-it-works)
- [The sigmund.yaml Trust Configuration](#the-sigmundyaml-trust-configuration)
  - [1. Signers](#1-signers)
  - [2. Trust Mappings](#2-trust-mappings)
  - [3. Signature-Optional Artifacts](#3-signature-optional-artifacts)
  - [4. Policy Configuration](#4-policy-configuration)
  - [5. Verification Configuration](#5-verification-configuration)
- [Complete Example](#complete-example)
- [Running Trust Verification](#running-trust-verification)
  - [Example Output](#example-output)
  - [Outcomes](#outcomes)
  - [Exit Codes](#exit-codes)
  - [Maven Properties](#maven-properties)
- [Generating Trust Configuration](#generating-trust-configuration)
  - [Generated File Structure](#generated-file-structure)
  - [Generation Options](#generation-options)
- [Updating Trust Configuration](#updating-trust-configuration)
  - [Update Options](#update-options)
- [Recommended Workflow](#recommended-workflow)
  - [Initial Setup](#initial-setup)
  - [CI Integration](#ci-integration)
  - [Updating When Dependencies Change](#updating-when-dependencies-change)
  - [Handling Untrusted Dependencies](#handling-untrusted-dependencies)
- [Troubleshooting](#troubleshooting)
- [See Also](#see-also)

> **Note:** The examples in this guide use the `sigmund` plugin prefix (e.g., `mvn sigmund:verify`). This requires adding the plugin to your project's `pluginManagement`:
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
> `mvn dev.cyberstamp.sigmund:sigmund-maven-plugin:0.0.2:verify`

## Concept

Trust verification combines signature verification with an identity policy:

1. **Signature verification** — confirms that an artifact's `.asc` signature is cryptographically valid
2. **Identity matching** — extracts signer credentials from the verified signature (fingerprints, email addresses, OIDC identities)
3. **Trust policy evaluation** — checks whether the proven credentials match your expected signers for that artifact

For example, you might trust artifacts from `io.quarkus.*` when signed by the Quarkus team, and artifacts from `com.fasterxml.jackson.*` when signed by Tatu Saloranta. Trust verification enforces these rules automatically during your build.

### How It Works

Sigmund's `verify` goal:
1. Resolves your project's dependencies
2. Downloads signature files (`.asc`) from Maven repositories
3. Verifies each signature and extracts proven credentials
4. Matches credentials against your `sigmund.yaml` trust mappings
5. Reports each artifact's outcome, grouped by outcome and then by attester
6. Fails the build if untrusted artifacts are found (configurable)

## The `sigmund.yaml` Trust Configuration

Trust policies are defined in `sigmund.yaml` in your project root. The file has five main sections for trust verification:

### 1. Signers

The `signers` section defines trusted identities. Each signer has a unique ID and one or more credentials that can prove their identity.

#### Three Forms

**Minimal form** — a single email address:
```yaml
signers:
  jackson-dev: "tatu@fasterxml.com"
```

**Short form** — an object with credential keys (no `name`):
```yaml
signers:
  jane:
    pgp4: "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
    email: "jane@example.com"
```

**Full form** — an object with a display name and credentials:
```yaml
signers:
  apache:
    name: "Apache Software Foundation"
    pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
    email: "dev@maven.apache.org"
```

#### Credential Types

Sigmund supports four credential types:

| Type | YAML Key | Description | Example |
|------|----------|-------------|---------|
| OpenPGP v4 | `pgp4` (alias: `openpgp4`) | 40-character v4 fingerprint | `4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12` |
| OpenPGP v6 | `pgp6` (alias: `openpgp6`) | 64-character v6 fingerprint | `D62AAB339E45E5EA2FD036872B01D46A517A2991...` |
| Email | `email` | Email address | `dev@example.com` |
| Sigstore | `sigstore` | Object with matchable certificate fields | (see below) |

**Sigstore credentials** (for Sigstore-signed artifacts):
```yaml
signers:
  github-actions:
    name: "My GitHub Actions"
    sigstore:
      issuer: "https://token.actions.githubusercontent.com"
      source-repository-uri: "https://github.com/myorg/myrepo"
```

**Multiple credentials per signer:**
```yaml
signers:
  alice:
    name: "Alice Developer"
    pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"  # v4 fingerprint
    pgp6: "D62AAB339E45E5EA2FD036872B01D46A517A2991EF8B8F67C32CF07A49CBDAA0"  # v6 fingerprint
    email: "alice@example.com"
```

When a signature is verified, Sigmund extracts all proven credentials (fingerprint, email, etc.). A signer matches if **any** of their configured credentials matches **any** proven credential from the signature. Fingerprints are matched first; email is used as a fallback when fingerprints are not available.

### 2. Trust Mappings

The `trust` section maps artifact patterns to signer IDs. Patterns support:
- `groupId` (e.g., `io.quarkus`)
- `groupId:artifactId` (e.g., `io.quarkus:quarkus-core`)
- `groupId:artifactId:version` (e.g., `io.quarkus:quarkus-core:3.0.0`)

**Wildcards** are supported:
- `*` matches any single component
- `org.apache.*` matches any groupId starting with `org.apache.`

**Multiple signers** can be assigned to a pattern using an array:
```yaml
trust:
  io.quarkus.*: [redhat, jboss-community]
```

**Pattern matching specificity:** When multiple patterns match an artifact, the most specific pattern wins:
1. Exact matches score higher than wildcards
2. More segments score higher than fewer segments
3. Longer namespace prefixes score higher than shorter ones

Example:
```yaml
trust:
  # Most specific - exact artifactId match
  io.quarkus:quarkus-core: core-team
  
  # Medium specificity - groupId wildcard
  io.quarkus.*: quarkus-team
  
  # Least specific - full wildcard
  "*": fallback-signer
```

For artifact `io.quarkus:quarkus-core:3.0.0`, the pattern `io.quarkus:quarkus-core` wins.

### 3. Signature-Optional Artifacts

The `signature-optional` section lists artifact patterns for which a signature is not required:

```yaml
signature-optional:
  - com.internal.*
  - org.example:test-utils
```

Artifacts matching these patterns will not fail verification when unsigned. If a matching artifact happens to be signed, normal trust policy evaluation applies.

### 4. Policy Configuration

The `policy` section controls trust verification behavior:

```yaml
policy:
  on-untrusted: fail       # or "warn"
  listed-evidence: all     # or "any"
  unlisted-evidence: ignore # "ignore", "warn", or "require"
```

| Setting | Default | Description |
|---------|---------|-------------|
| `on-untrusted` | `fail` | Action when untrusted artifacts are found: `fail` (build fails) or `warn` (log warning only) |
| `listed-evidence` | `all` | How to handle signatures from signers in your trust config: `all` (all must match expected signers) or `any` (at least one must match) |
| `unlisted-evidence` | `ignore` | How to handle signatures from signers NOT in your trust config: `ignore` (skip them), `warn` (log warning), or `require` (fail if found) |

**Note:** The `on-untrusted` setting can be overridden with the `-Dsigmund.onUntrusted` Maven property.

### 5. Verification Configuration

The `verification` section controls how Sigmund fetches signer information:

```yaml
verification:
  resolve-signers: true
  import-to-keyring: false
  keyservers:
    - hkps://keys.openpgp.org
```

| Setting | Default | Description |
|---------|---------|-------------|
| `resolve-signers` | `true` | Fetch unknown GPG keys from keyservers to resolve signer identities |
| `import-to-keyring` | `false` | Import fetched keys to the local keyring |
| `keyservers` | `hkps://keys.openpgp.org` | List of keyservers for fetching GPG keys |

**Why `keys.openpgp.org`?** It's the only major keyserver that verifies email addresses before publishing, preventing impersonation via unverified key uploads. Other keyservers (e.g., `keyserver.ubuntu.com`) can be added if needed.

## Complete Example

Here's a full `sigmund.yaml` with all trust-related sections:

```yaml
# Sigmund trust configuration
# See: https://github.com/cyberstamp/sigmund/blob/main/docs/trust-verification.md

# Define trusted signers
signers:
  # Full form: organization with display name
  apache:
    name: "Apache Software Foundation"
    pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
    email: "dev@maven.apache.org"
  
  # Short form: credentials only
  quarkus-team:
    pgp4: "BBE7232D7991050B54C8EA0ADC08637CA615D22C"
    email: "quarkus-dev@googlegroups.com"
  
  # Minimal form: email string
  jackson-dev: "tatu@fasterxml.com"
  
  # Multiple credentials (PGP + Sigstore)
  alice:
    name: "Alice Developer"
    pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
    pgp6: "D62AAB339E45E5EA2FD036872B01D46A517A2991EF8B8F67C32CF07A49CBDAA0"
    email: "alice@example.com"

# Map artifact patterns to trusted signers
trust:
  # Exact match
  io.quarkus:quarkus-core: quarkus-team
  
  # Wildcard groupId
  org.apache.maven.*: apache
  org.apache.commons.*: apache
  io.quarkus.*: quarkus-team
  
  # Multiple signers
  com.example:shared-lib: [alice, jackson-dev]
  
  # Specific artifact
  com.fasterxml.jackson.core:jackson-databind: jackson-dev

# Artifacts that do not require a signature
signature-optional:
  - com.internal.*
  - org.example:legacy-lib

# Trust policy settings
policy:
  on-untrusted: fail        # fail | warn
  listed-evidence: all      # all | any
  unlisted-evidence: ignore # ignore | warn | require

# Verification settings
verification:
  resolve-signers: true
  import-to-keyring: false
  keyservers:
    - hkps://keys.openpgp.org
```

## Running Trust Verification

Use the `sigmund:verify` goal to verify that all dependencies are signed by trusted signers:

```bash
mvn sigmund:verify
```

The goal reads `sigmund.yaml` from your project root (configurable with `-Dsigmund.trustConfig`).

### Example Output

```
SATISFIED (40)
  openpgp VERIFIED by bc (RSA) - Apache Software Foundation
    org.apache.commons:commons-lang3:3.12.0
    org.apache.maven:maven-core:3.9.0
  openpgp VERIFIED by sq (ML-DSA-87+Ed448) - Quarkus Team
    io.quarkus:quarkus-arc:3.0.0
    io.quarkus:quarkus-core:3.0.0

UNSATISFIED (1)
  openpgp VERIFIED by gpg (RSA) - Unknown <unknown@example.com>
    com.other:tool:3.0

NO_CLAIM (1)
    org.wildfly.common:wildfly-common:2.0.1
```

Results are grouped by outcome, and within an outcome by who attested them.
Artifacts nothing attested carry no group header. Add `-Dsigmund.detail` for the
credentials proven, the trust root, and the evidence each claim was read from.

### Outcomes

| Outcome | Meaning |
|---------|---------|
| **SATISFIED** | The claims found meet what the policy requires of this artifact |
| **UNSATISFIED** | Verification succeeded, but not by a signer the policy accepts |
| **FAILED** | A signature did not verify — an attack signal, never tolerated |
| **NO_CLAIM** | No evidence was found at all |
| **INDETERMINATE** | Verification could not be decided; the reason says why (for example a key that could not be fetched) |
| **NOT_CONFIGURED** | No rule in the policy applies to this artifact |

An artifact listed in `signature-optional` reaches `NO_CLAIM` like any other
artifact without evidence; what the listing changes is whether that blocks.

### Exit Codes

| Exit Code | Condition |
|-----------|-----------|
| `0` | Nothing found blocks the build |
| `1` | A blocking outcome was found: `FAILED` always, and `UNSATISFIED`, `INDETERMINATE` or an unlisted `NO_CLAIM` when `on-untrusted: fail` |

When `on-untrusted: warn` is set, warnings are logged but the build succeeds.
`FAILED` blocks regardless: a signature that does not verify is not a coverage
question.

### Maven Properties

These properties override settings from `sigmund.yaml`:

| Property | Default | Description |
|----------|---------|-------------|
| `sigmund.trustConfig` | `${project.basedir}/sigmund.yaml` | Path to the trust configuration file |
| `sigmund.onUntrusted` | (from config) | Override policy: `fail` or `warn` |
| `sigmund.listedEvidence` | (from config) | Override `listed-evidence` policy (`all` or `any`) |
| `sigmund.resolveSigners` | `true` | Fetch unknown GPG keys from keyservers |
| `sigmund.keyservers` | `hkps://keys.openpgp.org` | Comma-separated keyserver list (also accepts singular `sigmund.keyserver`) |
| `sigmund.verifyPomFiles` | `false` | Also verify signatures on POM files |
| `sigmund.includeTestDependencies` | `false` | Include test-scoped dependencies |
| `sigmund.skip` | `false` | Skip verification |

## Generating Trust Configuration

Instead of writing `sigmund.yaml` by hand, generate it from your project's actual dependency signatures:

```bash
mvn sigmund:dependency-signers \
  -Dsigmund.generateTrustConfig=true \
  -Dsigmund.resolveSigners=true
```

This creates a `sigmund.yaml` in your project root by:
1. Resolving all project dependencies
2. Downloading and verifying their signatures
3. Grouping artifacts by signer (based on proven credentials)
4. Collapsing common groupId prefixes into wildcard patterns (e.g., `io.quarkus.*`)
5. Listing artifacts with no signature in the `signature-optional` section

The generated file can be used directly with `mvn sigmund:verify`.

### Generated File Structure

```yaml
signers:
  signer-1:
    name: "Alice Developer"
    pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
    email: "alice@example.com"
  
  signer-2:
    name: "Bob Maintainer"
    pgp4: "BBE7232D7991050B54C8EA0ADC08637CA615D22C"

trust:
  io.quarkus.*: signer-1
  org.apache.maven.*: signer-2
  com.example:specific-lib: signer-1

signature-optional:
  - com.internal.utils:helper-lib
```

**Tips:**
- Review the generated file before committing — rename signer IDs to something meaningful
- Adjust wildcard patterns if they're too broad or too narrow
- Add display names to signers for better reporting

### Generation Options

| Property | Description |
|----------|-------------|
| `sigmund.generateTrustConfig` | Generate a new `sigmund.yaml`. Set to `true` for project root, or provide a file path. |
| `sigmund.overwrite` | Allow overwriting an existing file (default: `false`) |
| `sigmund.resolveSigners` | Fetch GPG keys from keyservers to resolve signer names and emails (recommended) |
| `sigmund.keyservers` | Comma-separated keyserver list (default: `hkps://keys.openpgp.org`) |

## Updating Trust Configuration

After adding new dependencies, update your existing `sigmund.yaml` instead of regenerating it:

```bash
mvn sigmund:dependency-signers \
  -Dsigmund.updateTrustConfig=true \
  -Dsigmund.resolveSigners=true
```

This appends new signers and artifact mappings to the end of each section while:
- Preserving existing content, comments, and formatting
- Skipping signers and artifacts already configured
- Adding only newly discovered dependencies

After updating, review the changes with `git diff` to see what was added.

### Update Options

| Property | Description |
|----------|-------------|
| `sigmund.updateTrustConfig` | Update an existing `sigmund.yaml`. Set to `true` for project root, or provide a file path. |
| `sigmund.resolveSigners` | Fetch GPG keys from keyservers to resolve signer names and emails (recommended) |

## Recommended Workflow

Here's a complete workflow for setting up and maintaining trust verification:

### Initial Setup

1. **Generate the initial trust config:**
   ```bash
   mvn sigmund:dependency-signers \
     -Dsigmund.generateTrustConfig=true \
     -Dsigmund.resolveSigners=true
   ```

2. **Review and refine the generated `sigmund.yaml`:**
   - Rename signer IDs to meaningful names
   - Add or adjust display names
   - Verify wildcard patterns match your intent
   - Remove or adjust signers you don't trust

3. **Test trust verification:**
   ```bash
   mvn sigmund:verify
   ```

4. **Commit the config:**
   ```bash
   git add sigmund.yaml
   git commit -m "Add dependency trust configuration"
   ```

### CI Integration

Add trust verification to your CI pipeline by running it before tests:

```yaml
# GitHub Actions example
- name: Verify dependency trust
  run: mvn sigmund:verify

- name: Run tests
  run: mvn test
```

Or configure it in your `pom.xml` to run automatically during the `validate` phase:

```xml
<build>
  <plugins>
    <plugin>
      <groupId>dev.cyberstamp</groupId>
      <artifactId>sigmund-maven-plugin</artifactId>
      <version>0.0.2</version>
      <executions>
        <execution>
          <goals>
            <goal>verify</goal>
          </goals>
        </execution>
      </executions>
    </plugin>
  </plugins>
</build>
```

### Updating When Dependencies Change

When you add or upgrade dependencies:

1. **Update the trust config:**
   ```bash
   mvn sigmund:dependency-signers \
     -Dsigmund.updateTrustConfig=true \
     -Dsigmund.resolveSigners=true
   ```

2. **Review the changes:**
   ```bash
   git diff sigmund.yaml
   ```

3. **Verify trust:**
   ```bash
   mvn sigmund:verify
   ```

4. **Commit the updates:**
   ```bash
   git add sigmund.yaml
   git commit -m "Update trust config for new dependencies"
   ```

### Handling Untrusted Dependencies

When `mvn sigmund:verify` reports untrusted artifacts, you have several options:

**Option 1: Add the signer to your trust config** (if you trust them):
```yaml
signers:
  new-signer:
    name: "New Developer"
    pgp4: "<fingerprint-from-output>"
    email: "<email-from-output>"

trust:
  com.example.*: new-signer
```

**Option 2: Allow the artifact to be unsigned** (if there's no signature):
```yaml
signature-optional:
  - com.example:artifact
```

**Option 3: Remove the dependency** (if you don't trust it or can replace it)

**Option 4: Use `warn` mode temporarily** while you investigate:
```bash
mvn sigmund:verify -Dsigmund.onUntrusted=warn
```

## Troubleshooting

### "Trust config file not found"

The default location is `${project.basedir}/sigmund.yaml`. Either create the file or specify a custom path:
```bash
mvn sigmund:verify -Dsigmund.trustConfig=/path/to/sigmund.yaml
```

### "Signer not in trust config" for known signers

This usually means:
1. The signer's credentials changed (new GPG key)
2. The artifact pattern doesn't match (check wildcard specificity)
3. The signer ID in the trust mapping is misspelled

Run `mvn sigmund:dependency-signers` to see the actual signer credentials, then compare with your config.

### "NO_CLAIM" for artifacts that should be signed

The artifact might not have a `.asc` signature file in the repository. Check Maven Central or your artifact repository. If the artifact is legitimately unsigned, add it to the `signature-optional` section.

### Fingerprint mismatches

Fingerprints are case-insensitive and can be specified with or without spaces. These are equivalent:
- `4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12`
- `4aee18f83afdeb23468b2e5a2d7baf3c1e9f5a12`
- `4AEE 18F8 3AFD EB23 468B  2E5A 2D7B AF3C 1E9F 5A12`

### "VERIFICATION_FAILED" results

This indicates a cryptographic signature verification failure — the signature is invalid or corrupt. This is different from "untrusted" (signature is valid but signer is unknown). Verify that:
1. The artifact and signature files match
2. The artifact hasn't been tampered with
3. The signature file is a valid OpenPGP armored signature

## See Also

- [Signature Verification](verification.md) — cryptographic signature verification without trust policies
- [Signing Guide](signing.md) — signing your own artifacts
- [Getting Started](getting-started.md) — installation and basic usage
