# Configuration Reference

Sigmund uses a `sigmund.yaml` file for configuration. This reference documents every section and setting.

## Contents

- [File Location](#file-location)
- [Complete Example](#complete-example)
- [Section Reference](#section-reference)
  - [version](#version)
  - [signers](#signers)
  - [signing](#signing)
  - [artifacts](#artifacts)
  - [trust](#trust)
  - [signature-optional](#signature-optional)
  - [policy](#policy)
  - [verification](#verification)
  - [tools](#tools)
- [Tool Settings Tables](#tool-settings-tables)
  - [BC (BouncyCastle)](#bc-bouncycastle)
  - [SQ (Sequoia)](#sq-sequoia)
  - [GPG (GnuPG)](#gpg-gnupg)
  - [Sigstore](#sigstore)
- [Common Configuration Patterns](#common-configuration-patterns)
  - [Minimal Verification-Only Config](#minimal-verification-only-config)
  - [CI/CD Signing Config](#cicd-signing-config)
  - [Multi-Tool Hybrid Signing](#multi-tool-hybrid-signing)
  - [Sigstore-Only Signing](#sigstore-only-signing)
  - [Mixed OpenPGP + Sigstore Signing](#mixed-openpgp--sigstore-signing)
  - [Strict Trust Policy](#strict-trust-policy)
  - [Permissive Development Config](#permissive-development-config)

## File Location

Sigmund locates configuration files using the following search order:

1. **Explicit path** — specified via `--config` flag (CLI) or `-Dsigmund.trustConfig` (Maven)
2. **Local config** — `./sigmund.yaml` (current working directory for CLI, `${project.basedir}` for Maven)
3. **User config** — `~/.config/sigmund/sigmund.yaml`

The **first file found wins**. Configuration files are not merged.

## Complete Example

```yaml
# Schema version (optional, defaults to 1)
version: 1

# Identity registry — define all trusted signers
signers:
  # Full form: organization with multiple members
  apache:
    name: "Apache Software Foundation"
    members:
      - pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
        email: "dev@maven.apache.org"
      - pgp4: "BBE7232D7991050B54C8EA0ADC08637CA615D22C"
  
  # Single-key signer with multiple credential types
  jane:
    name: "Jane Doe"
    pgp4: "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
    pgp6: "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
    email: "jane@example.com"
  
  # CI/CD identity using Sigstore credentials
  github-bot:
    name: "GitHub Actions Bot"
    sigstore:
      issuer: "https://token.actions.githubusercontent.com"
      source-repository-uri: "https://github.com/myorg/myrepo"
    email: "bot@example.com"
  
  # Minimal form: email-only signer
  jackson-dev: "tatu@fasterxml.com"

# Artifact-to-signer trust mappings
trust:
  # Map artifact patterns to signers
  "org.apache.maven.*": apache
  "org.apache.commons.*": apache
  "com.fasterxml.jackson.*": jackson-dev
  "com.example:mylib": jane
  
  # Multiple signers for one pattern
  "io.quarkus.*": [redhat, jboss-community]

# Artifacts that do not require a signature
signature-optional:
  - "com.internal.*"
  - "com.example:test-utils"

# Policy enforcement rules
policy:
  # Action on untrusted artifacts: "fail" or "warn"
  on-untrusted: fail
  
  # Evidence matching for artifacts with multiple signatures
  listed-evidence: all      # 'all' or 'any' - default: all
  unlisted-evidence: ignore # 'ignore', 'warn', or 'require' - default: ignore

# Signing configuration
signing:
  # Which signer identity to sign as (references signers section)
  signer: jane
  
  # Toolchain order for signing operations
  toolchain: [bc, sq, gpg]
  
  # Default credential types to produce (filters which tools are used)
  credential-types: [pgp4, pgp6]
  
  # Named profiles for explicit switching (e.g., --profile classic)
  profiles:
    classic:
      - pgp4

# Verification settings
verification:
  # Toolchain order for verification operations
  toolchain: [bc, sq, gpg]
  
  # Fetch missing keys from keyservers during verification
  resolve-signers: true
  
  # Persist fetched keys to tool keyrings (vs. in-memory cache)
  import-to-keyring: false
  
  # Keyserver URLs for key discovery
  keyservers:
    - hkps://keys.openpgp.org

# Tool-specific settings (used by both signing and discovery)
tools:
  bc:
    # Signing settings
    signing-fingerprint: "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
    passphrase-env: SIGMUND_BC_PASSPHRASE
    cipher-suite: ed25519
    
    # Verification settings
    gnupg-home: ~/.gnupg
    cert-d-home: ~/.local/share/openpgp-cert-d
    bc-private-home: ~/.local/share/openpgp-cert-d/bc-private
  
  sq:
    # Signing settings
    signing-fingerprint: "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
    
    # Common settings
    home: ~/.local/share/sequoia
    executable: sq
  
  gpg:
    # Signing settings
    key-name: "0xDEADBEEF"
    
    # Common settings
    executable: gpg
    home: ~/.gnupg
  
  sigstore:
    # Use the Sigstore staging instance (for testing)
    staging: false
    # Custom trusted root file (optional, defaults to TUF-fetched root)
    trusted-root: /path/to/trusted_root.json
    # Allow interactive OIDC browser login (for desktop use)
    interactive: true
```

## Section Reference

### `version`

**Type:** Integer  
**Default:** `1`

The schema version for this configuration file. Currently, only version `1` is defined.

```yaml
version: 1
```

### `signers`

**Type:** Map of signer ID → signer definition  
**Default:** `{}` (empty)

Defines the identity registry of trusted signers. Each signer can be specified in multiple forms:

#### Minimal Form (Email Only)

A simple string value representing an email address.

```yaml
signers:
  jackson-dev: "tatu@fasterxml.com"
```

#### Single-Key Signer

An object with credential fields. At least one credential type must be specified.

```yaml
signers:
  jane:
    name: "Jane Doe"                    # Optional display name
    pgp4: "ABCD...EF12"                 # OpenPGP v4 fingerprint (40 hex chars)
    pgp6: "1234...CDEF"                 # OpenPGP v6 fingerprint (64 hex chars)
    email: "jane@example.com"           # Email address
    sigstore:                           # Sigstore credential (matchable fields)
      issuer: "https://token.actions.githubusercontent.com"
      subject: "https://github.com/org/repo/.github/workflows/ci.yml@refs/heads/main"
```

**Credential types:**

- **`pgp4`** — OpenPGP v4 fingerprint (40 hexadecimal characters). Matched against OpenPGP v4 signatures. Alias: `openpgp4`.
- **`pgp6`** — OpenPGP v6 fingerprint (64 hexadecimal characters). Matched against OpenPGP v6 signatures. Alias: `openpgp6`.
- **`email`** — Email address. Matched case-insensitively against PGP user IDs and Sigstore OIDC subjects (when subject is an email).
- **`sigstore`** — Sigstore certificate credential with matchable fields. Only the fields you specify need to match. Available fields:
  - `issuer` — OIDC issuer URL
  - `subject` — SAN subject (exact workflow+ref match, changes per release)
  - `source-repository-uri` — source repository URL (stable across releases)
  - `source-repository-owner-uri` — repository owner URL
  - `build-trigger` — build trigger event (e.g., `release`, `push`)
  - `build-config-uri` — build configuration URI (e.g., workflow file URI with ref)
  - `runner-environment` — runner environment (e.g., `github-hosted`)

  > **Signing-time vs verification-time matching:** When both `issuer` and `subject` are set and the signer is used for signing (`signing.signer`), the OIDC token is validated at signing time — mismatched identities are rejected before requesting a Fulcio certificate. All other fields (`source-repository-uri`, `build-trigger`, etc.) are Fulcio certificate extensions and are matched at verification time only. For CI pipelines where the `subject` includes a git ref that changes per release, use `issuer` + `source-repository-uri` for stable verification-time matching without config churn.

**Aliases:** `openpgp4` and `openpgp6` are accepted aliases for `pgp4` and `pgp6` respectively.

#### Organization with Multiple Members

When a signer represents an organization, use the `members` array to list individual signing keys.

```yaml
signers:
  apache:
    name: "Apache Software Foundation"
    members:
      - pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
        email: "dev@maven.apache.org"
      - pgp4: "BBE7232D7991050B54C8EA0ADC08637CA615D22C"
```

### `signing`

**Type:** Object  
**Default:** No signer, no toolchain configured

Configures which identity to sign as and the signing toolchain.

```yaml
signing:
  signer: my-identity             # References a signer from the signers section
  toolchain: [bc, sq, gpg]        # Tools to use for signing, in priority order
  credential-types: [pgp4, pgp6]  # Default credential types to produce
  profiles:                       # Named profiles for explicit switching
    classic:
      - pgp4
```

#### Fields

- **`signer`** (string, optional) — References a signer ID from the `signers` section. This identity will be used for signing operations.
- **`toolchain`** (array of strings, optional) — Lists which tools to use for signing and in what order. Only the listed tools are initialized. Tool names: `bc`, `sq`, `gpg`, `sigstore`. Per-tool settings are configured in the top-level `tools` section.
- **`credential-types`** (array of strings, optional) — The default set of credential types to produce. Only tools whose supported credential types intersect this list are used. When omitted, all available signing tools are used. Values: `pgp4`, `pgp6`, `sigstore`.
- **`profiles`** (map, optional) — Named profiles for explicit switching (e.g., `--profile classic`). Each profile maps a name to a list of credential type strings. When a profile is requested by name, it takes precedence over `credential-types`.

### `signature-optional`

**Type:** Array of strings
**Default:** `[]` (empty)

Lists artifact patterns for which a signature is not required. Artifacts matching these patterns will not fail verification when unsigned. If a matching artifact happens to be signed, normal trust policy evaluation applies.

```yaml
signature-optional:
  - "com.internal.*"
  - "com.example:test-utils"
```

Pattern syntax is the same as the `trust` section. Named artifact groups from the `artifacts` section can also be referenced here.

### `artifacts`

**Type:** Map of group name → array of artifact patterns  
**Default:** `{}` (empty)

Defines named groups of artifact patterns that can be referenced by name in the `trust` and `signature-optional` sections. This avoids repeating the same long list of patterns when multiple signers or policies share the same set of artifacts.

```yaml
artifacts:
  apache-stack:
    - "org.apache.maven.*"
    - "org.apache.commons.*"
    - "org.apache.httpcomponents.*"
  internal-libs:
    - "com.internal.platform.*"
    - "com.internal.shared.*"

trust:
  apache-stack: apache          # Expands to all three org.apache.* patterns
  internal-libs: release-team

signature-optional:
  - internal-libs               # Expands to both com.internal.* patterns
```

When a key in `trust` or an entry in `signature-optional` matches a group name, it is expanded into the group's patterns. If no group matches, the key is treated as a literal artifact pattern.

### `trust`

**Type:** Map of artifact pattern → signer reference(s)  
**Default:** `{}` (empty)

Maps artifact coordinate patterns to trusted signer IDs. Patterns support wildcards and Maven coordinate syntax.

```yaml
trust:
  "org.apache.maven.*": apache              # Single signer
  "io.quarkus.*": [redhat, jboss-community] # Multiple signers (array)
  "com.example:mylib": jane                 # Specific artifact
  "com.example:*:1.0.*": jane               # Version wildcards
```

#### Pattern Format

Patterns use Maven coordinate syntax with wildcard support:

- `groupId` — matches all artifacts in the group
- `groupId.*` — matches group and all subgroups (prefix match)
- `groupId:artifactId` — matches specific artifact, all versions
- `groupId:artifactId:version` — matches specific version
- `groupId:artifactId:type:classifier:version` — full coordinates

**Wildcards:** Use `*` to match any value in a coordinate segment.

**Precedence:** When multiple patterns match an artifact, the most specific pattern wins.

#### Signer References

Values can be:
- A single signer ID (string)
- An array of signer IDs (for artifacts signed by multiple parties)

Signer IDs must reference entries from the `signers` section.

### `policy`

**Type:** Object  
**Default:** `on-untrusted: fail`, `listed-evidence: all`, `unlisted-evidence: ignore`

Configures trust policy enforcement rules.

```yaml
policy:
  on-untrusted: fail
  listed-evidence: all
  unlisted-evidence: ignore
```

#### Fields

- **`on-untrusted`** (string, default: `fail`)
  - `fail` — Reject artifacts that are not trusted or unsigned
  - `warn` — Log a warning but allow the build to continue

- **`listed-evidence`** (string, default: `all`)
  
  Controls how to handle signatures from signers listed in the trust configuration:
  - `all` — All signatures must match the expected signer(s) for the artifact
  - `any` — At least one signature must match an expected signer

- **`unlisted-evidence`** (string, default: `ignore`)
  
  Controls how to handle signatures from signers NOT listed in the trust configuration:
  - `ignore` — Unlisted signatures are ignored (trust decision based only on listed signers)
  - `warn` — Log a warning when unlisted signatures are found, but don't fail
  - `require` — Fail if any unlisted signatures are found on the artifact

### `verification`

**Type:** Object
**Default:** See fields below

Configures the verification toolchain, key fetching, and verification behavior.

```yaml
verification:
  toolchain: [bc, sq, gpg]
  resolve-signers: true
  import-to-keyring: false
  keyservers:
    - hkps://keys.openpgp.org
```

#### Fields

- **`toolchain`** (array of strings, default: `[bc, sq, gpg]`)
  
  Lists which tools to use for verification and in what order. When specified, **only** the listed tools are initialized. When omitted, all available tools are initialized in the default order (`bc`, `sq`, `gpg`). Tool-specific settings are configured in the top-level `tools` section.
  
  ```yaml
  toolchain: [bc, sq]  # Use only BC and Sequoia
  ```

- **`resolve-signers`** (boolean, default: `true`)
  
  Whether to fetch missing keys from keyservers to resolve signer identities (names and emails). When `true` and a key is not found locally, tools attempt to fetch it from the configured keyservers. The behavior depends on the tool and `import-to-keyring`:

  | `resolve-signers` | `import-to-keyring` | BC | GPG |
  |---|---|---|---|
  | `false` | any | no fetch | no fetch |
  | `true` | `false` (default) | fetch ephemerally (in-memory, discarded after build) | skip (GPG cannot do ephemeral imports) |
  | `true` | `true` | fetch + persist to cert-d | fetch + persist to GPG keyring |

  When `resolve-signers: true` but no tool in the configured toolchain can fetch keys (e.g., only GPG with `import-to-keyring: false`), Sigmund logs a warning.

  A per-keyserver circuit breaker prevents slow builds when offline — after the first connection failure to a keyserver, all subsequent fetch attempts to that server are skipped. A per-key negative cache prevents re-querying the same missing key across artifacts.

- **`import-to-keyring`** (boolean, default: `false`)
  
  Controls how fetched keys are stored. Only meaningful when `resolve-signers` is `true`:
  
  - `false` (default) — Keys are cached in memory for the session. BC supports ephemeral key storage; GPG does not, so key fetch is skipped entirely for GPG when this is `false`.
  - `true` — Keys are permanently imported into the tool's keyring (BC cert-d or GPG keyring).
  
  **Note:** `keys.openpgp.org` may serve keys without user IDs. BC can use these for verification, but GPG cannot import them.

- **`keyservers`** (array of strings, default: `[hkps://keys.openpgp.org]`)
  
  Keyserver URLs for fetching missing keys. Defaults to `hkps://keys.openpgp.org` because it verifies email addresses before publishing, preventing impersonation.
  
  ```yaml
  keyservers:
    - hkps://keys.openpgp.org
    - hkps://keyserver.ubuntu.com
  ```

### `tools`

**Type:** Map of tool name → tool settings  
**Default:** `{}` (empty)

Configures per-tool settings used by both signing and discovery operations. All tool-specific configuration lives here, avoiding duplication between `signing` and `discovery` sections.

```yaml
tools:
  bc:
    signing-fingerprint: "ABCD...EF12"
    passphrase-env: MY_BC_PASSPHRASE
    gnupg-home: ~/.gnupg
    cert-d-home: ~/.local/share/openpgp-cert-d
  
  sq:
    home: ~/.local/share/sequoia
    signing-fingerprint: "1234...CDEF"
    executable: sq
  
  gpg:
    key-name: "0xDEADBEEF"
    home: ~/.gnupg
    executable: gpg
```

#### Fields

Keys are tool names (`bc`, `sq`, `gpg`, `sigstore`). Values are tool-specific settings documented in the [Tool Settings Tables](#tool-settings-tables) below.

Settings configured here are available to both signing and verification operations. For example, `tools.bc.signing-fingerprint` is used by signing operations, while `tools.bc.gnupg-home` is used by verification.

## Tool Settings Tables

### BC (BouncyCastle)

Configured in the top-level `tools.bc` section.

| Setting | Default | Description |
|---------|---------|-------------|
| `gnupg-home` | `~/.gnupg` | GnuPG home directory for reading `pubring.kbx` (or legacy `pubring.gpg`) |
| `cert-d-home` | `~/.local/share/openpgp-cert-d` | Shared OpenPGP cert-d directory for public certificates |
| `bc-private-home` | `<cert-d-home>/bc-private` | BC private key store directory |
| `signing-fingerprint` | (none) | Fingerprint of the key to sign with (40 or 64 hex chars) |
| `tsk-file` | (none) | Path to an exported Transferable Secret Key (TSK) file for signing |
| `signing-key-env` | `SIGMUND_BC_SIGNING_KEY` | Environment variable name containing the ASCII-armored private key. For ephemeral CI runners. |
| `passphrase-env` | `SIGMUND_BC_PASSPHRASE` | Environment variable name containing the passphrase. If not set, falls back to interactive prompt. |
| `cipher-suite` | `ed25519` | Algorithm for key generation (see supported values below) |

**Supported cipher suites (BC):**

Classic algorithms:
- `ed25519` — EdDSA with Curve25519 (default)
- `ed448` — EdDSA with Curve448
- `rsa4096` — RSA with 4096-bit modulus
- `nistp256` — ECDSA with NIST P-256 curve
- `nistp384` — ECDSA with NIST P-384 curve
- `nistp521` — ECDSA with NIST P-521 curve

PQC composite (experimental):
- `mldsa87-ed448` — ML-DSA-87 + Ed448 hybrid
- `mldsa65-ed25519` — ML-DSA-65 + Ed25519 hybrid

**Passphrase resolution order:**

1. Explicit `PassphraseProvider` via API (`Sigmund.Builder.bcPassphraseProvider()`)
2. Environment variable specified by `passphrase-env` setting
3. Interactive console prompt (if a terminal is available)
4. No passphrase (works only for unencrypted keys)

**Example:**

```yaml
tools:
  bc:
    signing-fingerprint: "ABCDEF1234567890ABCDEF1234567890ABCDEF12"
    passphrase-env: MY_BC_KEY_PASSPHRASE
    cipher-suite: ed448
    gnupg-home: /custom/gnupg
    cert-d-home: /custom/cert-d
```

### SQ (Sequoia)

Configured in the top-level `tools.sq` section.

| Setting | Default | Description |
|---------|---------|-------------|
| `home` | `~/.local/share/sequoia` | Sequoia home directory for keys and certificates |
| `executable` | `sq` | Path to the `sq` executable (if not on `PATH`) |
| `signing-fingerprint` | (none) | Fingerprint of the key to sign with (64 hex chars for v6 keys) |
| `cipher-suite` | `mldsa87-ed448` | Algorithm for key generation (PQC hybrid suites) |

**Supported cipher suites (SQ):**

Sequoia supports post-quantum cryptography hybrid cipher suites as defined in RFC 9580:
- `mldsa87-ed448` — ML-DSA-87 + Ed448 (default)
- `mldsa65-ed25519` — ML-DSA-65 + Ed25519
- Additional suites supported by `sq key generate --cipher-suite`

**Example:**

```yaml
tools:
  sq:
    home: ~/.local/share/sequoia
    signing-fingerprint: "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
    executable: /usr/local/bin/sq
```

### GPG (GnuPG)

Configured in the top-level `tools.gpg` section.

| Setting | Default | Description |
|---------|---------|-------------|
| `executable` | `gpg` | Path to the `gpg` executable (if not on `PATH`) |
| `key-name` | (none) | Key identifier for signing (fingerprint, key ID, or email) |
| `home` | (system default) | GnuPG home directory (`--homedir` option) |
| `passphrase-env` | `SIGMUND_GPG_PASSPHRASE` | Environment variable name containing the passphrase. If not set, falls back to `gpg-agent`. |

**Note:** GPG only supports OpenPGP v4 keys. OpenPGP v6 keys cannot be used with GPG.

**Example:**

```yaml
tools:
  gpg:
    key-name: "0xDEADBEEF"
    home: ~/.gnupg
    executable: /usr/bin/gpg2
```

### Sigstore

Configured in the top-level `tools.sigstore` section. Sigstore uses OIDC-based keyless signing via `sigstore-java` — no long-lived keys to manage.

| Setting | Default | Description |
|---------|---------|-------------|
| `staging` | `false` | Use the Sigstore staging instance instead of production. For testing only. |
| `trusted-root` | (none) | Path to a custom `trusted_root.json` file. When omitted, the root is fetched via TUF from the Sigstore public-good instance. |
| `interactive` | `false` | Allow interactive OIDC browser login. When `false`, only ambient credentials are used: the `SIGSTORE_JAVA_ID_TOKEN` environment variable (if set), then GitHub Actions OIDC. Set to `true` for desktop signing. |

The Sigstore tool is pure Java (provided by the `sigmund-sigstore` module) and does not require any external CLI binary. It is ServiceLoader-discovered — adding the module to the classpath is sufficient.

**Credential type:** `sigstore`  
**File extension:** `.sigstore.json`

**Example:**

```yaml
tools:
  sigstore:
    interactive: true
```

## Common Configuration Patterns

### Minimal Verification-Only Config

```yaml
version: 1

signers:
  apache: "dev@apache.org"

trust:
  "org.apache.*": apache
```

### CI/CD Signing Config

```yaml
version: 1

signing:
  toolchain: [bc]

tools:
  bc:
    signing-fingerprint: "ABCD...EF12"
    passphrase-env: CI_SIGNING_KEY_PASSPHRASE
```

### Multi-Tool Hybrid Signing

```yaml
version: 1

signers:
  release-team:
    name: "Release Engineering"
    pgp4: "ABCD...EF12"  # v4 fingerprint for GPG compatibility
    pgp6: "1234...CDEF"  # v6 fingerprint for PQC

signing:
  signer: release-team
  toolchain: [bc, sq, gpg]
  credential-types: [pgp4, pgp6]

verification:
  toolchain: [bc, sq, gpg]

tools:
  bc:
    signing-fingerprint: "1234...CDEF"  # Use v6 key
    cipher-suite: ed448
  
  sq:
    signing-fingerprint: "1234...CDEF"
  
  gpg:
    key-name: "0xABCDEF12"  # Use v4 key
```

### Sigstore-Only Signing

```yaml
version: 1

signing:
  toolchain: [sigstore]
```

No tool settings needed — ambient OIDC credentials from GitHub Actions are used automatically.

To match signed artifacts against a specific Sigstore identity at verification time, add a signer with Sigstore credentials:

```yaml
version: 1

signers:
  ci-bot:
    sigstore:
      issuer: "https://token.actions.githubusercontent.com"
      source-repository-uri: "https://github.com/myorg/myrepo"

signing:
  signer: ci-bot
  toolchain: [sigstore]
```

### Mixed OpenPGP + Sigstore Signing

```yaml
version: 1

signers:
  release-lead:
    name: "Release Lead"
    pgp4: "ABCDEF1234567890ABCDEF1234567890ABCDEF12"
    sigstore:
      issuer: "https://token.actions.githubusercontent.com"
      source-repository-uri: "https://github.com/myorg/myrepo"
    email: "release@example.com"

signing:
  signer: release-lead
  toolchain: [bc, sigstore]

verification:
  toolchain: [bc, sigstore]

tools:
  bc:
    signing-fingerprint: "ABCDEF1234567890ABCDEF1234567890ABCDEF12"
    passphrase-env: BC_PASSPHRASE
  sigstore:
    trusted-root: /etc/sigmund/trusted_root.json
```

This produces both a `.asc` (OpenPGP) and a `.sigstore.json` (Sigstore bundle) for each artifact. Verifiers match the `email` credential across both backends.

### Strict Trust Policy

```yaml
version: 1

policy:
  on-untrusted: fail
  listed-evidence: all       # All listed signatures must match
  unlisted-evidence: require # Fail on any unlisted signatures

verification:
  resolve-signers: false     # Don't auto-fetch keys
  import-to-keyring: false   # Don't persist fetched keys
```

### Permissive Development Config

```yaml
version: 1

policy:
  on-untrusted: warn           # Warn but don't fail
  listed-evidence: any         # Any matching signature is sufficient
  unlisted-evidence: ignore    # Ignore unlisted signatures

signature-optional:
  - "com.internal.*"           # Internal artifacts don't need signatures
  - "com.example:*:*-SNAPSHOT" # Snapshots don't need signatures

verification:
  resolve-signers: true        # Auto-fetch missing keys
  import-to-keyring: true      # Cache keys permanently
```
