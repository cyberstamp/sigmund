# ADR-002: Identity-First Verification with Extensible Signing SPI

## Status

Proposed (supersedes ADR-001)

## Context

Sigmund currently supports two signing/verification backends — GnuPG (`GpgRunner`) and Sequoia (`SqRunner`). Both are concrete classes with no shared interface. The orchestration layer (`HybridSigner`, `HybridVerifier`, `SignatureBlockVerifier`), CLI commands, and Maven plugin all reference the concrete types directly.

The existing `trust-config.yaml` already expresses an identity-first model:

```yaml
signers:
  alice:
    uid: "Alice <alice@example.com>"
    openpgp-v4: "4AEE18F83AFDEB23"
    openpgp-v6: "ABCD1234..."

trust:
  "org.example:*": [alice]
```

This doesn't say "verify the GPG signature." It says "this artifact should be from Alice" and uses OpenPGP signatures as *evidence* to prove that. The config already separates:

1. **Named identities** (signers) — who do I know?
2. **Artifact-to-identity mapping** (trust) — who should have produced what?
3. **Verification policy** (settings) — how strict am I?
4. **Evidence** (openpgp-v4/openpgp-v6/uid fields) — how do I confirm identity?

But the code doesn't reflect this. Identity matching, policy enforcement, and signature verification are interleaved in `VerifyMojo` — a Maven plugin class.

The OpenPGP ecosystem itself is splitting. GnuPG has chosen to follow [LibrePGP](https://www.librepgp.org/) rather than the IETF-standardized [RFC 9580](https://www.rfc-editor.org/rfc/rfc9580.html). LibrePGP defines its own v5 key format, while RFC 9580 defines v6. GnuPG 2.5 already has experimental v5 key support with Kyber+ECC (PQC encryption), while Sequoia PGP implements RFC 9580 and handles v6 keys (both classical and post-quantum). The two specs are diverging — v4 is the common ground, but v5 (LibrePGP) and v6 (RFC 9580) are incompatible. The architecture must treat these as distinct credential types, not assume a single "OpenPGP" format that all tools handle uniformly.

Beyond the current OpenPGP tools, [Sigstore](https://docs.sigstore.dev/language_clients/java/) is emerging as a major signing paradigm for the Java ecosystem, with [Maven Central actively integrating it](https://www.sonatype.com/blog/pgp-vs.-sigstore-a-recap-of-the-match-at-maven-central) alongside PGP. The architecture must accommodate fundamentally different signing models — not just multiple OpenPGP implementations, but also keyless/OIDC-based systems like Sigstore, and potentially X.509/PKCS#7 (JAR signing), AWS Signer, or Notation (OCI container signing).

## Decision

Restructure Sigmund around identity-based trust verification. The primary question becomes **"is this artifact from someone I trust?"** rather than "does this signature verify?"

The architecture has two layers:

1. **Identity verification layer** — trust policy, credential matching, verdicts
2. **Signature operations layer** — format handling, tool SPI, signing/verification mechanics

### Core concepts

```
Layer 1 — Identity Verification:
  ArtifactIdentity        — generic identity for an artifact (namespace, name, version)
  SignerIdentity          — a named entity with an extensible credential bag
  Credential              — a typed identity credential (fingerprint, email, OIDC, x509, ...)
  TrustPolicy             — maps artifact patterns → expected signer identities + policy settings
  DiscoveryConfig         — operational settings for key fetching and keyservers
  EvidenceProvider        — general SPI: verifies evidence of identity (files → proven credentials)
  EvidenceResult          — verified evidence with proven credentials
  TrustResult             — the verdict: is this artifact from a trusted identity?

Layer 2 — Signature Operations:
  SignatureFormat         — owns format-specific parsing, detection, and combining
  SignatureTool           — SPI for signing/verification backends
  VerificationUnit        — a single verifiable piece from a signature file
  VerifyResult            — typed per-backend verification result

Bridge:
  SignatureEvidenceAdapter — wraps a SignatureFormat + its SignatureTools into EvidenceProvider (one per format)

Configuration:
  SigmundConfig           — unified config parsed from YAML (signers + TrustPolicy + SigningConfig + DiscoveryConfig)

Facade:
  Sigmund                 — tool registry, discovery, signature verification, session creation
  Signer                  — producer use case (sign)
  TrustVerifier           — consumer use case (trust assessment)
```

---

## Layer 1: Identity Verification

### ArtifactIdentity

A generic artifact identity not tied to any package manager. The core interface carries only universally shared fields:

```java
public interface ArtifactIdentity {
    String namespace();     // Maven: groupId, npm: scope, OCI: registry/org
    String name();          // Maven: artifactId, npm: package name
    String version();       // version string
}
```

Ecosystem-specific implementations add their own fields:

```java
// In the Maven plugin module
public record MavenArtifactIdentity(
    String namespace,       // groupId
    String name,            // artifactId
    String version,
    String type,            // "jar", "pom", etc.
    String classifier       // "sources", "javadoc", etc.
) implements ArtifactIdentity {
}
```

Trust config patterns use a colon-separated format with 1-3 parts mapping directly to the interface fields: `namespace`, `namespace:name`, or `namespace:name:version`. This is sufficient for Maven (where trust is expressed at the module level — `groupId:artifactId:version` — covering all types and classifiers within that module) and generic enough for most ecosystems. Pattern matching on these fields lives entirely in core.

Note: ecosystems where names contain colons or slashes (e.g., OCI registry references like `registry.io/org/image:tag`) may need an alternative pattern syntax or escaping rules. This is not a concern for the initial implementation but should be revisited if OCI or similar ecosystems are targeted.

### SignerIdentity and Credentials

A named entity with an extensible credential bag. Rather than hardcoding specific credential fields, a credential bag approach makes `SignerIdentity` extensible — adding support for a new backend (X.509/PKCS#7, AWS Signer, Notation for OCI containers) doesn't require schema changes, just a new credential type string.

```java
public record SignerIdentity(
    String id,                      // reference name (e.g., "alice", "ci-pipeline")
    String displayName,             // human-readable name
    List<Credential> credentials    // extensible credential bag
) {
}

public interface Credential {
    String type();                  // "openpgp-v4", "openpgp-v6", "email", "oidc", "x509", etc.
    String displayName();      // human-readable representation
    boolean matches(Credential other); // type-specific matching (e.g., fingerprint suffix)
}
```

Concrete credential types provide type safety where it matters:

```java
public record FingerprintCredential(String type, String fingerprint)
        implements Credential {
    public String displayName() { return fingerprint; }
}
// type = "openpgp-v4" or "openpgp-v6", value = the fingerprint

public record EmailCredential(String email) implements Credential {
    public String type() { return "email"; }
    public String displayName() { return email; }
}

public record OidcCredential(String issuer, String subject) implements Credential {
    public String type() { return "oidc"; }
    public String displayName() { return subject + " (via " + issuer + ")"; }
    // matches() checks both issuer and subject
}
```

The YAML config stays flat — each key under a signer maps to a credential type:

```yaml
signers:
  alice:
    name: "Alice"
    email: "alice@example.com"
    openpgp-v4: "4AEE18F83AFDEB23"
    openpgp-v6: "ABCD1234..."

  ci-pipeline:
    name: "CI Pipeline"
    oidc:
      issuer: "https://token.actions.githubusercontent.com"
      subject: "https://github.com/org/repo"

  # uid shorthand still accepted, parsed into name + email
  bob: "Bob <bob@example.com>"
```

The parser maps YAML keys to credential types (`openpgp-v4` → `FingerprintCredential("openpgp-v4", ...)`, `email` → `EmailCredential(...)`, `oidc` → `OidcCredential(issuer, subject)`, etc.). A new backend registers its credential type string and the parser learns a new key — no schema changes needed.

**Credential type naming** — the OpenPGP credential types are named after the key version (`openpgp-v4`, `openpgp-v6`), not the algorithm family or the tool. This reflects the LibrePGP / RFC 9580 split in the OpenPGP ecosystem: GnuPG follows LibrePGP and will remain v4-only, while Sequoia follows RFC 9580 and handles v6 keys. Naming by version rather than by tool (`gpg`/`sq`) or algorithm family (`classical`/`pqc`) keeps the credential types accurate regardless of which tool handles them — SQ can produce both v4 and v6 signatures. A v6 key can use either classical (e.g., Ed448) or post-quantum (e.g., ML-DSA-87+Ed448) algorithms — the algorithm is a property of the key itself, determined at key generation time and reported back via `SignResult.algorithm()` after signing. The credential type determines tool routing, not the algorithm.

**`email` vs `oidc` credentials** serve different matching needs:
- **`email`** — simple credential. Matches OpenPGP UIDs (combined with name) and Sigstore email-based subjects. Sufficient when the OIDC issuer doesn't matter or is implicitly trusted.
- **`oidc`** — compound credential (issuer + subject). Required for CI pipelines, service accounts, and cases where the issuer must be verified (matching just the subject without the issuer is insecure — different IdPs could issue the same subject).

A Sigstore `extractCredentials()` produces both: an `OidcCredential(issuer, subject)` and, if the subject is an email, an `EmailCredential(subject)`. Matching tries the strictest credential first (`oidc` requires both issuer and subject to match) before falling back to `email` (subject only).

### TrustPolicy

Defines who should produce what and how strictly to verify. Declared as an interface to allow pluggable policy sources beyond YAML (e.g., OPA, database-backed). The default implementation is parsed from `sigmund.yaml` via `SigmundConfig`.

```java
public interface TrustPolicy {

    // Look up expected signers for an artifact.
    // Returns an empty list if the artifact has no trust mapping (NOT_CONFIGURED).
    // A trust mapping with zero signers is a config error caught at parse time.
    List<SignerIdentity> expectedSigners(ArtifactIdentity artifact);

    // Is this artifact explicitly marked as unsigned-ok?
    boolean isUnsignedAllowed(ArtifactIdentity artifact);

    // Policy settings
    boolean requireAllEvidenceMatch();  // true: every piece of evidence must match
                                         // an expected signer (no unmatched evidence allowed)
                                         // false: at least one match is sufficient
    UntrustedPolicy onUntrusted();  // FAIL or WARN for unmatched artifacts
}
```

`TrustPolicy` is purely about trust decisions — who to trust and how strict to be. Operational concerns like key fetching and keyserver configuration live in `DiscoveryConfig`. This means a `TrustPolicy` backed by OPA or a database doesn't need to implement key-fetching logic.

### DiscoveryConfig

Operational settings for key discovery, signer info resolution, and per-tool verification configuration — separated from trust policy because these are transport/infrastructure concerns, not trust decisions.

```java
public record DiscoveryConfig(
    boolean fetchSignerInfo,                // attempt to fetch missing signer info?
    boolean importToKeyring,                // true: persist fetched keys into the tool's keyring
                                            // false (default): fetch ephemerally, discard after verification
    List<String> keyservers,                // keyservers for key discovery (empty = tool defaults)
    Map<String, Map<String, String>> tools  // per-tool verification settings (e.g., sigstore → trusted-root)
) {
    public static final DiscoveryConfig DEFAULT =
            new DiscoveryConfig(true, false, List.of(), Map.of());
}
```

**`keyservers`** — when non-empty, these keyservers are used for key fetching, overriding the tool's built-in defaults. When empty (the default), each tool uses its own default resolution — GPG delegates to dirmngr (which has its own keyserver configuration), Sequoia uses its configured certificate sources. This means `fetchSignerInfo: true` with an empty keyservers list is valid: the tools know where to look.

When `fetchSignerInfo` is true and a key is missing during verification, the behavior depends on `importToKeyring`:
- **`false`** (default) — the key is fetched to a temporary location, used for verification, then discarded. This avoids side effects on the shared GPG keyring, which other tools on the system may interpret as extending trust. Safe for CI and multi-tool environments.
- **`true`** — the key is imported into the tool's keyring (GPG keyring, Sequoia cert store). Convenient for interactive use where the user wants their keyring populated as a side effect of verification.

To avoid repeated keyserver fetches when `importToKeyring` is false, the `Sigmund` instance maintains an internal key cache (in-memory or temp directory) scoped to its lifetime. The first fetch for a given key ID goes to the keyserver; subsequent verifications within the same session reuse the cached copy. The cache is discarded when the `Sigmund` instance is garbage-collected or closed.

**`tools`** — per-tool verification settings, keyed by tool name. This mirrors the `signing.tools` section but for verification/discovery concerns. Each tool defines its own recognized keys. The top-level `fetchSignerInfo`, `importToKeyring`, and `keyservers` fields cover OpenPGP tools; backends with fundamentally different verification models use their own `tools` entry:

```yaml
discovery:
  fetch-signer-info: true
  import-to-keyring: false
  keyservers:
    - "hkps://keys.openpgp.org"
  tools:
    sigstore:
      trusted-root: "/path/to/trusted-root.json"   # custom trust root (default: Sigstore public TUF root)
      rekor-url: "https://rekor.example.com"        # custom Rekor instance (default: public Rekor)
      offline: "false"                               # skip online Rekor verification (default: false)
    sq:
      home: "/custom/sequoia/home"                   # override SEQUOIA_HOME
```

Tools receive their settings map at construction time. Unrecognized keys are ignored (forward compatibility). When no `tools` entry exists for a tool, it uses its built-in defaults. This keeps `DiscoveryConfig` generic while allowing each backend to define its own verification-time settings without polluting the top-level fields.

### SigmundConfig

The unified configuration parsed from a single YAML file. Produces separate typed objects for different consumers while keeping the user's configuration in one place.

```java
public record SigmundConfig(
    int version,                             // schema version (currently 1)
    Map<String, SignerIdentity> signers,      // shared identity registry
    TrustPolicy trustPolicy,                 // references signers via trust mappings
    SigningConfig signingConfig,              // references a signer for production
    DiscoveryConfig discoveryConfig
) {
    static SigmundConfig parse(Path file);
}
```

`signers` is a top-level shared registry of known identities — not owned by trust or signing, but referenced by both. `TrustPolicy` receives the signers it needs (via trust mappings), and `SigningConfig` references a signer by name. Callers that construct `TrustPolicy`, `SigningConfig`, or `DiscoveryConfig` programmatically (OPA, tests, hardcoded config) never touch `SigmundConfig` or YAML.

**Limitation: shared credential bag affects both signing and verification.** Because signers are a shared registry, adding credentials for signing (e.g., fingerprints) also makes them available for verification matching. This can be surprising when a project both signs its own artifacts and verifies dependencies signed with different keys of the same type — e.g., signing v2.0 with a new key while depending on v1.0 artifacts signed with an old key. Since YAML keys are unique per signer, each credential type can have at most one value in the config. The workaround is to define separate signer entries:

```yaml
signers:
  alice:
    openpgp-v4: "NEW_KEY"
  alice-legacy:
    openpgp-v4: "OLD_KEY"

signing:
  signer: alice

trust:
  "org.example:*": [alice, alice-legacy]
```

A future refinement could allow multiple values per credential type (e.g., `openpgp-v4: ["OLD_KEY", "NEW_KEY"]`) with signing selecting a specific one, but this is deferred.

### SigningConfig

Configures which identity to sign as and which credential types (tools) to use. References a signer from the shared `signers` registry by name.

```java
public record SigningConfig(
    String signer,                           // signer identity name (e.g., "alice")
    Map<String, ToolConfig> tools,           // tool-specific overrides keyed by tool name
    Map<String, List<String>> profiles,      // profile name → credential types to use
    String defaultProfile                    // optional, null = use all credentials
) {
    public static final SigningConfig DEFAULT = new SigningConfig(null, Map.of(), Map.of(), null);
}

public record ToolConfig(
    List<String> credentials,                // credential types this tool handles (overrides defaults)
    Map<String, String> settings             // tool-specific settings (e.g., cipher-suite)
) {
}
// The parser extracts `credentials` as a first-class field;
// remaining keys become entries in `settings`.
```

The signing identity's credentials determine which tools are used. The builder routes credential types to tools via `SignatureTool.supportedCredentialTypes()` — each tool declares what credential types it can handle (see [Credential-to-tool routing](#credential-to-tool-routing) under SignatureTool). When multiple tools support the same credential type, the builder uses `canSign()` availability to resolve ambiguity (see [Credential-to-tool routing](#credential-to-tool-routing) under SignatureTool). Profiles reference credential types (not tool names) to select subsets for different signing scenarios. No key material lives in the config file — only references to keys in keyrings and cert stores.

The `tools` section provides tool-specific overrides, namespaced by tool name to avoid collisions. Each tool entry can include a `credentials` list to override the default credential-to-tool routing, plus any tool-specific settings:

```yaml
signing:
  signer: alice
  profiles:
    hybrid: [openpgp-v4, openpgp-v6]
    v6-only: [openpgp-v6]
    classical: [openpgp-v4]
  default-profile: hybrid
  tools:
    sq:
      credentials: [openpgp-v6]       # explicit: SQ handles v6 (this is also the default)
      cipher-suite: "mldsa87-ed448"
```

When `credentials` is omitted for a tool, the builder uses the tool's `supportedCredentialTypes()` defaults. When present, it overrides which credential types that tool handles. To route all OpenPGP signing through SQ (bypassing GPG entirely):

```yaml
  tools:
    sq:
      credentials: [openpgp-v4, openpgp-v6]  # SQ handles both v4 and v6
```

The YAML file uses namespaced sections. A `version` field is reserved at the top for future schema evolution — the parser records it but does not enforce it in the initial implementation:

```yaml
version: 1

signers:
  alice:
    name: "Alice"
    email: "alice@example.com"
    openpgp-v4: "4AEE18F83AFDEB23"
    openpgp-v6: "ABCD1234..."

  ci-pipeline:
    name: "CI Pipeline"
    oidc:
      issuer: "https://token.actions.githubusercontent.com"
      subject: "https://github.com/org/repo"

  # uid shorthand still accepted, parsed into name + email
  bob: "Bob <bob@example.com>"

signing:
  signer: alice
  profiles:
    hybrid: [openpgp-v4, openpgp-v6]
    v6-only: [openpgp-v6]
    classical: [openpgp-v4]
  default-profile: hybrid
  tools:
    sq:
      cipher-suite: "mldsa87-ed448"

trust:
  "org.example:*": [alice, bob]

unsigned:
  - "org.example:unsigned-lib"

policy:
  on-untrusted: fail
  require-all-evidence-match: true

discovery:
  fetch-signer-info: true
  import-to-keyring: false
  keyservers:
    - "hkps://keys.openpgp.org"
  tools:
    sigstore:
      trusted-root: "/path/to/trusted-root.json"
```

The parser maps `signers` into a shared `Map<String, SignerIdentity>`, then constructs `TrustPolicy` from `signers` + `trust` + `unsigned` + `policy`, `SigningConfig` from `signing`, and `DiscoveryConfig` from `discovery`. All sections are optional — a verify-only project omits `signing`, a sign-only project omits `trust`.

The config file parsing moves from the Maven plugin to core. The config file is named `sigmund.yaml`. The file is resolved from a single location — no merging across multiple files:

- **CLI** — current working directory (`./sigmund.yaml`)
- **Maven plugin** — project base directory (`${project.basedir}/sigmund.yaml`)
- **Fallback** — `~/.sigmund/sigmund.yaml` (user home) if not found in the primary location

The first file found wins. Config merging (e.g., user-level defaults overridden by project-level settings) is not supported in the initial implementation.

### EvidenceResult

The output of verifying a piece of evidence. Carries the proven credentials so identity matching is type-agnostic:

```java
public class EvidenceResult {
    VerificationResult result();            // PASS, FAIL, NO_KEY, SKIPPED
    List<Credential> provenCredentials();   // credentials this evidence proves
    String mechanism();                     // "openpgp", "sigstore", "slsa", etc.
}
```

`EvidenceResult` carries only what the identity matching layer needs — the verification outcome and proven credentials. Provider-specific details (OpenPGP key IDs, Sigstore log indices) are handled internally by each `EvidenceProvider` and don't leak into the trust layer.

A verified OpenPGP v4 signature produces `provenCredentials` containing a `FingerprintCredential("openpgp-v4", "AB01CD23EF45678901234AEE18F83AFDEB230042")`. A verified Sigstore bundle produces an `EmailCredential("alice@example.com")`.

### EvidenceProvider

The general interface for anything that can verify evidence of identity. This is what `TrustVerifier.assess()` works with. It operates at a higher level than `SignatureTool` — takes a file, returns proven credentials.

```java
public interface EvidenceProvider {
    String name();
    boolean isAvailable();

    // Can this provider handle the given evidence file?
    boolean canHandle(Path evidenceFile);

    // Verify evidence and return results with proven credentials
    List<EvidenceResult> verify(Path artifactFile, Path evidenceFile);
}
```

**`EvidenceProvider` and `SignatureTool` are separate SPIs** — they don't inherit from each other. They serve different layers:

- `EvidenceProvider` is the Layer 1 interface — file in, `EvidenceResult` (with proven credentials) out. Used by `TrustVerifier.assess()`.
- `SignatureTool` is the Layer 2 interface — `VerificationUnit` in, `VerifyResult` out, plus signing. Used by `Signer`.

**Bridging**: a `SignatureEvidenceAdapter` wraps a `SignatureFormat` and its associated `SignatureTool`s into an `EvidenceProvider`. There is one adapter per format, not per tool — the adapter parses the file once and routes each `VerificationUnit` to the right tool via `canVerify()`:

1. `SignatureFormat.canHandle(file)` → detection
2. `SignatureFormat.parse(file)` → `VerificationUnit`s
3. For each unit, find a `SignatureTool` where `canVerify(unit)` is true
4. `SignatureTool.verify(artifact, unit)` → `VerifyResult`
5. If `NO_KEY` and `DiscoveryConfig.fetchSignerInfo()` is enabled, fetch the key using the unit's metadata (e.g., `issuerFingerprint()` for OpenPGP) and re-verify. If `importToKeyring` is true, the key is imported via `KeyImporter.importKey()`; otherwise the key is fetched to a temporary location and discarded after verification.
6. `SignatureTool.extractCredentials(result)` → proven credentials
7. Wrap into `EvidenceResult`

Key fetching lives in the adapter because it has all the context needed — the `VerificationUnit` (with the fingerprint to fetch), the `SignatureTool` (to re-verify), and `DiscoveryConfig` (provided at construction via the builder). This keeps `EvidenceResult` clean and `TrustVerifier.assess()` free of signature-layer concerns.

This avoids redundant parsing when multiple tools share a format (e.g., GPG and SQ both use `OpenPgpSignatureFormat`) and keeps one evidence file → one provider as the common case.

**Non-signature evidence providers** implement `EvidenceProvider` directly — no `SignatureFormat`, no `VerificationUnit`, no `sign()`:

```
EvidenceProvider                              ← TrustVerifier works with this
├── SlsaAttestationProvider  (direct impl)    ← future
├── SbomVerifier             (direct impl)    ← future
└── SignatureEvidenceAdapter                  ← bridges Layer 2 → Layer 1
      one per SignatureFormat, routes units to matching SignatureTools

SignatureTool                                 ← Signer works with this
├── GpgRunner
├── SqRunner
└── SigstoreTool
```

### Identity matching

Matching checks for overlap between a signer's credential bag and evidence's proven credentials — no `instanceof` cascades, fully extensible:

```java
boolean matches(SignerIdentity signer, EvidenceResult evidence) {
    for (Credential proven : evidence.provenCredentials()) {
        for (Credential expected : signer.credentials()) {
            if (expected.matches(proven))
                return true;
        }
    }
    return false;
}
```

Credential-type-specific matching logic (e.g., fingerprint suffix matching, case-insensitive comparison) lives in the `Credential.matches()` implementation. Mismatched credential types return `false` — a `FingerprintCredential` never matches an `EmailCredential`. Cross-backend matching works because `extractCredentials()` produces all applicable credential types: a Sigstore verification produces both an `OidcCredential` and an `EmailCredential` (when the subject is an email), so a signer configured with only an `email` credential matches via the `EmailCredential` in the proven set — no cross-type matching needed.

### Credential provenance trust boundary

The credential type string (`"openpgp-v4"`, `"openpgp-v6"`, `"oidc"`, etc.) is an assertion by the tool about *how* the credential was proven — not a claim from the signature data. The trust chain ensures correctness:

1. `SignatureFormat.parse()` extracts units with packet metadata (version, fingerprint)
2. `SignatureTool.canVerify()` gates routing — a v4 packet reaches GPG, a v6 packet reaches SQ
3. `SignatureTool.verify()` cryptographically validates the signature, proving the fingerprint
4. `SignatureTool.extractCredentials()` types the credential based on the packet version verified — a tool verifying a v4 packet produces `FingerprintCredential("openpgp-v4", ...)`, a tool verifying a v6 packet produces `FingerprintCredential("openpgp-v6", ...)`. The credential type follows the packet version, not the tool identity — if SQ verifies a v4 packet, it produces `openpgp-v4`, not `openpgp-v6`.

A signature cannot "claim" a credential type it wasn't verified through. The credential type is determined by the packet version that was cryptographically verified, not by what tool performed the verification. This is why `extractCredentials()` lives on `SignatureTool` rather than on `VerifyResult` — the tool has access to both the verification result and the unit's packet metadata to determine the correct credential type.

### TrustResult

The verdict for an artifact — the answer to "is this from someone I trust?":

```java
public class TrustResult {
    ArtifactIdentity artifact();
    TrustVerdict verdict();
    List<MatchedEvidence> matchedEvidence();         // evidence that matched an expected signer
    List<EvidenceResult> unmatchedEvidence();        // valid evidence that didn't match any expected signer
}

public record MatchedEvidence(
    SignerIdentity signer,
    EvidenceResult evidence
) {
}

public enum UntrustedPolicy {
    FAIL,           // reject untrusted artifacts
    WARN            // log a warning but continue
}

public enum TrustVerdict {
    TRUSTED,            // evidence matches expected signer(s)
    UNTRUSTED,          // evidence present but doesn't match expected signers
    UNSIGNED,           // no evidence found
    NOT_CONFIGURED,     // artifact not in trust policy
    VERIFICATION_FAILED // evidence present but cryptographically invalid
}
```

---

## Layer 2: Signature Operations

### SignatureFormat

Each signature format (OpenPGP, Sigstore, etc.) has its own file format, detection logic, and rules for combining multiple signatures. `SignatureFormat` encapsulates all of this, keeping the facade and tools format-agnostic.

```java
public interface SignatureFormat {

    String name();              // "openpgp", "sigstore"
    String fileExtension();     // ".asc", ".sigstore.json"

    // Content-based detection — can this format handle the given signature file?
    boolean canHandle(Path signatureFile);

    // Parse a signature file into individually verifiable units
    List<VerificationUnit> parse(Path signatureFile);

    // Combining — optional capability. Not all formats support merging
    // multiple signatures into a single file (e.g., Sigstore bundles are
    // standalone). Defaults to writing a single input unchanged and
    // rejecting multiple.
    default boolean supportsCombining() { return false; }
    default void combine(List<Path> signatures, Path output) {
        if (signatures.size() == 1) { /* copy single file */ return; }
        throw new UnsupportedOperationException(
                name() + " format does not support combining signatures");
    }
}
```

`canHandle()` and `parse()` take `Path` rather than `String` so each format reads files in its natural representation — `OpenPgpSignatureFormat` reads text, a hypothetical PKCS#7 format reads binary. This avoids forcing all content through `String`, which would require lossy or wasteful conversions for binary formats.

**`VerificationUnit`** — a single verifiable piece extracted from a signature file. The sealed interface carries no shared state — each implementation holds content in its natural form, avoiding `String ↔ byte[]` roundtrips:

```java
public sealed interface VerificationUnit
        permits OpenPgpVerificationUnit, SigstoreVerificationUnit {
}

public record OpenPgpVerificationUnit(
    String armoredBlock,        // text — natural for OpenPGP
    int packetVersion,          // 4, 6, etc.
    String issuerFingerprint,   // from the signature packet
    int algorithmId             // IANA algorithm ID
) implements VerificationUnit {
}

public record SigstoreVerificationUnit(
    String jsonBundle           // text — natural for Sigstore
) implements VerificationUnit {
}

// Adding a new format requires adding a permits entry and a new implementation.
// future example:
// public record Pkcs7VerificationUnit(
//     byte[] signature        // binary — natural for PKCS#7
// ) implements VerificationUnit {
// }
```

**Implementations:**

- **`OpenPgpSignatureFormat`** — absorbs current `AscCombiner` logic for block extraction, packet inspection, armor detection, and block combining. Overrides `supportsCombining() → true` and `combine()` to concatenate armored blocks. Shared by all OpenPGP tools (GPG, SQ). Can be a singleton.
- **`SigstoreSignatureFormat`** — detects JSON bundles, returns the whole content as one `SigstoreVerificationUnit`. Inherits default `supportsCombining() → false` — each signing produces its own standalone bundle file.

### SignatureTool

The SPI that backends implement. Focused on signing and verification. Linked to a `SignatureFormat` via direct reference.

```java
public interface SignatureTool {

    String name();
    boolean isAvailable();
    boolean canSign();                      // true if constructed with signing credentials
    SignatureFormat signatureFormat();       // the format this tool produces and consumes

    // Credential types this tool can sign with (e.g., ["openpgp-v4"], ["openpgp-v4", "openpgp-v6"], ["oidc"])
    // Used by the builder to route signer credentials to tools for signing.
    // Not used for verification — canVerify() handles that based on unit content.
    Set<String> supportedCredentialTypes();

    // Can this tool verify the given unit? (e.g., GPG handles v4 blocks, SQ handles v5+)
    boolean canVerify(VerificationUnit unit);

    // Core operations
    SignResult sign(Path artifactFile, Path outputSig);
    VerifyResult verify(Path artifactFile, VerificationUnit unit);

    // Credential extraction — the tool knows what credentials its results prove
    List<Credential> extractCredentials(VerifyResult result);
}
```

**`SignResult`** — returned by `sign()` so the tool can report what algorithm it actually used (important for multi-algorithm tools like a Bouncy Castle backend that supports both RSA and Ed25519):

```java
public record SignResult(
    String algorithm        // the algorithm actually used for signing
) {
}
```

**File I/O responsibility**: the tool writes the signature to the provided `outputSig` path (CLI tools like `gpg` and `sq` need an output path). The `Signer` owns the overall lifecycle — it assigns temp paths, calls each tool, then groups and combines the results into final output files. `SignResult` only carries the algorithm because the `Signer` already knows the path (it assigned it), the tool name (`tool.name()`), and the format (`tool.signatureFormat()`).

**Concurrency.** `SignatureTool` instances may be called from concurrent threads or processes (e.g., parallel Maven module builds signing artifacts simultaneously). Implementations must be safe for concurrent use. Since tools are configured at construction and carry no mutable state after that, the Java side is naturally thread-safe. However, implementations wrapping CLI tools must account for underlying tool constraints — e.g., GPG may lock the keyring during concurrent operations, and SQ may contend on the cert store. Implementations should handle or document these limitations.

**Tools are fully configured at construction time.** Credentials (key IDs, fingerprints, OIDC provider references) are provided when the tool is created. `sign()` takes no credential argument — the tool embodies its context. `canSign()` returns true only if signing credentials were provided.

**Online and interactive signing.** The `sign()` contract is synchronous and blocking — it accommodates tools that require network access or user interaction during signing. Sigstore, for example, performs OIDC authentication (interactive browser flow or CI token), requests an ephemeral certificate from Fulcio, and logs the signature in Rekor — all within a single `sign()` call. This complexity is internal to the tool implementation; the caller sees the same `sign(Path, Path) → SignResult` interface regardless of whether the tool is a local CLI wrapper or an online service. Whether signing is interactive or automated is determined by the tool's construction-time configuration (e.g., OIDC token source), not by the `sign()` method. Network or authentication failures are infrastructure errors and surface as `ToolExecutionException`.

**`supportedCredentialTypes()`** declares which credential types a tool can sign with. This is a **capability** declaration — it says what the tool *can* do, not what it *will* do in a given configuration. Built-in tools declare:

| Tool | `supportedCredentialTypes()` |
|------|------------------------------|
| `GpgRunner` | `["openpgp-v4"]` |
| `SqRunner` | `["openpgp-v4", "openpgp-v6"]` |
| `SigstoreTool` | `["oidc"]` |

Note that SQ supports both v4 (classical) and v6 (classical or PQC) OpenPGP signatures — the credential type reflects the key version, not the algorithm. The algorithm is a property of the key itself.

**Credential-to-tool routing** — the builder uses `supportedCredentialTypes()` and `canSign()` to decide which tool handles each credential from the signing identity. The routing has three steps:

1. **Capability match** — for each credential in the signer's identity, find tools whose `supportedCredentialTypes()` contains that credential type. This is a static check.
2. **Availability check** — construct each candidate tool with the credential and check `canSign()`. A tool returns `canSign() → false` if the key isn't actually in its keyring or cert store. This filters out tools that theoretically support the credential type but don't have the key material.
3. **Ambiguity resolution** — if a single tool survives for a credential type, use it. If multiple tools survive (e.g., both GPG and SQ have signing keys available for the `openpgp-v4` credential type), fail with a configuration error directing the user to disambiguate via `tools.*.credentials`.

In the common case, ambiguity resolves naturally because only one tool has a signing key available for a given credential type. For example, if Alice's `openpgp-v4` fingerprint is in GPG's keyring but SQ has no v4 key available, GPG is the only viable candidate — no config needed. A credential type with no matching tool is silently skipped (the signer may have credentials that are only relevant for verification, such as `email`).

The `tools` section in the config explicitly assigns credential types to tools, bypassing the automatic routing above:

```yaml
signing:
  signer: alice
  tools:
    sq:
      credentials: [openpgp-v4, openpgp-v6]   # override: SQ handles both v4 and v6
      cipher-suite: "mldsa87-ed448"
```

In this example, GPG is not used for signing even though it supports `openpgp-v4` — the explicit assignment takes precedence. When `credentials` is present for any tool, only those explicit assignments are used for the listed credential types — automatic routing applies only to credential types not covered by any explicit assignment.

**Signing vs verification routing** — `supportedCredentialTypes()` is only used for signing (mapping credentials to tools). Verification routing uses `canVerify(VerificationUnit)` instead, which examines the parsed signature content (e.g., OpenPGP packet version) to find the right tool. These are separate mechanisms because signing starts from identity ("sign as Alice with her v6 key") while verification starts from evidence ("this signature block is v6, who can verify it?").

**`canVerify(VerificationUnit)`** lets each tool declare what it can handle within its format. For OpenPGP, GPG handles `packetVersion() < 6` and SQ handles `packetVersion() >= 6` (v5 is LibrePGP-only and currently experimental; the boundary is v6 per RFC 9580, matching the current `SignatureBlockVerifier` implementation). For Sigstore, the tool always handles its own unit type. This keeps all routing decisions out of the facade.

### Capability interfaces

Operations that only some backends support are modeled as separate interfaces, not forced onto all tools:

```java
public interface KeyGenerator {
    String generateKey(String userId, String cipherSuite);
}

public interface CertExporter {
    String exportCert(String fingerprint);
}

public interface KeyImporter {
    boolean importKey(String keyId, String keyserver);
}

public interface SignerIdentityResolver {
    String lookupKeyUserId(String keyId);
}
```

Backend implementations:
- **GpgRunner** implements `SignatureTool, KeyImporter, SignerIdentityResolver` — `supportedCredentialTypes() → ["openpgp-v4"]`
- **SqRunner** implements `SignatureTool, KeyGenerator, CertExporter` — `supportedCredentialTypes() → ["openpgp-v4", "openpgp-v6"]`
- **SigstoreTool** implements just `SignatureTool` (keyless — no key management) — `supportedCredentialTypes() → ["oidc"]`

### Error model

The SPI distinguishes between **verification outcomes** (the evidence was examined and a conclusion was reached) and **infrastructure failures** (verification couldn't be attempted).

**Verification outcomes are always result objects, never exceptions:**
- Cryptographically invalid signature → `VerifyResult` with `FAIL`
- Corrupt or malformed evidence → `VerifyResult` with `FAIL`
- Signing key not in keyring/store → `VerifyResult` with `NO_KEY`
- Tool can't handle this unit → `VerifyResult` with `SKIPPED`

**Infrastructure failures are unchecked exceptions:**
- CLI tool not found or crashed mid-operation
- I/O errors (disk, network)
- Transparency log or keyserver unreachable
- These prevent verification from completing — the caller needs to know something went wrong, not that the signature was invalid

**Configuration errors fail fast at construction/parse time:**
- Malformed trust policy YAML
- Invalid signer or credential references
- These are detected during `SigmundConfig.parse()` or `Sigmund.builder().build()`, not deferred to `assess()` time

Exception hierarchy:

```java
public class SigmundException extends RuntimeException { ... }

// Tool-level failures (CLI tool crashed, I/O error during sign/verify)
public class ToolExecutionException extends SigmundException { ... }

// Trust policy configuration errors (bad YAML, invalid references)
public class PolicyConfigException extends SigmundException { ... }
```

All SPI methods use unchecked exceptions — implementations are not forced to declare specific checked exceptions, and callers can catch `SigmundException` broadly or specific subtypes as needed.

### VerificationResult enum

The existing `VerificationResult` enum is reused across both layers (`EvidenceResult.result()` and `VerifyResult.result()`). The current `NOT_PRESENT` value is dropped — in the new architecture, absence is handled structurally: no evidence files produces `TrustVerdict.UNSIGNED`, and no matching tool for a `VerificationUnit` means no `VerifyResult` is produced. The remaining values are:

- `PASS` — signature is valid
- `FAIL` — signature is invalid or data has been modified
- `NO_KEY` — required key not available (distinct from `FAIL` — configuration issue, not invalid signature)
- `SKIPPED` — verification not attempted (tool can't handle this unit)

### VerifyResult hierarchy

Verification results use typed per-backend classes with a common base:

```java
public abstract sealed class VerifyResult
        permits OpenPgpVerifyResult, SigstoreVerifyResult {
    VerificationResult result();    // PASS, FAIL, NO_KEY, SKIPPED
    String signerDisplayName();     // human-readable signer (UID, email, URI)
    String algorithm();             // signing algorithm name
}

public final class OpenPgpVerifyResult extends VerifyResult {
    int version();          // signature packet version (4, 6)
    String keyId();         // short key ID
    String fingerprint();   // full fingerprint
}

public final class SigstoreVerifyResult extends VerifyResult {
    String issuer();        // OIDC issuer URL
    String logIndex();      // Rekor transparency log entry
}
```

The facade wraps `VerifyResult` into `EvidenceResult` (Layer 1) by calling `tool.extractCredentials(result)` — each tool knows what credentials its results prove. For OpenPGP tools, `extractCredentials()` maps the verified packet version to the credential type: `version() < 6` → `FingerprintCredential("openpgp-v4", fingerprint)`, `version() >= 6` → `FingerprintCredential("openpgp-v6", fingerprint)`. Sigstore maps its result to `EmailCredential` or `OidcCredential`. The full fingerprint is used for credential matching — not the short key ID, which is insufficient for reliable identity verification.

This keeps the facade free of `instanceof` checks on `VerifyResult` subtypes — the tool owns the mapping from its result type to proven credentials. Both `VerifyResult` and `Credential` live in core, so there's no module dependency issue. The bridge between the two layers is `extractCredentials()` on the SPI.

### SigningOutput

`sign()` returns a `SigningOutput` carrying metadata about each produced file:

```java
public record SigningOutput(List<SignedFile> files) {
}

public record SignedFile(
    Path path,              // the signature file
    String toolName,        // "gpg", "sq", "sigstore"
    String format,          // "openpgp", "sigstore"
    String algorithm        // "RSA", "ML-DSA-87+Ed448", etc.
) {
}
```

CLI callers that only need paths can use `result.files().stream().map(SignedFile::path)`.

### SignatureVerificationReport — hierarchical

For direct verification (without trust policy), a hierarchical report with per-file sub-reports:

```java
public class SignatureVerificationReport {
    VerificationOutcome outcome();          // ALL_PASS, PASS_WITH_FAILURES, etc.
    List<FileSignatureReport> files();

    boolean isPass();
    boolean isLenientPass();
    String format();            // human-readable summary
}

public class FileSignatureReport {
    Path signatureFile();
    String format();                        // "openpgp", "sigstore"
    List<VerifyResult> results();           // typed per-backend
}
```

---

## The Sigmund Facade

Signing, verification, and tool management are distinct use cases with different contexts and configurations. `Sigmund` is the shared foundation (tool registry, discovery, algorithm routing) that owns direct signature verification and produces focused session objects for signing and trust assessment.

```java
public class Sigmund {

    // --- Construction ---
    static Builder builder();

    static class Builder {
        Builder discover();                         // probe known tools (verify-only)
        Builder discoveryConfig(DiscoveryConfig dc); // key fetching and keyserver settings
        Builder config(SigmundConfig config);         // apply signing + discovery config
        Builder addTool(SignatureTool tool);         // add or replace signing tool (by name)
        Builder addEvidenceProvider(EvidenceProvider provider); // add non-signature evidence provider
        Sigmund build();
    }

    // --- Session creation ---
    Signer signer();                                // default profile or all signing tools
    Signer signer(String profileName);              // named profile
    TrustVerifier verifier(TrustPolicy policy);

    // --- Direct signature verification (no trust policy) ---
    SignatureVerificationReport verify(Path artifactFile, Path signatureFile);
    SignatureVerificationReport verifyAll(Path artifactFile, List<Path> signatureFiles);

    // --- Tool access ---
    List<SignatureTool> tools();
    SignatureTool tool(String name);
    <T> T findTool(Class<T> capability);
    <T> T findTool(Class<T> capability, String toolName);

}
```

### Signer

Focused on the producer use case — signing artifacts.

```java
public class Signer {

    SigningOutput sign(Path artifactFile, Path outputDir);
}
```

### TrustVerifier

Focused on the consumer use case — identity-based trust assessment. Answers "is this artifact from someone I trust?" by combining evidence verification with trust policy matching. Direct signature verification (without trust policy) lives on `Sigmund`.

```java
public class TrustVerifier {

    // "Is this artifact from someone I trust?"
    TrustResult assess(ArtifactIdentity artifact, Path artifactFile,
            List<Path> evidenceFiles);

    // Batch assessment
    List<TrustResult> assessAll(List<AssessmentRequest> requests);
}

public record AssessmentRequest(
    ArtifactIdentity artifact,
    Path artifactFile,
    List<Path> evidenceFiles
) {
}
```

### Usage

```java
// From unified config file (sigmund.yaml)
SigmundConfig config = SigmundConfig.parse(configFile);

Sigmund sigmund = Sigmund.builder()
    .config(config)                     // apply signing + discovery config
    .discover()                         // probe for verify-only tools
    .build();

// Producer: sign artifacts
Signer signer = sigmund.signer();                  // default profile
Signer v6Signer = sigmund.signer("v6-only");        // named profile
SigningOutput result = signer.sign(artifact, outputDir);

// Consumer: trust assessment (DiscoveryConfig was set at build time via config())
TrustVerifier verifier = sigmund.verifier(config.trustPolicy());
TrustResult result = verifier.assess(artifact, artifactFile, evidenceFiles);

// Direct signature verification (no trust policy needed)
SignatureVerificationReport report = sigmund.verify(artifactFile, signatureFile);

// Programmatic construction (no config file)
Sigmund sigmund = Sigmund.builder()
    .discover()
    .addTool(new GpgRunner(gpgKey))
    .addTool(new SqRunner(sqHome, fingerprint))
    .build();
TrustVerifier verifier = sigmund.verifier(myOpaPolicy);

// Tool management: key generation, cert export
sigmund.findTool(KeyGenerator.class).generateKey(userId, cipherSuite);
sigmund.findTool(CertExporter.class).exportCert(fingerprint);
```

### Builder

- **`discover()`** — hardcoded for now: probes `GpgRunner.isAvailable()` and `SqRunner.isAvailable()`, creates verify-only instances. Only adds tools not already present (explicit `addTool()` takes precedence).
- **`discoveryConfig(DiscoveryConfig)`** — sets key fetching and keyserver configuration, fixed at build time. All `TrustVerifier` instances created from this `Sigmund` share it. If not called, defaults to `DiscoveryConfig.DEFAULT`.
- **`config(SigmundConfig)`** — applies the full config: constructs signing tools from the config's signing identity, applies tool-specific overrides, and sets `DiscoveryConfig`. See [Tool construction from config](#tool-construction-from-config) below. Overrides any prior `discoveryConfig()` call. Explicit `addTool()` calls take precedence over config-derived tools with the same name.
- **`addTool()`** — adds or replaces a `SignatureTool` by `name()`. The tool is grouped with others sharing the same `SignatureFormat` under a single `SignatureEvidenceAdapter` for use by `TrustVerifier.assess()`.
- **`addEvidenceProvider()`** — adds a non-signature `EvidenceProvider` (e.g., SLSA attestation verifier). Used only by `TrustVerifier.assess()`, not by `Signer`.
- **`build()`** — filters out tools/providers where `isAvailable()` returns false. Collects distinct `SignatureFormat` instances from the tools.

### Tool construction from config

When `config(SigmundConfig)` is called, the builder constructs live `SignatureTool` instances from the config's signing identity and tool-specific overrides. Internally, the builder delegates to `SignatureToolFactory` implementations — one per built-in tool — to keep construction logic out of the builder itself:

```java
interface SignatureToolFactory {

    String toolName();                      // "gpg", "sq", "sigstore"
    Set<String> supportedCredentialTypes();

    // Create a signing-capable tool for the given credential.
    // Returns null if the key/credential is not available in this tool's keyring/store.
    SignatureTool create(Credential credential, Map<String, String> settings);

    // Create a verify-only tool (no signing credentials).
    SignatureTool createVerifyOnly(Map<String, String> settings);
}
```

This is an internal implementation detail, not a public SPI — the builder registers built-in factories directly. Third-party tools use `addTool()` on the builder. If a `ServiceLoader`-based extension point is needed later, this interface is the natural candidate.

**Built-in factories:**

- **`GpgToolFactory`** — extracts the fingerprint from the credential, constructs `GpgRunner` with it as the signing key. Verify-only: no signing key.
- **`SqToolFactory`** — extracts the fingerprint, resolves the SQ home directory (from settings or `SEQUOIA_HOME` env var). Recognizes settings: `home`, `cipher-suite`. Verify-only: no signing fingerprint.
- **`SigstoreToolFactory`** (future) — reads OIDC configuration from settings (`oidc-provider`, `token-source`). Verify-only: reads verification settings (`trusted-root`, `rekor-url`, `offline`).

**Construction flow:**

1. Resolve the signing identity: look up `signing.signer` in the `signers` registry
2. For each credential in the identity, find a factory whose `supportedCredentialTypes()` contains the credential type (respecting `signing.tools.*.credentials` overrides)
3. Call `factory.create(credential, settings)` with merged settings (from `signing.tools.<name>` in the YAML, excluding `credentials`). Returns null if the key isn't available, meaning this tool is skipped for this credential
4. If multiple factories match a credential type and both produce a tool, fail with a configuration error (same ambiguity resolution as [credential-to-tool routing](#credential-to-tool-routing))
5. For tools not involved in signing, call `factory.createVerifyOnly(settings)` to create verify-only instances

**Extensibility boundary** — third-party *tools* within existing formats (e.g., a Bouncy Castle OpenPGP backend) can be added via `addTool()` on the builder today, or via a future `ServiceLoader`-based factory. New signature *formats*, however, require a core release: both `VerificationUnit` and `VerifyResult` are sealed hierarchies, and adding a format means adding new `permits` entries and subclasses in core. This is intentional — a new format introduces new packet structures, verification semantics, and credential types that warrant review as part of core rather than silent plug-in. The extensibility split is: tools are pluggable, formats are curated.

### `assess()` flow (TrustVerifier)

1. **Resolve policy** — look up expected signers for the artifact from the trust policy (provided at construction). If the list is empty, the artifact has no trust mapping — return `NOT_CONFIGURED` (the policy's `onUntrusted()` setting decides whether this is a failure or a warning).
2. **Check unsigned** — if the policy marks this artifact as unsigned-ok and no evidence files are present, return `TRUSTED` (explicitly allowed unsigned).
3. **Verify evidence** — for each evidence file, find an `EvidenceProvider` where `canHandle(evidenceFile)` is true and call `provider.verify(artifactFile, evidenceFile)` → list of `EvidenceResult`s with proven credentials. Since `SignatureEvidenceAdapter` is per-format (not per-tool), each evidence file typically matches a single provider. If multiple providers do match (e.g., a signature provider and a future non-signature provider both claim the file), all matching providers verify it independently — one provider failing does not taint results from others.
   - For signature evidence, the matching provider is a `SignatureEvidenceAdapter` which internally: parses into `VerificationUnit`s → routes each unit to the right `SignatureTool` via `canVerify()` → verifies → extracts credentials → wraps into `EvidenceResult`s.
   - For non-signature evidence (future: SLSA, SBOM), the matching provider is a direct `EvidenceProvider` implementation that handles the file in its own way.
4. **Match identity** — for each `EvidenceResult`, check against expected signers via credential bag overlap. Key fetching for `NO_KEY` results is already handled by `SignatureEvidenceAdapter` in step 3 (see [bridging flow](#evidenceprovider) above) — by the time results reach `assess()`, fetchable keys have been resolved.
5. **Apply policy** — based on `requireAllEvidenceMatch()`, `onUntrusted()`, and match results, produce a `TrustVerdict`.

### `sign()` flow (Signer)

1. **Resolve tools** — if a profile was specified at `signer()` creation, filter to tools matching the profile's credential types. Otherwise use all tools where `canSign()` is true. Credential-to-tool assignment follows the routing rules: explicit `tools.*.credentials` overrides take precedence, then automatic routing via `supportedCredentialTypes()` + `canSign()` availability check, failing on ambiguity.
2. Call `sign()` on each resolved tool, collecting `SignResult` (includes algorithm used)
3. Group results by `signatureFormat()`
4. For each group:
   - If `format.supportsCombining()` → call `format.combine()` to merge into one file
   - Otherwise → write each signature as a separate file
5. Write output files using `<artifact><format.fileExtension()>` (e.g., `artifact.jar.asc`, `artifact.jar.sigstore.json`). Output file names follow ecosystem conventions via the format's `fileExtension()` — no configurable suffixes.
6. Return `SigningOutput` with metadata per file

### Direct `verify()` flow (Sigmund)

1. Find the `SignatureFormat` where `canHandle(signatureFile)` is true
2. Call `format.parse(signatureFile)` to get a list of `VerificationUnit`s
3. For each unit, find a tool where `canVerify(unit)` is true
4. Call `tool.verify(artifact, unit)`
5. Collect results into a `FileSignatureReport`
6. `verifyAll()` aggregates multiple `FileSignatureReport`s into a top-level `SignatureVerificationReport`

### Signing modes

**With config file (`sigmund.yaml`)** — the `signing` section references a signer identity. The builder constructs signing tools from the signer's credentials and applies tool-specific overrides. Profiles select which credential types to use. CLI/Maven params can override config values (e.g., `-Dsigmund.fingerprint=...` overrides the v6 fingerprint).

**Without config file** — the caller provides signing keys explicitly (CLI arguments, Maven plugin parameters) and constructs tools via `addTool()`. All tools where `canSign()` is true produce signatures. No profiles.

In both modes, multiple signing tools produce multiple signatures, grouped and combined by format. No signing tools configured means verify-only.

---

## Consequences

### Module structure

**Core module** owns:
- Identity verification: `ArtifactIdentity`, `SignerIdentity`, `Credential`, `TrustPolicy`, `UntrustedPolicy`, `DiscoveryConfig`, `TrustResult`, `TrustVerdict`, `EvidenceResult`
- Configuration: `SigmundConfig`, `SigningConfig` (unified YAML parsing)
- Signature operations: `SignatureTool`, `SignatureFormat`, `VerificationUnit`, `VerifyResult`, `SignatureVerificationReport`, `SigningOutput`
- Capability interfaces: `KeyGenerator`, `CertExporter`, `KeyImporter`, `SignerIdentityResolver`
- `Sigmund` facade
- `sigmund.yaml` config file parsing (moved from Maven plugin)
- `Algorithms` utility class (IANA algorithm ID mapping, `algorithmName()`, `isPqcAlgorithmName()`, alias resolution — moved from `AscCombiner`)
- `OpenPgpSignatureFormat` (absorbs `AscCombiner` block extraction, packet inspection, combining)
- Armor/dearmor utilities remain as shared helpers (slimmed-down `AscCombiner` or new `OpenPgpArmor` utility)

**Maven plugin** owns:
- Artifact resolution (Maven repository system)
- Evidence file auto-discovery (`.asc`, `.sigstore.json` alongside artifacts)
- `MavenArtifactIdentity` (GAV-to-`ArtifactIdentity` mapping)
- Maven lifecycle integration (mojos)

**CLI module** owns:
- Command-line interface (picocli)
- Accepts explicit paths for artifacts and evidence files

### Name collision: `Sigmund` CLI class

The CLI module already has a `Sigmund` class (`cli/src/main/java/.../cli/Sigmund.java`) — the picocli `@TopCommand` entry point. The new `Sigmund` facade in the core module would collide. The CLI class should be renamed to `SigmundCli` (or similar) to free the `Sigmund` name for the facade.

### Classes absorbed or removed

- **`HybridSigner`** — absorbed into `Signer.sign()` + `SignatureFormat.combine()`
- **`HybridVerifier`** — absorbed into `Sigmund.verify()` + `SignatureFormat.parse()`
- **`SignatureBlockVerifier`** — version-based routing moves into `SignatureEvidenceAdapter` (via `canVerify()`), per-tool verification logic moves into each tool's `verify()`
- **`AscCombiner`** — split: format logic → `OpenPgpSignatureFormat`, algorithm mappings → `Algorithms`, armor utilities → shared helper
- **`TrustConfig`** — replaced by `SigmundConfig` (shared `SignerIdentity` registry + `TrustPolicy` + `SigningConfig` + `DiscoveryConfig`). This is a clean break — `trust-config.yaml` is dropped with no compatibility parser. The project is pre-1.0 with no external users to migrate.
- **`ArtifactMatcher`** — pattern matching moves to core, works on `ArtifactIdentity`
- **`VerifyMojo.VerificationState`** — becomes `TrustVerdict` enum

### Changes to GpgRunner and SqRunner

Both are refactored to implement `SignatureTool` and the relevant capability interfaces. Existing public methods that don't fit the SPI (e.g., `GpgRunner.VerifyResult`, `SqRunner.verify(Path, Path, String)`) are removed — the project is pre-1.0 with no external API consumers.

- **GpgRunner** implements `SignatureTool, KeyImporter, SignerIdentityResolver`. `verify(Path, VerificationUnit)` absorbs logic from `SignatureBlockVerifier.verifyGpgBlock()` and returns `OpenPgpVerifyResult` (replacing the inner `GpgRunner.VerifyResult` record). `importKey()` replaces `receiveKey()`, `lookupKeyUserId()` replaces `listKeyUserId()`.
- **SqRunner** implements `SignatureTool, KeyGenerator, CertExporter`. `verify(Path, VerificationUnit)` absorbs logic from `SignatureBlockVerifier.verifySequoiaBlock()`. `sign(Path, Path)` uses a stored signing fingerprint (replacing the three-arg `sign(Path, Path, String)`). `canSign()` returns true only when constructed with a fingerprint.

### Changes to callers

CLI commands and Maven plugin mojos construct tools, build a `Sigmund` instance via the builder, and call its methods.

Signature file discovery is **not** a core or facade concern:
- **CLI commands** accept explicit signature file paths from the user.
- **Maven plugin** auto-discovers signature files alongside artifacts (probing for `.asc`, `.sigstore.json`, etc.).

### Testing

Tests mock the `SignatureTool` interface directly (anonymous implementations) instead of subclassing concrete runners. `SignatureFormat` implementations and credential matching can be tested independently.

### Future directions

- **Sigstore backend**: keyless signing via OIDC identity. [sigstore-java](https://github.com/sigstore/sigstore-java) provides `KeylessSigner` and `KeylessVerifier` — a `SigstoreTool` would wrap these, implementing `SignatureTool` with `SigstoreSignatureFormat`. `supportedCredentialTypes() → ["oidc"]`. No capability interfaces needed (keyless = no key management). Sigstore signing is online (OIDC authentication → Fulcio certificate → Rekor transparency log), which fits within the `sign()` contract but requires OIDC configuration at construction time (provider URL, token source, interactive vs CI mode). Sigstore-specific verification settings (trusted root bundle, custom instance URLs, offline mode) would need a home — likely in a `tools.sigstore` section under `discovery` or a dedicated per-tool config extension.
- **OpenPGP v5 / LibrePGP backend**: GnuPG 2.5 has experimental v5 key support with Kyber+ECC for PQC encryption. If LibrePGP v5 signing matures, it would introduce an `openpgp-v5` credential type with GnuPG as the tool (`supportedCredentialTypes() → ["openpgp-v4", "openpgp-v5"]`). The version-based credential type naming was chosen with this in mind — adding v5 requires no renames, just a new credential type. The `OpenPgpSignatureFormat` would need to handle v5 packets, and `canVerify()` routing would dispatch v5 units to GnuPG. Current interoperability challenges (keyservers reject v5 keys, Sequoia cannot read them) may limit practical use in the near term.
- **Bouncy Castle backend**: pure-Java OpenPGP signing/verification without external CLI tools. Already a project dependency (`bcpg-jdk18on`). Would share `OpenPgpSignatureFormat` with GPG and SQ.
- **Non-signature evidence providers**: SLSA provenance attestations, SBOM verification, reproducible build verification. Each implements `EvidenceProvider` directly (not `SignatureTool`) and produces `EvidenceResult`s with proven credentials that feed into the same identity matching pipeline via `TrustVerifier.assess()`.
- **User configuration file**: tool paths, algorithm preferences (signing profiles are covered by `sigmund.yaml`).
- **Pluggable discovery**: Java `ServiceLoader` for third-party `SignatureTool` implementations within existing formats (e.g., a Bouncy Castle backend for OpenPGP). New signature formats require new `VerificationUnit` and `VerifyResult` subclasses in core — the sealed hierarchies make this an intentional, explicit extension point rather than something plugged in silently.
