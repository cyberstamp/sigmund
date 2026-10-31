# ADR-003: Sigstore Integration

## Status

Proposed

## Context

Sigstore is a keyless signing framework for the software supply chain. Instead of long-lived private keys, Sigstore uses ephemeral keys tied to an OIDC identity — a developer authenticates via their identity provider (GitHub, Google, Microsoft, etc.), receives a short-lived signing certificate from Fulcio, signs the artifact, and logs the signature in the Rekor transparency log. The signed artifact ships with a `.sigstore.json` bundle containing the certificate, signature, and log entry.

Maven Central [now validates Sigstore signatures](https://central.sonatype.org/news/20220310_sigstore/) alongside PGP. Several projects already publish `.sigstore.json` bundles — [Caffeine](https://repo1.maven.org/maven2/com/github/ben-manes/caffeine/caffeine/3.2.2/), [ORAS Java SDK](https://repo1.maven.org/maven2/land/oras/oras-java-sdk/0.2.7/), [WavesJ](https://repo1.maven.org/maven2/com/wavesplatform/wavesj/1.6.3/) — with both `.asc` (PGP) and `.sigstore.json` signatures present.

The Sigstore Java ecosystem is centered on [sigstore-java](https://github.com/sigstore/sigstore-java), which provides:
- `KeylessSigner` — OIDC auth → Fulcio certificate → sign → Rekor log, all in one call
- `KeylessVerifier` — bundle verification against a TUF-managed trust root
- `Bundle` — serialization/deserialization of the Sigstore bundle format (`application/vnd.dev.sigstore.bundle.v0.3+json`)
- A [Maven plugin](https://github.com/sigstore/sigstore-java/tree/main/sigstore-maven-plugin) (`dev.sigstore:sigstore-maven-plugin:2.2.0`) that demonstrates the integration pattern — the entire signing Mojo is ~100 lines wrapping `KeylessSigner.signFile()`

Sigmund's architecture (ADR-002) was designed to accommodate Sigstore as a first-class backend. The core module already contains:
- `SigstoreVerificationUnit` — holds the JSON bundle text
- `SigstoreVerifyResult` — carries OIDC issuer and Rekor log index
- `OidcCredential` — issuer + subject identity matching
- `EmailCredential` — simple email-based matching (shared between OpenPGP UIDs and Sigstore email subjects)
- `VerificationUnit` and `VerifyResult` sealed hierarchies already `permit` the Sigstore variants
- `SigmundConfigParser` already parses `oidc` credentials from YAML

What remains is the concrete implementation: a `SignatureFormat`, a `SignatureTool`, a `SignatureToolFactory`, and the integration points in the builder, Maven plugin, and CLI.

## Decision

### Module structure

The Sigstore **runtime implementation** lives in a new `sigmund-sigstore` module, **not** in `sigmund-core`. The `dev.sigstore:sigstore-java` dependency brings in HTTP clients, TUF library, protobuf, and gRPC stubs — a non-trivial footprint that users who only need OpenPGP should not pay for.

Note that `sigmund-core` already contains the Sigstore **data types** — `SigstoreVerificationUnit`, `SigstoreVerifyResult`, and `OidcCredential` — because the `VerificationUnit` and `VerifyResult` sealed hierarchies require their permitted subtypes to be in the same module. These types are lightweight (records/classes holding strings) and have no dependency on sigstore-java. The separate module isolates the heavy runtime dependencies, not the concept of Sigstore itself.

**Extensibility tradeoff:** The sealed hierarchies create a tension with the `ServiceLoader`-based `SignatureToolFactory` extensibility. New tools within existing formats (e.g., another OpenPGP implementation) can be discovered at runtime. But a genuinely new signature format requires adding `permits` entries to `VerificationUnit` and `VerifyResult` in core — a core release. This is a deliberate choice: new formats are rare (PGP has been the only format for decades, Sigstore is the first new one), and each introduces new verification semantics that warrant core review. Unsealing the hierarchies would lose compile-time exhaustiveness in the verification pipeline. The `ServiceLoader` extension point is for new tools and new formats that have gone through a core release, not for fully decoupled runtime format discovery.

The module structure:

| Module | Sigstore dependency | Purpose |
|--------|-------------------|---------|
| `sigmund-core` | None | Core SPI, OpenPGP backends, `SignatureToolFactory` service interface |
| `sigmund-sigstore` | `dev.sigstore:sigstore-java` | `SigstoreSignatureFormat`, `SigstoreTool`, `SigstoreToolFactory` |
| `sigmund-cli` | `sigmund-sigstore` (bundled) | Fat jar includes Sigstore out of the box |
| `sigmund-maven-plugin` | None (optional user dependency) | Users add `sigmund-sigstore` as a plugin dependency to enable Sigstore |

The sigstore-java library is pure Java (no native CLI dependency), unlike the GPG and Sequoia backends which shell out to `gpg` and `sq`.

### Service discovery

`SignatureToolFactory` becomes a **public** service interface, discoverable via `ServiceLoader`. The `sigmund-sigstore` module registers `SigstoreToolFactory` in `META-INF/services/dev.cyberstamp.sigmund.core.SignatureToolFactory`. The builder loads service-provided factories alongside the hardcoded ones:

```java
private static final List<SignatureToolFactory> BUILTIN_FACTORIES = List.of(
        new BcToolFactory(), new GpgToolFactory(), new SqToolFactory());

private List<SignatureToolFactory> allFactories() {
    List<SignatureToolFactory> all = new ArrayList<>(BUILTIN_FACTORIES);
    ServiceLoader.load(SignatureToolFactory.class).forEach(all::add);
    return all;
}
```

The built-in factories (`BcToolFactory`, `GpgToolFactory`, `SqToolFactory`) remain hardcoded in `BUILTIN_FACTORIES`. Additional factories — including `SigstoreToolFactory` — are discovered via `ServiceLoader`. This is the extension point the `SignatureToolFactory` javadoc already anticipates: *"If a ServiceLoader-based extension point is needed later, this interface is the natural candidate."*

The current `FACTORIES` field is referenced in five places in `Sigmund.Builder` — all must use `allFactories()`:

- `createFromFactory()` (line 485) — tool lookup by name for `addSigningTool()`
- `enforceExclusiveSigners()` (line 577) — polls factories for exclusive signer claims
- `FACTORIES` declaration (line 623) — renamed to `BUILTIN_FACTORIES`
- `initializeTools()` fallback loop (line 636) — initializes factories not in the priority list
- `initializeTool()` (line 646) — factory lookup by tool name

ServiceLoader-discovered factories are appended after built-ins. See [Builder integration](#builder-integration) for initialization details.

For the **CLI**, `sigmund-sigstore` is a compile dependency of the `cli` module — the fat jar includes Sigstore support with no user action needed.

For the **Maven plugin**, users opt in by adding `sigmund-sigstore` as a plugin dependency:

```xml
<plugin>
  <groupId>dev.cyberstamp</groupId>
  <artifactId>sigmund-maven-plugin</artifactId>
  <dependencies>
    <dependency>
      <groupId>dev.cyberstamp</groupId>
      <artifactId>sigmund-sigstore</artifactId>
      <version>${sigmund.version}</version>
    </dependency>
  </dependencies>
</plugin>
```

### SigstoreSignatureFormat

A new `SignatureFormat` implementation for the Sigstore bundle format:

```java
public class SigstoreSignatureFormat implements SignatureFormat {

    public static final String FORMAT_SIGSTORE = "sigstore";

    String name()          → "sigstore"
    String fileExtension() → ".sigstore.json"

    boolean canHandleByContent(Path signatureFile)
        // Read the file and check for a "mediaType" field starting with
        // "application/vnd.dev.sigstore.bundle". Files that don't start
        // with `{` are rejected immediately.

    List<VerificationUnit> parse(Path signatureFile)
        // Read the file as a string, return a single SigstoreVerificationUnit
        // wrapping the JSON bundle text. Unlike OpenPGP where one .asc file
        // may contain multiple armored blocks, a Sigstore bundle is always
        // one verifiable unit.

    boolean supportsCombining() → false
        // Each signing produces a standalone bundle. No combining.
        // Inherits the default combine() which accepts a single input.
}
```

Format detection uses extension-first matching via a default method on `SignatureFormat`. The existing abstract `canHandle(Path)` method is replaced with a default implementation that checks the extension first, and the content-based detection logic moves to a new abstract method `canHandleByContent(Path)`. `OpenPgpSignatureFormat.canHandle()` is renamed to `canHandleByContent()`:

```java
default boolean canHandle(Path signatureFile) {
    if (signatureFile.getFileName().toString().endsWith(fileExtension())) {
        return true;
    }
    return canHandleByContent(signatureFile);
}

boolean canHandleByContent(Path signatureFile);
```

When the file extension matches (`.sigstore.json`, `.asc`), content reading is skipped entirely. Content-based detection is the fallback for misnamed or extensionless files. This avoids O(formats × files) content reads in the verification flow — each file is matched by extension on the first try in the common case. Implementations should only override `canHandleByContent()`, not `canHandle()` — overriding the latter would bypass the extension fast path.

### SigstoreTool

A new `SignatureTool` implementation wrapping sigstore-java's `KeylessSigner` and `KeylessVerifier`:

```java
public class SigstoreTool implements SignatureTool {

    // Construction-time state:
    private final SigstoreSignatureFormat format;
    private final KeylessSigner signer;          // null for verify-only
    private final KeylessVerifier verifier;
    private final boolean staging;
}
```

#### Construction

`SigstoreTool` follows the same pattern as `GpgRunner` and `SqRunner` — fully configured at construction time, no mutable state after construction.

Two construction modes:
- **Signing + verification**: creates both `KeylessSigner` and `KeylessVerifier`
- **Verify-only**: creates only `KeylessVerifier`, `canSign()` returns `false`

The `KeylessSigner` is created once and reused across multiple `sign()` calls. sigstore-java internally caches the Fulcio certificate and reuses it across `signFile()` calls until it has less than 5 minutes of remaining validity (`DEFAULT_MIN_SIGNING_CERTIFICATE_LIFETIME`). This is important for Maven builds where multiple artifacts (JAR, POM, sources, javadoc) are signed sequentially — each gets the same certificate without a new OIDC authentication.

#### OIDC identity validation

OIDC identity validation is **optional** for Sigstore signing. `createSigning(settings, expected)` receives the signer `signing.signer` asserts, resolved with `SignerIdentity.withIssuersResolved` so every identity entry names its issuer. Each entry whose issuer is an OIDC issuer becomes an `OidcTokenMatcher` passed to `KeylessSigner.builder().allowedOidcIdentities()` — sigstore-java's built-in allow-list mechanism: on the entry's issuer, and on its exact subject when the entry names a `subject` (any subject otherwise). If the OIDC flow returns a token that matches no entry (e.g., the user authenticates as `bob@example.com` but the signer says `alice@example.com`), signing fails immediately with a `KeylessSignerException` before Fulcio is asked for a certificate. This is only an early refusal: whatever the token, core checks every signature against the asserted signer after signing (`SignerBindingCheck`), on the issued certificate's issuer, subject and extensions, before anything is written.

When no signer is asserted (`expected` is `null`), or it has no OIDC identity entry, `allowedOidcIdentities` is left empty (the default), which accepts whatever identity the OIDC flow returns. This matches the `sigstore-maven-plugin` behavior and is the natural mode for CI environments where the workflow identity is implicitly correct.

`KeylessSigner` implements `AutoCloseable` — its `close()` clears the cached ephemeral signing certificate material (security hygiene, not system resource cleanup). `KeylessVerifier` does not implement `AutoCloseable` — it holds stateless verifier objects with no cleanup needed.

To propagate this lifecycle, `SigstoreTool` implements `AutoCloseable` (delegating to `KeylessSigner.close()`), and `Sigmund` implements `AutoCloseable` — its `close()` iterates all tools and closes any that implement `AutoCloseable`:

```java
public void close() {
    for (SignatureTool tool : tools) {
        if (tool instanceof AutoCloseable ac) {
            try { ac.close(); } catch (Exception ignored) {}
        }
    }
}
```

`Sigmund` is the right owner because it holds the tool instances. `Signer` does **not** implement `AutoCloseable` — it borrows tool references from `Sigmund`, and `sigmund.signer()` can create multiple `Signer` instances sharing the same underlying tools. If `Signer.close()` closed the `KeylessSigner`, a second `Signer` from the same `Sigmund` would be broken. The Maven plugin and CLI wrap `Sigmund` in try-with-resources. For verify-only usage, `close()` is a no-op — `KeylessVerifier` has no cleanup. Existing tools (GPG, SQ, BC) are unaffected — they don't implement `AutoCloseable`.

`Sigmund.Builder.build()` must wrap tool initialization in try-catch — if construction fails after creating a signing-capable `SigstoreTool` (which opens a `KeylessSigner`), the builder closes any `AutoCloseable` tools before propagating the exception.

For staging vs production:
```java
KeylessSigner.builder().sigstorePublicDefaults().build()
KeylessSigner.builder().sigstoreStagingDefaults().build()
```

For custom trusted roots (required for air-gapped environments):
```java
KeylessVerifier.builder().trustedRootProvider(TrustedRootProvider.from(path)).build()
```

The default `sigstorePublicDefaults()` fetches the trusted root via TUF (The Update Framework) at construction time — this is the only network access during verification. This means `initializeTools()` in `Sigmund.Builder` may trigger a network call when Sigstore is in the toolbox, unlike OpenPGP tool initialization which is purely local. Once constructed, `KeylessVerifier.verify()` is fully offline: all verification data (inclusion proof, certificate chain, signature) comes from the bundle itself. For environments without internet access, the `trusted-root` setting provides a pre-fetched local root, eliminating all network dependencies — both at construction and verification time.

#### SignatureTool implementation

```java
String name()                    → "sigstore"
boolean isAvailable()            → true  // pure Java, always available
boolean canSign()                → signer != null
SignatureFormat signatureFormat() → format (shared SigstoreSignatureFormat)
Set<String> supportedCredentialTypes() → Set.of("oidc")

boolean canVerify(VerificationUnit unit) → unit instanceof SigstoreVerificationUnit
```

#### signingInfo()

Returns a single `SigningInfo` describing the OIDC identity that will be used for signing:

```java
List<SigningInfo> signingInfo() {
    if (!canSign()) {
        return List.of();
    }
    // oidcSubject is the first subject among the asserted signer's OIDC entries, null otherwise
    return List.of(new SigningInfo("sigstore", null, null, oidcSubject, Set.of("oidc")));
}
```

The `fingerprint` is `null` (Sigstore uses ephemeral keys, no persistent fingerprint). The `algorithm` is `null` — the exact signing algorithm is chosen by sigstore-java at signing time and reported in the `SignResult` afterward, not known at construction. The `userId` carries the OIDC subject when an entry of the asserted signer names one, or `null` when the identity is determined at signing time (CI ambient flow).

#### sign()

```java
SignResult sign(Path artifactFile, Path outputSig) {
    Bundle bundle = signer.signFile(artifactFile);
    Files.writeString(outputSig, bundle.toJson());

    X509Certificate cert = (X509Certificate) bundle.getCertPath().getCertificates().get(0);
    String algorithm = cert.getPublicKey().getAlgorithm();  // e.g., "EC"

    return new SignResult(algorithm);
}
```

Note: `cert.getSigAlgName()` returns how Fulcio (the CA) signed the certificate, not the artifact-signing algorithm. The artifact is signed with the ephemeral key whose public key is embedded in the certificate — `cert.getPublicKey().getAlgorithm()` returns the correct key type (e.g., `"EC"` for ECDSA P-256).

This mirrors the `sigstore-maven-plugin` pattern — `signFile()` handles the full OIDC → Fulcio → sign → Rekor flow internally. Network and OIDC failures surface as `KeylessSignerException`, which `SigstoreTool` wraps in `ToolExecutionException`.

Unlike every other `SignatureTool.sign()` (which are local operations), `SigstoreTool.sign()` makes three network calls (OIDC provider, Fulcio, Rekor). This introduces failure modes — timeouts, rate limits, outages — that are qualitatively different from a local GPG failure. Sigmund delegates network resilience entirely to sigstore-java, which currently exposes no timeout or retry configuration. The `sigstore-maven-plugin` takes the same approach — any network failure immediately fails the build. Sigmund follows suit: no custom retry or timeout layer on top of sigstore-java. If sigstore-java exposes timeout/retry configuration in a future release, `SigstoreToolFactory` can surface it as tool settings.

#### verify()

```java
VerifyResult verify(Path artifactFile, VerificationUnit unit) {
    SigstoreVerificationUnit su = (SigstoreVerificationUnit) unit;

    Bundle bundle = Bundle.from(new StringReader(su.jsonBundle()));
    verifier.verify(artifactFile, bundle, VerificationOptions.empty());
    // empty() = default policy (TLog + CTLog verification enabled), no certificate
    // identity constraints. Identity matching is handled by Sigmund's TrustVerifier
    // via extractCredentials(), not by sigstore-java's CertificateMatcher.
    //
    // Verification is fully offline — verify() never contacts Rekor live.
    // All verification data (inclusion proof, certificate, signature) comes
    // from the bundle. The only network access is at KeylessVerifier construction
    // time when the TUF-managed trusted root is fetched. For air-gapped
    // environments, the trusted-root setting provides a local path.

    // If we reach here, verification passed — KeylessVerifier throws on failure
    X509Certificate cert = (X509Certificate) bundle.getCertPath().getCertificates().get(0);

    String issuer = extractIssuer(cert);
    String subject = extractSubject(cert);  // from SAN: rfc822Name or uniformResourceIdentifier
    String logIndex = bundle.getEntries().isEmpty() ? null
            : String.valueOf(bundle.getEntries().get(0).getLogIndex());

    int subjectType = resolveSubjectType(cert);  // GeneralName tag: 1 = rfc822Name, 6 = URI

    return new SigstoreVerifyResult(
            Verdict.PASS, subject, cert.getPublicKey().getAlgorithm(), issuer, logIndex, subjectType);
    // subject maps to VerifyResult.signerDisplayName
}
```

`KeylessVerifier.verify()` throws `KeylessVerificationException` on failure. The catch block distinguishes two cases:

- **Cryptographic failure** (invalid signature, bad certificate, failed inclusion proof) — returns a `SigstoreVerifyResult` with `Verdict.FAIL`, consistent with the error model in ADR-002 (verification outcomes are result objects, not exceptions).
- **Infrastructure failure** (Rekor unreachable, Fulcio down, network timeout) — rethrown as `ToolExecutionException`, following the `SignatureTool.verify()` contract: "throws only for infrastructure failures." This allows the caller to handle transient network issues differently from cryptographically invalid signatures.

Bundle parsing failures (malformed JSON) return `Verdict.FAIL` — a corrupt bundle is a verification outcome, not an infrastructure issue.

#### Identity extraction from Fulcio certificates

The OIDC issuer is embedded in Fulcio certificate extensions using Sigstore-specific OIDs, following the [Sigstore OID specification](https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md):

| OID | Version | Encoding |
|-----|---------|----------|
| `1.3.6.1.4.1.57264.1.8` | V2 (current) | ASN1-encoded UTF-8 string |
| `1.3.6.1.4.1.57264.1.1` | V1 (deprecated) | Raw UTF-8 bytes in octet string |

The extraction logic tries V2 first, falls back to V1. This is the same pattern used by `FulcioOidHelper` in the `sigstore-maven-plugin`. The V1 encoding is unusual — the octet string contains raw UTF-8 bytes directly, not an ASN1-encoded string object. Bouncy Castle's `ASN1Sequence.fromByteArray()` handles the outer DER wrapper, then the V1 path reads the inner bytes as raw UTF-8 while the V2 path performs a second ASN1 parse to extract the string.

The subject (signer identity) is extracted from the certificate's Subject Alternative Name (SAN) extension. The SAN type is captured as an `int` on `SigstoreVerifyResult` using the standard `GeneralName` tag value from RFC 5280 (1 = `rfc822Name`, 6 = `uniformResourceIdentifier`), so that `extractCredentials()` can distinguish email subjects from URI subjects without string heuristics (URIs can also contain `@` characters). The raw tag value is used instead of a custom enum — the `GeneralName` types are a well-defined standard, Bouncy Castle already provides named constants (`GeneralName.rfc822Name`, `GeneralName.uniformResourceIdentifier`), and new SAN types can be handled by adding an `if` branch without any type changes. The Sigstore OID specification already defines extensions for build signer URI, source repository URI, runner environment, and others that could introduce new identity forms. For email-based signers, the SAN contains an RFC 822 name (email address). For CI pipelines (e.g., GitHub Actions), the SAN contains a URI (e.g., `https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0`).

#### extractCredentials()

```java
List<Credential> extractCredentials(VerifyResult result) {
    if (result.verdict() != Verdict.PASS) {
        return List.of();
    }
    SigstoreVerifyResult sr = (SigstoreVerifyResult) result;
    String issuer = sr.issuer();
    String subject = sr.signerDisplayName();

    List<Credential> credentials = new ArrayList<>(2);

    if (issuer != null && subject != null) {
        credentials.add(new OidcCredential(issuer, subject));
    }

    // If the subject is an RFC 822 name (email), also produce an EmailCredential.
    // This enables matching against signers configured with only an email
    // credential, without requiring them to specify the OIDC issuer.
    if (subject != null && sr.subjectType() == GeneralName.rfc822Name) {
        credentials.add(new EmailCredential(subject));
    }

    return List.copyOf(credentials);
}
```

This dual credential extraction is the key to cross-backend identity matching described in ADR-002: a signer configured with only `email: "alice@example.com"` matches both an OpenPGP signature (via UID parsing) and a Sigstore signature (via the `EmailCredential` in the proven set), while a signer configured with `oidc: {issuer: ..., subject: ...}` gets the stricter issuer+subject check via the `OidcCredential`.

### SigstoreVerifyResult update

`SigstoreVerifyResult` gains an `int subjectType` field to carry the SAN type from `verify()` to `extractCredentials()`. The value is a standard `GeneralName` tag from RFC 5280 — Bouncy Castle's `GeneralName` class provides named constants:

```java
public final class SigstoreVerifyResult extends VerifyResult {
    private final String issuer;
    private final String logIndex;
    private final int subjectType;  // GeneralName tag: 1 = rfc822Name, 6 = URI
}
```

It also overrides `signerIdentifier()` to return the OIDC subject:

```java
@Override
public String signerIdentifier() {
    return signerDisplayName();
}
```

This parallels `OpenPgpVerifyResult.signerIdentifier()` returning the key fingerprint — each backend provides the most meaningful identifier for its verification model. For Sigstore, that is the OIDC subject (email or workflow URI).

### SigstoreToolFactory

Discovered via `ServiceLoader` when `sigmund-sigstore` is on the classpath:

```java
class SigstoreToolFactory implements SignatureToolFactory {

    String toolName() → "sigstore"
    Set<String> supportedCredentialTypes() → Set.of("oidc")

    SignatureTool createSigning(Map<String, String> settings, SignerIdentity expected) {
        boolean staging = "true".equals(settings.get("staging"));
        boolean interactive = "true".equals(settings.get("interactive"));
        // Each OIDC identity entry of expected becomes an allowedOidcIdentities matcher
        // (issuer, plus subject when named), refusing a wrong token before Fulcio.
        // If expected is null or has no OIDC entry, accept any ambient identity.
        // Build signing-capable SigstoreTool
    }

    SignatureTool createVerifyOnly(Map<String, String> settings) {
        boolean staging = "true".equals(settings.get("staging"));
        String trustedRoot = settings.get("trusted-root");
        // Build verify-only SigstoreTool
    }
}
```

`SignatureToolFactory` now has two creation methods:

- `createSigning(Map<String, String> settings, SignerIdentity expected)` — creates a signing-capable tool from its own settings. `expected` is the signer `signing.signer` asserts, resolved with `withIssuersResolved` so every identity entry names its issuer, or `null` when none is asserted. A tool may use it only to refuse early (Sigstore's token matchers), never to select a key; core checks every signature against it after signing. Default implementation throws (signing not supported).
- `createVerifyOnly(Map<String, String> settings)` — creates a verify-only tool (unchanged).

#### Signer resolution

Tools are created from their own settings; the asserted signer never routes to or selects a tool. The flow is:

1. Builder resolves `signing.signer` once against the `signers` registry (or `null` if absent) and resolves its identity entries with `SignerIdentity.withIssuersResolved`: an entry without its own `issuer` becomes one entry per top-level `issuers` name
2. For each tool that signs (see [Signing tool routing](#signing-tool-routing)), the builder calls `factory.createSigning(settings, expected)` with the tool's settings from the top-level `tools` section and the resolved signer
3. Each factory chooses its key or identity from its settings (e.g., `signing-key-env` for BC) or ambient credentials (e.g., ambient OIDC for Sigstore); `expected` may only make it refuse early
4. After signing, core checks every fresh signature against the asserted signer (`SignerBindingCheck`) and fails, writing nothing, when one does not prove it

For `SigstoreToolFactory`, the config-to-code flow is:
1. `signing.toolchain` lists `sigstore`, so the builder calls `SigstoreToolFactory.createSigning(settings, expected)`
2. The factory turns every OIDC identity entry of `expected` into an `allowedOidcIdentities` matcher — issuer, plus subject when the entry names one; directory entries contribute none
3. If `expected` is `null` or has no OIDC entry, the factory builds a `KeylessSigner` without identity constraints, accepting any ambient OIDC identity
4. `Signer.sign()` triggers the OIDC flow; a token matching no entry is refused before Fulcio
5. Core checks the issued certificate's identity against the asserted signer before the bundle is written

Tool settings are read from the top-level `tools` section in the configuration:

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `staging` | boolean | `false` | Use `sigstage.dev` instead of production `sigstore.dev` |
| `trusted-root` | path | TUF-managed | Custom trusted root JSON file |
| `interactive` | boolean | `false` | Enable browser-based OIDC flow for interactive signing. When `false` (default), only ambient credentials (env vars, GitHub Actions) are used; signing fails if none are found. |

The `staging` setting is particularly useful for testing — it avoids polluting the production Rekor transparency log. This mirrors the `publicStaging` parameter from the `sigstore-maven-plugin`. Because tool settings are centralized in the top-level `tools` section, `staging` is configured once and applies to both signing and verification — no duplication.

### SignerInspection

`SigstoreTool` does **not** implement the `SignerInspection` interface in this iteration. Sigstore signer inspection would require querying the Rekor transparency log for entries matching an OIDC identity — a useful capability but one that adds scope beyond the core signing and verification integration. The `inspect-signer` command already handles tools that don't implement `SignerInspection` (it iterates only tools where `canInspect()` returns `true`), so no changes are needed. Rekor-based signer inspection is deferred to a future enhancement.

**Known UX gap:** With `allowedOidcIdentities` configured, an identity mismatch is caught at `sign()` time — after the OIDC flow completes. In interactive mode, this means the user authenticates in the browser before learning their identity doesn't match the config. A pre-flight check (e.g., via `inspect-signer` or a signing dry-run) that reports the configured expected identity or queries the ambient OIDC provider would catch this earlier. This is deferred alongside `SignerInspection` but worth noting as a motivation for it.

### OIDC authentication

Sigmund does **not** implement any custom OIDC handling. All authentication is delegated to sigstore-java's `OidcClients`, which tries providers in order and returns a token from the first one that is enabled:

1. **Environment token** — reads a pre-set token from an environment variable (e.g., `SIGSTORE_ID_TOKEN`)
2. **GitHub Actions** — ambient OIDC via `ACTIONS_ID_TOKEN_REQUEST_URL` + `ACTIONS_ID_TOKEN_REQUEST_TOKEN`
3. **Interactive browser flow** — opens a browser for the user to authenticate via their identity provider

In CI environments, providers 1 or 2 supply the token automatically. On a developer workstation, the browser flow kicks in as a fallback.

By default (`interactive: false`), only ambient OIDC providers (environment token, GitHub Actions) are used. If none supply a token, signing fails with a clear error. This is the safe default for CI — no risk of a build hanging on a browser prompt.

When `interactive` is `true`, the `KeylessSigner` includes `WebOidcClient`, enabling the browser-based OIDC flow for desktop signing. The `KeylessSigner` is constructed with the full `OidcClients.from()` provider set.

For GitHub Actions, the workflow needs:
```yaml
permissions:
  id-token: write
  contents: read
```

### Configuration

#### Configuration structure

Sigmund uses a centralized configuration model. Per-tool settings live in a top-level `tools` section — the definitive tool registry. The `signing` and `discovery` sections reference tools by name rather than embedding per-tool configuration, eliminating duplication for settings like `staging` that apply to both signing and verification.

```yaml
# Top-level tool registry — all per-tool settings in one place
tools:
  sigstore:
    staging: false
    trusted-root: "/path/to/root.json"
    interactive: true

# Signing workflow — references tools by name
signing:
  signer: ci-pipeline
  toolchain: [sigstore]

# Discovery/verification workflow — references tools by name
discovery:
  toolchain: [bc, sq]
  resolve-signers: true
```

Setting names within the `tools` section are self-describing: `signing-fingerprint` is obviously signing-specific, `trusted-root` is obviously verification-specific, `staging` is obviously shared. No subsections or signing/verification prefixes are needed — the flat namespace reads naturally because each setting's purpose is clear from its name. A tool's signing key or identity comes only from these settings (or ambient credentials), never from the asserted signer.

When the top-level `tools` section is absent, the builder falls back to built-in defaults (BC, SQ, GPG in default order) plus ServiceLoader classpath discovery. If a classpath-discovered tool's `supportedCredentialTypes()` overlaps with an existing tool and the user has not configured ordering, the builder fails with a clear error asking the user to configure the toolchain. If there is no overlap (e.g., Sigstore handles `oidc`, which no built-in handles), the discovered tool is initialized without conflict.

#### Signing tool routing

Which tools sign never depends on the asserted signer's credentials:

**With `signing.toolchain`:** it is an allowlist — only listed tools sign, in the listed order. Each is created with `createSigning(settings, expected)` and uses its own settings for its key or identity (`signing-key-env`, `signing-fingerprint`, ambient OIDC, etc.).

**Without `signing.toolchain`:** the default OpenPGP tools (BC, SQ, GPG) are tried in order and those that cannot sign are skipped; a factory claiming default exclusive signing (an injected CI key) becomes the sole signer. Sigstore signs only when the toolchain lists it.

`signing.credential-types` and profiles then select the keys to sign with: the signing plan keeps the keys, across all signing tools, whose credential type (from `signingInfo()`) is in the listed types, and `sign()` is called once per planned key. With or without a signer, `signing.signer` only adds the check after signing (and Sigstore's early refusal).

#### Signing with Sigstore

Sigstore signing can be configured with or without identity validation.

**With identity validation** — `signing.signer` names a signer with OIDC identity entries. The toolchain lists Sigstore; `SigstoreToolFactory.createSigning(settings, expected)` receives the resolved signer and builds its token matchers from it:

```yaml
signers:
  ci-pipeline:
    identities:
      - issuer: "https://token.actions.githubusercontent.com"
        source-repository-uri: "https://github.com/org/repo"

signing:
  signer: ci-pipeline
  toolchain: [sigstore]
```

A token from another issuer is refused before Fulcio; the repository is checked on the issued certificate after signing.

**Without identity validation (CI)** — no signer, ambient OIDC identity accepted. The toolchain explicitly lists Sigstore:

```yaml
signing:
  toolchain: [sigstore]
```

No `tools` section needed — Sigstore uses production defaults. The builder calls `createSigning({}, null)`, and the factory builds a `KeylessSigner` without identity constraints.

**Interactive desktop signing** — enable the browser-based OIDC flow:

```yaml
tools:
  sigstore:
    interactive: true

signing:
  toolchain: [sigstore]
```

#### Signing with mixed backends

A signer can carry both OpenPGP and OIDC credentials, enabling hybrid signing (OpenPGP + Sigstore) in a single `Signer.sign()` call:

```yaml
signers:
  alice:
    name: "Alice"
    email: "alice@example.com"
    pgp4: "4AEE18F83AFDEB23"
    pgp6: "ABCD1234..."
    oidc:
      issuer: "https://accounts.google.com"
      subject: "alice@example.com"

signing:
  signer: alice
  profiles:
    full: [openpgp4, openpgp6, oidc]
    pgp-only: [openpgp4, openpgp6]
    sigstore-only: [oidc]
  default-profile: full
```

With the `full` profile, `Signer.sign()` produces both `artifact.jar.asc` (combined classical + PQC OpenPGP signatures) and `artifact.jar.sigstore.json` (Sigstore bundle) — three signatures across two files.

Profiles are lists of credential types. Each profile entry is matched against the credential types of the keys the tools report through `signingInfo()`. The `oidc` credential type is intentionally named after the identity protocol, not the signing system — OIDC is a reusable identity format (issuer + subject) that future signing backends could also support. Which tools sign is decided by `signing.toolchain`; the profile only selects among their keys.

**Choosing tools** — `signing.toolchain` decides which tools sign; each signs with the key its own settings name:

```yaml
tools:
  sq:
    signing-fingerprint: "ABCD1234..."
    cipher-suite: mldsa87-ed448

signing:
  signer: alice
  toolchain: [sq, sigstore]
```

Here SQ produces the OpenPGP signature with the key it is configured with, and Sigstore the bundle with the ambient OIDC identity. BC and GPG are not in the toolchain, so they don't participate. Whichever tools sign, core checks every signature against `alice` after signing.

When `signing.toolchain` is present, it is an allowlist — only listed tools sign. Tools not in the toolchain do not participate, even if they support the signer's credential types.

**Explicit split — BC for v4, SQ for v6:**

```yaml
tools:
  bc:
    signing-fingerprint: "4AEE18F83AFDEB23..."
  sq:
    signing-fingerprint: "ABCD1234..."
    cipher-suite: mldsa87-ed448

signing:
  signer: alice
  toolchain: [bc, sq, sigstore]
```

#### Verification settings

Verification tool settings are part of the centralized `tools` section:

```yaml
tools:
  sigstore:
    staging: false
    trusted-root: "/path/to/custom-root.json"    # optional, default: TUF-managed public root
```

The `discovery` section controls operational verification behavior:

```yaml
discovery:
  toolchain: [bc, sq]
  resolve-signers: true
  keyservers:
    - hkps://keys.openpgp.org
```

`discovery.toolchain` selects and orders tools for verification — symmetric with `signing.toolchain`. When absent, all tools in the toolbox are used (built-in defaults plus ServiceLoader-discovered). Sigstore verification routing is type-based (`SigstoreVerificationUnit` only matches `SigstoreTool`), so its position in the toolchain does not affect behavior — ordering only matters for OpenPGP tools where multiple tools compete for the same unit type.

### Signer flow with Sigstore

When `Signer.sign()` encounters a `SigstoreTool`:

1. `tool.sign(artifactFile, tempSig)` calls `KeylessSigner.signFile()` internally
2. The result is grouped under `SigstoreSignatureFormat`
3. Since `supportsCombining()` is `false`, the bundle is written as a standalone file
4. Output: `<artifact>.sigstore.json`

This integrates naturally with the existing flow — OpenPGP signatures from GPG and SQ are combined into one `.asc` file, while the Sigstore bundle gets its own file. No special-casing in `Signer` is needed.

**How `SigstoreTool` ends up in the `Signer`'s tool list:**

- `signing.toolchain` lists `sigstore` → the builder calls `SigstoreToolFactory.createSigning(settings, expected)` → the resulting `SigstoreTool` is added to the `Signer`'s tool list
- **With signer:** `expected` is the asserted signer; its OIDC entries become token matchers, and core checks the issued certificate against it after signing
- **Without signer:** `expected` is `null` → the `SigstoreTool` accepts ambient OIDC identity

### Verification flow with Sigstore

When `Sigmund.verify()` encounters a `.sigstore.json` file:

1. `SigstoreSignatureFormat.canHandle()` matches by `.sigstore.json` extension (fast path), falling back to `mediaType` content detection for misnamed files
2. `parse()` returns a single `SigstoreVerificationUnit`
3. `SigstoreTool.canVerify()` matches on `instanceof SigstoreVerificationUnit`
4. `verify()` calls `KeylessVerifier.verify()`, extracts identity from the Fulcio certificate
5. Returns `SigstoreVerifyResult` with issuer, subject, Rekor log index, and SAN type (`GeneralName` tag)

For trust-based verification via `TrustVerifier.assess()`, the `SignatureEvidenceAdapter` bridges the result:

1. `SigstoreTool.extractCredentials()` produces `OidcCredential` and optionally `EmailCredential`
2. `TrustVerifier` matches these against the expected signer's credential bag
3. An `OidcCredential` match requires both issuer and subject to match (strict)
4. An `EmailCredential` match requires only the subject (lenient — for signers configured with just `email`)

### Builder integration

`Sigmund.Builder` changes:

- `SigstoreToolFactory` is discovered via `ServiceLoader` when `sigmund-sigstore` is on the classpath — it is not in the hardcoded `BUILTIN_FACTORIES` list.
- When no top-level `tools` section is configured, the builder initializes all factories: built-ins in default order plus ServiceLoader-discovered ones. If a discovered factory's `supportedCredentialTypes()` overlaps with an existing factory and no ordering has been configured, the builder fails with a clear error directing the user to configure the toolchain. If there is no overlap (Sigstore's `oidc` doesn't conflict with any built-in), the tool is initialized without issue.
- When the top-level `tools` section is present, it defines the definitive toolbox. Only listed tools are available. The builder initializes each listed tool using its factory (built-in or ServiceLoader-discovered).
- **Signing tool construction:** every signing tool is created with `createSigning(settings, expected)` from its own settings, with or without an asserted signer. Each factory uses the tool's settings to resolve its key or identity (e.g., `signing-key-env` for BC, ambient OIDC for Sigstore); `expected` — the asserted signer resolved with `withIssuersResolved`, or `null` — may only make a tool refuse early, never select a key.
- **Signing tool construction with toolchain:** when `signing.toolchain` is present, it is an allowlist — only listed tools produce signatures. Without it, the default OpenPGP tools that can sign are used. Sigstore signs only when listed.
- **Check after signing:** when `signing.signer` is set, core checks every fresh signature against the asserted signer (`SignerBindingCheck`) before anything is written, whichever tools signed.
- `addSigningTool("sigstore", settings)` creates a signing-capable `SigstoreTool`
- The builder groups `SigstoreTool` under `SigstoreSignatureFormat`, creating a separate `SignatureEvidenceAdapter` for the Sigstore format
- The builder validates at construction time that no non-combining format has multiple signing tools. Since `SigstoreSignatureFormat.supportsCombining()` returns `false`, all tools sharing that format would write to the same output path (`<artifact>.sigstore.json`), with the second silently overwriting the first. The builder rejects this with a clear error message. This is a general validation — it applies to any future non-combining format, not just Sigstore.
- The existing `injectFetchSettings()` method injects OpenPGP-specific settings (`resolve-signers`, `import-to-keyring`, `keyservers`) into every tool's settings map. This should be made conditional — these settings are irrelevant to `SigstoreTool` and should only be injected for OpenPGP-related factories.

### Maven plugin integration

#### Signing

The sign Mojo currently hardcodes `.asc` in three places that need updating:

1. **`collectFilesToSign()`** — the exclusion filter for the main artifact (line 70) and attached artifacts (line 84) both check `!file.getName().endsWith(".asc")`. The filter should query the registered formats' extensions rather than hardcoding them. `Sigmund` exposes a `signatureFileExtensions()` method returning the set of file extensions from its registered formats (e.g., `[".asc", ".sigstore.json"]`). The Mojo uses this to build the exclusion filter:

```java
Set<String> sigExtensions = sigmund.signatureFileExtensions();

private boolean isSignatureFile(String name, Set<String> sigExtensions) {
    return sigExtensions.stream().anyMatch(name::endsWith);
}
```

2. **`signAndAttach()`** — the current implementation hardcodes the output path as `file + ".asc"` (line 100) and assumes a single output file from `Signer.sign()` (line 106-107, takes only `output.files().get(0)`). With Sigstore, signing can produce multiple files. This changes to iterate all produced files, using the `fileExtension` from `SignedFile` rather than hardcoding format names:

```java
SigningOutput output = signer.sign(artifactPath, artifactPath.getParent());
for (SignedFile sf : output.files()) {
    Path produced = sf.path();
    Path signaturePath = Path.of(file.getAbsolutePath() + sf.fileExtension());
    if (!produced.equals(signaturePath)) {
        Files.move(produced, signaturePath, StandardCopyOption.REPLACE_EXISTING);
    }
    String attachExtension = fileToSign.extension + sf.fileExtension();
    projectHelper.attachArtifact(project, attachExtension, classifier, signaturePath.toFile());
}
```

`SignedFile` gains a `fileExtension` field (e.g., `".asc"`, `".sigstore.json"`) populated by `Signer` from `SignatureFormat.fileExtension()` at construction time. Both construction paths in `Signer.combineAndWrite()` are updated — the combining case (OpenPGP, one `.asc` from multiple tools) and the non-combining case (Sigstore standalone bundle, or single-tool OpenPGP) — since both already have the `SignatureFormat` in scope. This keeps format knowledge out of the plugin layer.

#### Verification

`ArtifactFileResolver` currently only resolves `.asc` signature files. Both `VerifyMojo` and `SignatureInspector` delegate to it for evidence resolution, so the extension-probing logic belongs in `ArtifactFileResolver.resolve()` — a single place rather than duplicated across callers.

Evidence resolution is driven by two factors: the signer's credential types (**listed evidence**) and the trust policy's `unlisted-evidence` setting (**unlisted evidence**).

Evidence is **listed** when a signer for the artifact has credentials matching the evidence format (e.g., `.sigstore.json` is listed evidence when the signer has `oidc` credentials). Evidence is **unlisted** when it's found for a format that no expected signer has credentials for.

The resolver determines which extensions to probe:

- **Listed evidence** — always resolved. Extensions are derived from the expected signers' credential types and their matching tools. If a signer has `oidc` credentials and `SigstoreTool` is in the tool chain, `.sigstore.json` is probed.
- **Unlisted evidence** — resolution depends on the `unlisted-evidence` policy:
  - `ignore` (default) — don't probe for unlisted extensions alongside already-found evidence. Only probe as fallback when no listed evidence is found.
  - `warn` or `require` — probe all extensions from the tool chain, so unlisted evidence can be evaluated.
- **Fallback** — when no evidence is found for listed extensions, the resolver probes all extensions from the tool chain regardless of `unlisted-evidence`. An artifact with only `.sigstore.json` and no `.asc` is still verifiable.

```yaml
policy:
  on-untrusted: fail
  listed-evidence: all          # all | any (any = lenient verification)
  unlisted-evidence: ignore     # ignore | warn | require
```

The existing `require-all-evidence-match` boolean is replaced by two settings that cleanly separate the two concerns it was conflating:

- **`listed-evidence`** — controls whether all evidence for formats listed in the signer's credentials must match, or if any single match is sufficient. `all` (default) is strict: every piece of listed evidence must match an expected signer. `any` is lenient: at least one listed evidence match is sufficient. "Listed" means evidence for formats matching a credential type in the signer's credential bag.
- **`unlisted-evidence`** — controls what happens with evidence for formats *not* listed in the signer's credentials. `ignore` (default) doesn't probe for unlisted formats (unless no listed evidence is found at all). `warn` probes all formats and logs a warning for unlisted evidence. `require` probes all formats and requires unlisted evidence to also match.

"Listed" and "unlisted" share a common framing: evidence is "listed" when the signer has a credential type matching the evidence format (e.g., `.sigstore.json` is listed evidence when the signer has `oidc` credentials), and "unlisted" when no signer credential matches the format.

`SignatureInspector` benefits from the same logic since it already delegates to `ArtifactFileResolver` for signature resolution.

#### Exclude patterns

`.sigstore.json` files must be excluded from GPG signing. `maven-gpg-plugin` 3.2.5+ handles this automatically. For checksum suppression, Maven 3.9.2+ or `-Daether.checksums.omitChecksumsForExtensions=.asc,.sigstore.json` in `.mvn/maven.config`.

### CLI integration

- `sign` command: Sigstore signing is enabled through `sigmund.yaml` configuration, the same way as other backends — no dedicated CLI flag.
  - When signing produces multiple files (e.g., both `.asc` and `.sigstore.json`), each is written to the artifact's directory with the format's extension, and the command lists all produced files.
  - If `--output` is provided and signing produces multiple files, the command fails with an error — `--output` is only valid when a single signature file is produced.
- `verify` command: auto-detects `.sigstore.json` files via `SigstoreSignatureFormat.canHandle()`. No flag needed — Sigstore verification is always available in the CLI since `sigmund-sigstore` is bundled as a dependency.

### What does NOT change

The following types are **used as-is** — no modifications needed:

- `SigstoreVerificationUnit` — already holds `jsonBundle`
- `OidcCredential` — already implements issuer + subject matching
- `EmailCredential` — already implements email matching
- `VerificationUnit` sealed interface — already `permits SigstoreVerificationUnit`
- `VerifyResult` sealed class — already `permits SigstoreVerifyResult`
- `SignatureTool` interface — `SigstoreTool` implements it without changes
- `SignatureFormat` interface — `SigstoreSignatureFormat` implements it (but the interface itself gains `canHandle()` default and `canHandleByContent()` — see [modified classes](#modified-classes))
- `Signer` — format grouping and `supportsCombining()` logic handles Sigstore naturally
- `TrustVerifier` — credential matching works through the existing `Credential.matches()` dispatch

## Consequences

### New classes

| Class | Location | Purpose |
|-------|----------|---------|
| `SigstoreSignatureFormat` | `sigmund-sigstore` | Format detection, parsing, file extension |
| `SigstoreTool` | `sigmund-sigstore` | `SignatureTool` wrapping sigstore-java |
| `SigstoreToolFactory` | `sigmund-sigstore` | Factory for builder integration, discovered via `ServiceLoader` |

### Modified classes

| Class | Change |
|-------|--------|
| `SignatureFormat` | Add default `canHandle()` with extension-first fast path, new `canHandleByContent()` method |
| `SignedFile` | Add `fileExtension` field, populated from `SignatureFormat.fileExtension()` |
| `SigstoreVerifyResult` | Add `int subjectType` field (RFC 5280 `GeneralName` tag value), override `signerIdentifier()` to return OIDC subject |
| `SignatureToolFactory` | Made `public`, ServiceLoader-loadable, replace `create(Credential, Map)` with `createSigning(Map, SignerIdentity)`: the tool is created from its own settings and receives the asserted signer (or `null`) only to refuse early. Default implementation throws (signing not supported). |
| `Sigmund` | Implement `AutoCloseable` (closes tools), add `signatureFileExtensions()` |
| `Sigmund.Builder` | Load `ServiceLoader`-discovered factories alongside hardcoded ones; pass the asserted signer to every signing factory; overlap detection for classpath-discovered tools |
| `SigmundConfig` / `SigmundConfigParser` | Top-level `tools` section as definitive tool registry; `signing.toolchain` and `discovery.toolchain` as name lists; centralized per-tool settings with flat namespace |
| `TrustPolicy` | Replace `requireAllEvidenceMatch` with `listedEvidence` (all/any) and `unlistedEvidence` (ignore/warn/require) |
| `ArtifactFileResolver` | Policy-driven evidence resolution based on configured/unlisted evidence; `SignatureInspector` benefits automatically |
| `SignMojo` | Iterate all `SigningOutput.files()`, attach each with format-specific extension, exclude `.sigstore.json` from signing |
| CLI `SignCommand` | Handle multiple output files, error on `--output` with multiple files |

### Configuration schema changes

The configuration schema is restructured to centralize per-tool settings and use toolchain lists for tool selection:

**Before (ADR-002 model):**
```yaml
signing:
  signer: alice
  tools:
    sq:                              # per-tool signing config
      credentials: [openpgp4, openpgp6]
      cipher-suite: mldsa87-ed448
    sigstore:                        # per-tool signing config
      staging: true
      interactive: true

discovery:
  tool-priority: [bc, sq, gpg]
  tools:
    sigstore:                        # per-tool verification config (duplicates staging)
      staging: true
      trusted-root: "/path/to/root.json"

policy:
  require-all-evidence-match: true
```

**After (this ADR):**
```yaml
tools:                               # definitive tool registry
  sq:
    signing-fingerprint: "ABCD1234..."   # the tool's own key, never taken from the signer
    cipher-suite: mldsa87-ed448
  sigstore:
    staging: true                    # configured once, applies to both signing and verification
    trusted-root: "/path/to/root.json"
    interactive: true

signing:
  signer: alice
  toolchain: [sq, sigstore]         # name list (allowlist + ordering)

discovery:
  toolchain: [bc, sq]               # symmetric with signing.toolchain
  resolve-signers: true

policy:
  listed-evidence: all               # all | any
  unlisted-evidence: ignore          # ignore | warn | require
```

Key differences:
- Top-level `tools` eliminates duplication — settings like `staging` are configured once
- `signing.toolchain` and `discovery.toolchain` are name lists, not maps with per-tool config
- Tool-specific settings (both signing and verification) live in one flat namespace under `tools.<name>`
- Setting names are self-describing (`signing-fingerprint`, `trusted-root`, `interactive`)
- `signing.toolchain` decides which tools sign; each tool's key or identity comes from its own settings, never from the signer
- `listed-evidence` and `unlisted-evidence` replace the boolean `require-all-evidence-match`, cleanly separating "must all listed evidence match?" from "what about unlisted evidence?"

### New module and dependency

A new `sigmund-sigstore` module with `dev.sigstore:sigstore-java` as a compile dependency. This transitively brings Bouncy Castle (already a Sigmund dependency) and adds the Fulcio/Rekor/TUF client libraries. Sigmund's parent POM manages the Bouncy Castle version (currently 1.85) — this version will be enforced over whatever sigstore-java brings transitively. Compatibility with sigstore-java's expected BC version should be verified during integration. The `sigmund-cli` module bundles `sigmund-sigstore`; the Maven plugin leaves it as an optional user dependency.

### Comparison with sigstore-maven-plugin

The `dev.sigstore:sigstore-maven-plugin` is a standalone Sigstore signing plugin. Sigmund integrates Sigstore as one backend within a multi-format signing and verification framework. The key differentiator is identity management — the sigstore-maven-plugin delegates entirely to sigstore-java's defaults and doesn't validate which identity signs, while Sigmund treats the OIDC identity as a configured signer credential, validates it at signing time via `allowedOidcIdentities`, and matches it at verification time through the same trust framework used for OpenPGP.

### Key differences from OpenPGP backends

| Aspect | GpgRunner / SqRunner | SigstoreTool |
|--------|---------------------|-------------|
| Runtime | External CLI (`gpg`, `sq`) | In-process (pure Java) |
| Key model | Long-lived keys in keyrings | Ephemeral keys, OIDC identity |
| `isAvailable()` | Probes for CLI binary | Always `true` |
| `canSign()` | Key must be in keyring | `true` when signing-capable, `false` in verify-only mode |
| Capability interfaces | `KeyGenerator`, `CertExporter`, `KeyImporter`, `SignerInspection` | None (keyless) |
| `sign()` | Local CLI call | Network call (OIDC + Fulcio + Rekor) |
| `supportsCombining()` | `true` (concatenated armored blocks) | `false` (standalone bundles) |
| Output file | `.asc` (shared) | `.sigstore.json` (standalone) |
| Credential type | `"openpgp4"`, `"openpgp6"` | `"oidc"` |

### Testing

- **Unit tests**: `SigstoreSignatureFormat` — canHandle detection (valid bundles, non-bundles, edge cases), parse producing correct `SigstoreVerificationUnit`
- **Unit tests**: `SigstoreTool.extractCredentials()` — email subjects (rfc822Name), URI subjects (uniformResourceIdentifier), missing issuer, `GeneralName` tag handling
- **Unit tests**: `SigstoreToolFactory` — settings parsing, staging flag, construction with and without an asserted signer (a matcher per OIDC entry: issuer and subject, or issuer alone; none for directory entries)
- **Unit tests**: `SigstoreVerifyResult.signerIdentifier()` — returns OIDC subject
- **Integration tests**: signing and verification against the Sigstore staging instance (`sigstage.dev`). These require OIDC authentication and network access, so they should be gated behind a profile or system property.
- **Identity matching tests**: `OidcCredential` and `EmailCredential` matching through `TrustVerifier.assess()` — these already exist and cover the credential matching logic; new tests verify the end-to-end path from `SigstoreTool.extractCredentials()` through `TrustVerifier`.
- **Configuration tests**: top-level `tools` section parsing, `signing.toolchain` and `discovery.toolchain` as name lists, signing tools created from their own settings with and without an asserted signer, no-signer ambient signing construction.

## Follow-up work

- **JPMS compatibility** — the project does not currently use the Java module system. If it adopts JPMS, `sigmund-sigstore` will need a `provides dev.cyberstamp.sigmund.core.SignatureToolFactory with ...SigstoreToolFactory` declaration in its `module-info.java` for `ServiceLoader` discovery to work

- **Comparison document** — a detailed comparison with `sigstore-maven-plugin` (similar to `docs/migrating-from-gpg-plugin.md`) to accompany the implementation
- **Rekor-based signer inspection** — `SigstoreTool` implementing `SignerInspection` to query the Rekor transparency log for entries matching an OIDC identity
- **Pre-flight identity check** — a dry-run or `inspect-signer` flow that reports the configured expected identity or queries the ambient OIDC provider before the browser flow, catching mismatches before interactive authentication
- **Timeout/retry configuration** — if sigstore-java exposes timeout or retry settings in a future release, surface them as `SigstoreToolFactory` settings

## References

### Sigstore-signed artifacts on Maven Central

Several projects already publish `.sigstore.json` bundles alongside their artifacts on Maven Central:

- [Caffeine 3.2.0](https://repo1.maven.org/maven2/com/github/ben-manes/caffeine/caffeine/3.2.0/) — has `.sigstore.json` for all artifacts (JAR, sources, javadoc, POM)
- [Caffeine 3.2.2](https://repo1.maven.org/maven2/com/github/ben-manes/caffeine/caffeine/3.2.2/) — most recent (July 2025)
- [ORAS Java SDK 0.2.7](https://repo1.maven.org/maven2/land/oras/oras-java-sdk/0.2.7/) — another example
- [WavesJ 1.6.3](https://repo1.maven.org/maven2/com/wavesplatform/wavesj/1.6.3/) — includes both `.asc` and `.sigstore.json`

The bundle format is `application/vnd.dev.sigstore.bundle.v0.3+json` and contains the Fulcio certificate, the message signature (SHA-256 digest + ECDSA signature), and the Rekor transparency log entry with inclusion proof. The Caffeine bundle shows it was signed via GitHub Actions OIDC (`token.actions.githubusercontent.com`) — the SAN in the cert points to the workflow file (e.g., `release.yml@refs/tags/v3.2.0`).
