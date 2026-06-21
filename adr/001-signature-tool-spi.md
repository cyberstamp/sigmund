# ADR-001: SignatureTool SPI and Sigmund Facade

## Status

Proposed

## Context

Sigmund currently supports two signing/verification backends — GnuPG (`GpgRunner`) and Sequoia (`SqRunner`). Both are concrete classes with no shared interface. The orchestration layer (`HybridSigner`, `HybridVerifier`, `SignatureBlockVerifier`), CLI commands, and Maven plugin all reference the concrete types directly, tightly coupling the codebase to these two specific tools.

This makes it difficult to:
- Add new signing backends without modifying orchestration code
- Test orchestration logic in isolation from real tools
- Provide a unified API for operations like key generation, certificate export, and signing that span multiple tools

Beyond the current OpenPGP tools, [Sigstore](https://docs.sigstore.dev/language_clients/java/) is emerging as a major signing paradigm for the Java ecosystem, with [Maven Central actively integrating it](https://www.sonatype.com/blog/pgp-vs.-sigstore-a-recap-of-the-match-at-maven-central) alongside PGP. The SPI must accommodate fundamentally different signing models — not just multiple OpenPGP implementations, but also keyless/OIDC-based systems like Sigstore.

## Decision

Introduce three abstractions:

1. **`SignatureFormat`** — owns format-specific concerns: detection, parsing signature files into verifiable units, and combining signatures
2. **`SignatureTool`** — the SPI that backends implement for signing and verification, linked to a `SignatureFormat`
3. **`Sigmund`** — the facade that discovers tools, orchestrates signing/verification, and routes work to the right tool

### SignatureFormat

Each signature format (OpenPGP, Sigstore, etc.) has its own file format, detection logic, and rules for combining multiple signatures. `SignatureFormat` encapsulates all of this, keeping the facade and tools format-agnostic.

```java
public interface SignatureFormat {

    String name();              // "openpgp", "sigstore"
    String fileExtension();     // ".asc", ".sigstore.json"

    // Content-based detection — can this format handle the given signature file?
    boolean canHandle(String content);

    // Parse a signature file into individually verifiable units
    List<VerificationUnit> parse(String signatureContent);

    // Combining — optional capability. Not all formats support merging
    // multiple signatures into a single file (e.g., Sigstore bundles are
    // standalone). Defaults to accepting a single signature passthrough
    // and rejecting multiple.
    default boolean supportsCombining() { return false; }
    default String combine(List<String> signatures) {
        if (signatures.size() == 1) return signatures.get(0);
        throw new UnsupportedOperationException(
                name() + " format does not support combining signatures");
    }
}
```

**`VerificationUnit`** — a single verifiable piece extracted from a signature file:

```java
public class VerificationUnit {
    String rawContent();    // the signature data to verify
}
```

Typed subclasses carry format-specific metadata:

```java
public class OpenPgpVerificationUnit extends VerificationUnit {
    int packetVersion();        // 4, 6, etc.
    String issuerFingerprint(); // from the signature packet
    int algorithmId();          // IANA algorithm ID
}

public class SigstoreVerificationUnit extends VerificationUnit {
    // whole bundle — no additional parsing metadata needed
}
```

**Implementations:**

- **`OpenPgpSignatureFormat`** — absorbs current `AscCombiner` logic for block extraction, packet inspection, armor detection, and block combining. Overrides `supportsCombining() → true` and `combine()` to concatenate armored blocks. Shared by all OpenPGP tools (GPG, SQ). Can be a singleton.
- **`SigstoreSignatureFormat`** — detects JSON bundles, returns the whole content as one `SigstoreVerificationUnit`. Inherits default `supportsCombining() → false` — each signing produces its own standalone bundle file.

### SignatureTool

The core SPI that backends implement. Focused on two operations: signing and verification. Linked to a `SignatureFormat` via direct reference.

```java
public interface SignatureTool {

    String name();
    boolean isAvailable();
    boolean canSign();                      // true if constructed with signing credentials
    SignatureFormat signatureFormat();       // the format this tool produces and consumes

    // Can this tool verify the given unit? (e.g., GPG handles v4 blocks, SQ handles v5+)
    boolean canVerify(VerificationUnit unit);

    // Core operations
    String sign(Path artifactFile, Path outputSig);
    VerifyResult verify(Path artifactFile, VerificationUnit unit);
}
```

**Tools are fully configured at construction time.** Credentials (key IDs, fingerprints, OIDC provider references) are provided when the tool is created. `sign()` takes no credential argument — the tool embodies its context. `canSign()` returns true only if signing credentials were provided.

**`canVerify(VerificationUnit)`** lets each tool declare what it can handle within its format. For OpenPGP, GPG handles `packetVersion() <= 4` and SQ handles `packetVersion() >= 5`. For Sigstore, the tool always handles its own unit type. This keeps all routing decisions out of the facade.

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
- **GpgRunner** implements `SignatureTool, KeyImporter, SignerIdentityResolver`
- **SqRunner** implements `SignatureTool, KeyGenerator, CertExporter`
- **SigstoreTool** implements just `SignatureTool` (keyless — no key management)

### SigningResult

`sign()` returns a `SigningResult` carrying metadata about each produced file, so callers like the Maven plugin can associate signature files with their tool and algorithm:

```java
public record SigningResult(List<SignedFile> files) {
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

### VerifyResult hierarchy

Verification results use typed per-backend classes with a common base:

```java
public abstract class VerifyResult {
    VerificationResult result();    // PASS, FAIL, NO_KEY, SKIPPED, etc.
    String signerIdentity();        // human-readable signer (UID, email, URI)
    String algorithm();             // signing algorithm name
}

public class OpenPgpVerifyResult extends VerifyResult {
    int version();          // signature packet version (4, 6)
    String keyId();         // short key ID
    String fingerprint();   // full fingerprint
}

public class SigstoreVerifyResult extends VerifyResult {
    String issuer();        // OIDC issuer URL
    String logIndex();      // Rekor transparency log entry
}
```

### VerificationReport — hierarchical

A top-level report aggregates per-file sub-reports. Callers can check the overall outcome or drill into each backend's results.

```java
public class VerificationReport {
    VerificationOutcome outcome();          // ALL_PASS, PASS_WITH_FAILURES, etc.
    List<FileVerificationReport> files();

    boolean isPass();
    boolean isLenientPass();
    String format();            // human-readable summary
}

public class FileVerificationReport {
    Path signatureFile();
    String format();                        // "openpgp", "sigstore"
    List<VerifyResult> results();           // typed per-backend
}
```

### Sigmund facade

The central entry point. Discovers tools, orchestrates signing and verification, routes work by format and tool capability.

```java
public class Sigmund {

    // --- Construction ---
    static Builder builder();

    static class Builder {
        Builder discover();             // probe known tools (verify-only instances)
        Builder addTool(SignatureTool tool);  // add or replace tool (by name)
        Sigmund build();
    }

    // --- Signing ---
    // Signs with all tools where canSign() is true.
    // Groups results by signatureFormat(), combines compatible formats,
    // writes separate files for incompatible formats.
    SigningResult sign(Path artifactFile, Path outputDir) throws IOException;

    // --- Verification ---
    // Reads signature file, detects format, parses into units,
    // routes each unit to the right tool.
    VerificationReport verify(Path artifactFile, Path signatureFile);
    VerificationReport verifyAll(Path artifactFile, List<Path> signatureFiles);

    // --- Tool access ---
    List<SignatureTool> tools();
    SignatureTool tool(String name);
    <T> T findTool(Class<T> capability);
    <T> T findTool(Class<T> capability, String toolName);

    // --- Algorithm routing ---
    // Returns the first matching tool in registration order.
    // Throws if no tool supports the resolved algorithm.
    SignatureTool toolForAlgorithm(String algorithmOrAlias);
}
```

**`discover()`** — hardcoded for now: probes `GpgRunner.isAvailable()` and `SqRunner.isAvailable()`, creates verify-only instances. Only adds tools not already present (explicit `addTool()` takes precedence).

**`build()`** — filters out tools where `isAvailable()` returns false. Collects distinct `SignatureFormat` instances from the tools.

#### Signing flow

1. Filter tools to those where `canSign()` is true
2. Call `sign()` on each, collecting the raw signature data
3. Group results by `signatureFormat()`
4. For each group:
   - If `format.supportsCombining()` → call `format.combine()` to merge into one file
   - Otherwise → write each signature as a separate file
5. Write output files using `format.fileExtension()`
6. Return the list of produced files

#### Verification flow

1. Read signature file content
2. Find the `SignatureFormat` where `canHandle(content)` is true
3. Call `format.parse()` to get a list of `VerificationUnit`s
4. For each unit, find a tool where `signatureFormat()` matches AND `canVerify(unit)` is true
5. Call `tool.verify(artifact, unit)`
6. Collect results into a `FileVerificationReport`
7. `verifyAll()` aggregates multiple `FileVerificationReport`s into a top-level `VerificationReport`

### Algorithm routing with aliases

The routing discriminator is the **algorithm name** (e.g., `"RSA"`, `"ML-DSA-87+Ed448"`). Sigmund resolves convenient aliases to canonical algorithm names:

| Alias | Resolves to |
|-------|------------|
| `"classical"` | RSA, DSA, EdDSA, ... |
| `"pqc"` | ML-DSA-87+Ed448, ML-DSA-65+Ed25519, ... |
| `"mldsa87-ed448"` (cipher suite) | ML-DSA-87+Ed448 |
| `"RSA"` (canonical) | used as-is |

`AscCombiner` already maintains the IANA algorithm ID-to-name mapping and `isPqcAlgorithmName()` — these can be reused or moved to a shared location.

### Signing defaults (no config file)

The system works without a configuration file. The caller provides signing keys explicitly (CLI arguments, Maven plugin parameters) and constructs tools with those credentials. Multiple signing tools produce multiple signatures, grouped and combined by format. No signing tools configured means verify-only.

A future configuration file could define named **signing profiles** (e.g., `"hybrid": gpg key X + sq fingerprint Y`) to save repeated CLI arguments, but the underlying machinery is the same.

## Consequences

### Classes absorbed or removed

- **`HybridSigner`** — its combine-two-signatures logic moves into `Sigmund.sign()` + `SignatureFormat.combine()`
- **`HybridVerifier`** — its block-extraction and dispatch logic moves into `Sigmund.verify()` + `SignatureFormat.parse()`
- **`SignatureBlockVerifier`** — its version-based routing moves into `Sigmund` (via `canVerify()`) and per-tool verification logic moves into each tool's `verify()` implementation
- **`AscCombiner`** is split across two destinations:
  - **Block extraction, packet inspection, armor detection, and combining** move into `OpenPgpSignatureFormat`.
  - **Armor/dearmor utilities** (`armor()`, `dearmor()`) remain as shared helpers (either a slimmed-down `AscCombiner` or a new `OpenPgpArmor` utility), since they may be needed independently of the format handler.
  - **IANA algorithm ID mapping, `algorithmName()`, `isPqcAlgorithmName()`, and alias resolution** move to a new `Algorithms` utility class. This is shared knowledge used by `OpenPgpSignatureFormat` (packet inspection), `Sigmund` (algorithm-based tool routing), and `VerificationReport` (display formatting). It is not format-specific.

### Changes to GpgRunner and SqRunner

Both implement `SignatureTool` while retaining their existing public methods for backward compatibility.

- **GpgRunner** implements `SignatureTool, KeyImporter, SignerIdentityResolver`. Gains `verify(Path, VerificationUnit)` (absorbs logic from `SignatureBlockVerifier.verifyGpgBlock()`). Maps `importKey()` → `receiveKey()`, `lookupKeyUserId()` → `listKeyUserId()`.
- **SqRunner** implements `SignatureTool, KeyGenerator, CertExporter`. Gains `verify(Path, VerificationUnit)` (absorbs logic from `SignatureBlockVerifier.verifySequoiaBlock()`). Adds `sign(Path, Path)` using a stored signing fingerprint. `canSign()` returns true only when constructed with a fingerprint.

### Name collision: `Sigmund` CLI class

The CLI module already has a `Sigmund` class (`cli/src/main/java/.../cli/Sigmund.java`) — the picocli `@TopCommand` entry point. The new `Sigmund` facade in the core module would collide. The CLI class should be renamed to `SigmundCli` (or similar) to free the `Sigmund` name for the facade, which is the more prominent API surface.

### Changes to callers

CLI commands and Maven plugin mojos construct tools, build a `Sigmund` instance via the builder, and call its methods. `SignatureInspector`'s `inspectGpgBlock` and `inspectBlock` merge into a single method — the facade handles routing.

Signature file discovery is **not** a core or facade concern:
- **CLI commands** accept explicit signature file paths from the user.
- **Maven plugin** auto-discovers signature files alongside artifacts (probing for `.asc`, `.sigstore.json`, etc.).

### Testing

Tests mock the `SignatureTool` interface directly (anonymous implementations) instead of subclassing concrete runners. `SignatureFormat` implementations can be tested independently with known inputs.

### Trust config evolution

The current `trust-config.yaml` defines trusted signers with a `Member` record carrying `gpg` (fingerprint), `pqc` (fingerprint), and `uid` (OpenPGP user ID string like `"Alice <alice@example.com>"`). This model is already identity-centric — multiple credential types identify the same signer.

To accommodate Sigstore, the `uid` field is split into `name` and `email`, and an `oidc` field is added for non-email OIDC identities (service accounts, URIs):

```yaml
# Current model
signers:
  alice:
    uid: "Alice <alice@example.com>"
    gpg: "4AEE18F83AFDEB23"
    pqc: "ABCD1234..."

# Evolved model
signers:
  alice:
    name: "Alice"
    email: "alice@example.com"
    gpg: "4AEE18F83AFDEB23"
    pqc: "ABCD1234..."

  ci-pipeline:
    name: "CI Pipeline"
    oidc: "https://github.com/org/repo"
```

The `uid` shorthand is still accepted as input and parsed into `name` + `email` during deserialization for backward compatibility.

**Matching priority** during verification:

1. **Fingerprint** (`gpg`/`pqc`) — most specific, version-aware. Used for OpenPGP v1-v4 (gpg) and v5+ (pqc).
2. **OIDC** (`oidc`) — for Sigstore non-email identities (service accounts, repository URIs).
3. **Email** (`email`) — shared across OpenPGP (reconstructed as `"Name <email>"` for UID matching) and Sigstore (email-based OIDC subjects).
4. **Name** (`name`) — weakest, primarily for display. Not used for matching on its own.

This means `email` does double duty: it participates in OpenPGP UID matching (combined with `name`) and serves as the Sigstore OIDC identity for email-based signers. The `oidc` field covers Sigstore identities that aren't email addresses. A signer entry can carry all credential types simultaneously — the verifier picks the appropriate one based on the backend that produced the signature.

The `Member` record becomes:

```java
public record Member(String gpg, String pqc, String name, String email, String oidc) {
}
```

The `memberMatchesSignature` method dispatches on the `VerifyResult` type to access backend-specific fields:

```java
if (result instanceof OpenPgpVerifyResult pgp) {
    // Fingerprint matching — most specific
    if (member.gpg() != null && pgp.keyId() != null && pgp.version() < 6)
        return fingerprintsMatch(member.gpg(), pgp.keyId());
    if (member.pqc() != null && pgp.keyId() != null && pgp.version() >= 6)
        return fingerprintsMatch(member.pqc(), pgp.keyId());
    // UID fallback (reconstructed from name + email)
    if (member.email() != null && pgp.signerIdentity() != null)
        return reconstructUid(member).equals(pgp.signerIdentity());
}

if (result instanceof SigstoreVerifyResult sr) {
    // OIDC identity matching (service accounts, URIs)
    if (member.oidc() != null)
        return member.oidc().equals(sr.signerIdentity());
    // Email matching (email-based OIDC subjects)
    if (member.email() != null)
        return member.email().equals(sr.signerIdentity());
}
```

This couples the matcher to known `VerifyResult` subclasses — adding a new backend requires a new branch. The coupling is localized to one method and is a pragmatic tradeoff. A future refinement could promote `keyId()` to the base class to enable type-agnostic fingerprint matching.

### Future directions

- **Sigstore backend**: keyless signing via OIDC identity. [sigstore-java](https://github.com/sigstore/sigstore-java) provides `KeylessSigner` and `KeylessVerifier` — a `SigstoreTool` would wrap these, implementing `SignatureTool` with `SigstoreSignatureFormat`. No capability interfaces needed (keyless = no key management). Validates the SPI generality.
- **Bouncy Castle backend**: pure-Java OpenPGP signing/verification without external CLI tools. Already a project dependency (`bcpg-jdk18on`). Would share `OpenPgpSignatureFormat` with GPG and SQ.
- **User configuration file**: named signing profiles, tool paths, algorithm preferences
- **Pluggable discovery**: Java `ServiceLoader` for third-party tool backends
