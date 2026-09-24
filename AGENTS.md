# Agent Guidelines for Sigmund

Guidelines for AI agents working on the sigmund codebase.

## Project Overview

Sigmund is a Maven plugin and CLI for artifact signing, signature verification, and dependency trust enforcement. Multi-module Maven project: `core`, `cli`, `maven-plugin`, `sigstore` (in progress).

## Build and Test

```bash
# Full build with integration tests
mvn verify

# Core module only
mvn test -pl core

# Specific test class
mvn test -pl core -Dtest="SigmundConfigParserTest"

# Maven plugin tests
mvn test -pl maven-plugin
```

Java 17 target. No JPMS module-info.

## Code Style

- **Package imports only.** Never use fully-qualified names inline.
- **Small, descriptive methods.** Extract logical steps into well-named private methods rather than writing long method bodies.
- **Detailed javadoc** on all public types and methods. Explain semantics, contracts, and relationships — not just `@param`/`@return`.
- **No comments on implementation.** Code should be self-explanatory. Only comment non-obvious constraints or workarounds.
- **Defensive copies** in records and constructors. Use `Map.copyOf()`, `List.copyOf()`, `LinkedHashMap` when insertion order matters.

## Architecture

### Config Model

Each top-level YAML section in `sigmund.yaml` maps 1:1 to a Java type:

| YAML section | Java type |
|---|---|
| `signers` | `SignersConfig` |
| `artifacts` | `ArtifactsConfig` |
| `tools` | `ToolsConfig` |
| `signing` | `SigningConfig` |
| `discovery` | `DiscoveryConfig` |
| `trust`/`unsigned`/`policy` | `TrustPolicy` |

`SigmundConfig` is the top-level record holding all of these. `SigmundConfigParser` produces it from YAML.

### Two-Layer Architecture

**Layer 1 — Identity Verification:** "Is this artifact from someone I trust?" via `TrustVerifier`, `EvidenceProvider`, `SignerIdentity`, `TrustPolicy`.

**Layer 2 — Signature Operations:** Cryptographic signing/verification via `SignatureTool`, `SignatureFormat`, `Claim`, `VerifyResult`.

**Bridge:** `SignatureEvidenceAdapter` wraps a `SignatureFormat` and its tools into an `EvidenceProvider`.

### Vocabulary: evidence and claim

**Evidence** is the file carrying assertions — the `.asc`, the Sigstore bundle, a DSSE envelope. A **claim** is a single verifiable assertion extracted from it. One evidence file can carry several claims: a hybrid `.asc` with a classic and a PQC block is two claims. Evidence is located and parsed by an `EvidenceProvider`; the unit of verification is a `Claim`. Use both terms as defined — never "verification unit".

### Key Abstractions

- `SignatureTool` — core SPI for signing and verification (GPG, Sequoia, Bouncy Castle, Sigstore)
- `SignatureToolFactory` — public, ServiceLoader-discoverable factory for tool construction
- `SignatureFormat` — file format detection (`canHandle` with extension-first fast path), parsing, combining
- `Credential` — extensible identity: `FingerprintCredential`, `EmailCredential`, `OidcCredential`
- `Sigmund` — central facade, implements `AutoCloseable`
- `Signer` — producer use case (signing)
- `TrustVerifier` — consumer use case (trust assessment)

### Sealed Hierarchies

`Claim` and `VerifyResult` are sealed — adding a new format requires adding `permits` in core. This is deliberate: new formats are rare and warrant core review.

## Testing

- Write tests for every change. TDD where practical.
- JUnit 6.1.2 with nested test classes organized by concern.
- Use `@TempDir` for file-system tests.
- Mock tools for unit tests; integration tests use real tools when available.
- Parser tests use inline YAML strings via `SigmundConfigParser.parse(source, reader)`.

## Configuration

Tool settings live in the top-level `tools` section. `signing.toolchain` and `discovery.toolchain` are simple name lists referencing tools by name.

```yaml
tools:
  bc:
    signing-fingerprint: "ABCD..."
  sq:
    cipher-suite: mldsa87-ed448

signing:
  signer: alice
  toolchain: [bc, sq]

discovery:
  toolchain: [bc, sq]
  resolve-signers: true
```

## Documentation

Update docs in `docs/` whenever config schema or behavior changes. Key files: `configuration.md`, `signing.md`, `verification.md`, `trust-verification.md`.

## Design Process

For non-trivial changes:
1. Write or update an ADR in `adr/` for architectural decisions
2. Create a design spec capturing requirements and approach
3. Break implementation into tasks with clear boundaries
4. Each task should be independently testable
5. Review against spec after implementation

## Common Patterns

- **First-successful routing:** When matching credentials to tools, iterate in toolchain order, call `createSigning()`, first non-null result wins.
- **Extension-first detection:** `SignatureFormat.canHandle()` checks file extension before reading content.
- **`injectFetchSettings()`** is conditional — only inject OpenPGP key-fetching settings for OpenPGP tools.
- **`isDefaultExclusiveSigner()`** — factory-level mechanism for zero-config CI (e.g., env-var-injected signing key).
