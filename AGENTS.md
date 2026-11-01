# Agent Guidelines for Sigmund

Guidelines for AI agents working on the sigmund codebase. This file holds rules and
conventions that do not follow from reading the code; for what the code is, read the code and
the docs it points to rather than a summary here.

## Project Overview

Sigmund is a Maven plugin and CLI for artifact signing, signature verification, and dependency trust enforcement. Multi-module Maven project: `core`, `cli`, `maven-plugin`, `sigstore`.

Where to look:

- `docs/sigmund-verification-design-direction.md` — what verification is for and why (cited as §n)
- `docs/sigmund-verification-roadmap.md` — what is next and in what order
- `adr/` — decisions and the alternatives rejected
- `docs/configuration.md` — the `sigmund.yaml` schema, published for editors as
  `core/src/main/resources/sigmund.schema.json`
- `docs/architecture.md` — types and how they fit together

## Build and Test

```bash
# Full build with integration tests and strict javadoc
mvn verify

# Core module only
mvn test -pl core

# Specific test class
mvn test -pl core -Dtest="SigmundConfigParserTest"

# Maven plugin tests (install core first when it changed: mvn install -pl core -DskipTests)
mvn test -pl maven-plugin

# Skip the tests that need gpg or sq (both run by default and fail without the tool)
mvn verify -Dsigmund.test.skip-gpg=true -Dsigmund.test.skip-sq=true
```

Java 17 target. No JPMS module-info. The build formats sources; expect import order and line
wrapping to change after `mvn verify`.

## Working Rules

- **No backward compatibility.** Sigmund has not been adopted. Replace types, config keys and
  parameters outright — no aliases, deprecations or migration code. Design docs in `docs/` are
  edited in place; ADRs are not (see [Architecture Decision Records](#architecture-decision-records)).
- **Core uses repository concepts, never build-tool types.** Coordinates, layout and sidecar
  conventions are fine in `core`; Maven plugin API, project model, resolver session and Gradle
  API are not.
- **Introduce types, options and vocabulary when code needs them**, not because a design
  sketches them.
- **Tests and docs ship with the change.** Update `docs/` and this file in the same change when
  behaviour, schema or conventions move.
- **The schema moves with the parser.** `core/src/main/resources/sigmund.schema.json` is the
  published schema of `sigmund.yaml`. A change to what the parser, the policy compile or a tool
  factory accepts changes the schema in the same commit; `SchemaAgreementTest` holds them
  together — add the new shape to its valid or structurally invalid documents. Sigmund never
  reads the schema at runtime.

## Code Style

- **Package imports only.** Never use fully-qualified names inline.
- **Small, descriptive methods.** Extract logical steps into well-named private methods rather than writing long method bodies.
- **Detailed javadoc** on all public types and methods. Explain semantics, contracts, and relationships — not just `@param`/`@return`.
- **No comments on implementation.** Code should be self-explanatory. Only comment non-obvious constraints or workarounds.
- **Defensive copies** in records and constructors. Use `Map.copyOf()`, `List.copyOf()`, `LinkedHashMap` when insertion order matters.
- **Narrow API.** Public only when something outside the package needs it.

## Vocabulary

- **Evidence** is the file carrying assertions — the `.asc`, the Sigstore bundle, a DSSE
  envelope. A **claim** is a single verifiable assertion extracted from it; a hybrid `.asc` with
  a classic and a PQC block is two claims. Never say "verification unit".
- A **credential** is what a claim proves: key material (`KeyCredential`, full fingerprint) or an
  identity asserted by an issuer the policy names (`IdentityCredential`). An OpenPGP user ID is
  never a credential.
- **Policy** is the `rules`/`defaults` part of `sigmund.yaml`; `verification` holds settings for
  *how* verification runs, which can change what is seen but never what is accepted (§5.3).

## Verification Invariants

Rules the code relies on; breaking one is a defect even if tests pass.

- **`FAILED` is the attack signal and is never overridable.** A claim is `FAILED` only when its
  bytes do not match, or its key had expired when it signed or was revoked (compromise at any
  time, otherwise before it signed). A key a tool will not use is `INDETERMINATE` with a reason
  — never `FAILED` ([ADR-005](adr/005-verification-result-model.md)).
- **Backends must agree.** The toolchain is an argument, so the outcome cannot depend on which
  backend answered. Judge CLI tools by what they report (GnuPG status lines, `sq`'s tally), not by
  exit codes. Accepted algorithms are defined once in `VerificationAlgorithms`.
  `BackendAgreementTest` and `KeyValidityAgreementTest` enforce this.
- **Enforcement never changes an outcome.** Outcomes come from the roll-up; whether they block is
  resolved separately from the matched rule.
- **A policy is declared only when the file has `rules`** (`TrustPolicy.declared()`); `defaults`
  without `rules` is a load error. Without a policy, verification observes: only `FAILED` blocks.
- **Signing never compiles the policy.** The parser produces `TrustPolicySpec`; `RulePolicy.compile`
  runs only on the verification path, so verification-only config errors cannot break signing.

## Architecture

**Layer 1 — Identity verification:** "Is this artifact from someone I trust?" via `TrustVerifier`, `EvidenceProvider`, `SignerIdentity`, `TrustPolicy`.

**Layer 2 — Signature operations:** cryptographic signing and verification via `SignatureTool`, `SignatureFormat`, `Claim`, `VerifyResult`.

**Bridge:** `SignatureEvidenceAdapter` wraps a `SignatureFormat` and its tools into an `EvidenceProvider`.

`Claim` and `VerifyResult` are sealed — adding a new format requires adding `permits` in core. This is deliberate: new formats are rare and warrant core review.

## Common Patterns

- **Extension-first detection:** `SignatureFormat.canHandle()` checks file extension before reading content.
- **`injectFetchSettings()`** is conditional — only inject OpenPGP key-fetching settings for OpenPGP tools.
- **`isDefaultExclusiveSigner()`** — factory-level mechanism for zero-config CI (e.g., env-var-injected signing key).
- **A tool setting is declared where it is read.** A factory reads its settings only through its
  `ToolSetting` enum, and `acceptedSettings()` is derived from the enum's values, so reading and
  accepting cannot drift; an unused constant is a setting accepted and ignored. Each setting is
  also listed under `tools.<name>` in the schema, which `SchemaAgreementTest` holds to the
  factory, and in its table in `docs/configuration.md`. A setting that takes a list says so on its
  constant (`takesList()`), and `listSettings()` is derived from it with `ToolSetting.listKeysOf`.
  The key-fetching settings Sigmund injects are `FetchSetting`, not accepted under `tools`.

## Testing

- Write tests for every change. TDD where practical.
- JUnit with nested test classes organized by concern.
- Use `@TempDir` for file-system tests.
- Mock tools for unit tests; integration tests use the real tools and fail when one is missing.
  `gpg` and a post-quantum `sq` (1.4.0+) are required to build, as CI installs them. A test that
  needs a tool carries `@DisabledIfSystemProperty(named = "sigmund.test.skip-<gpg|sq>",
  matches = "true")`, so `-Dsigmund.test.skip-gpg=true` or `-Dsigmund.test.skip-sq=true` skips
  it on request; both are off by default. Never skip on what the environment happens to hold —
  an absent tool, a set variable. A variable that changes Sigmund's behaviour, such as
  `SIGMUND_BC_SIGNING_KEY`, is excluded from the test JVM in the root `pom.xml`
  (`excludedEnvironmentVariables`); a test that needs it sets it on a process it forks.
- Parser tests use inline YAML strings via `SigmundConfigParser.parse(source, reader)`.
- When a test pins a CLI tool's output, use the tool's real output — including invisible
  characters such as `sq`'s no-break spaces — captured from the installed version.

## Design Process

For non-trivial changes:
1. Write an ADR in `adr/` for an architectural decision; one that changes an accepted decision is a
   new ADR
2. Create a design spec capturing requirements and approach
3. Break implementation into tasks with clear boundaries
4. Each task should be independently testable
5. Review against spec after implementation

## Architecture Decision Records

An ADR records one decision: what was decided, why, and what it was chosen over. How the system
works today belongs in `docs/` and the javadoc, not in an ADR — an ADR that describes the code
goes stale with every change, and the decision it holds gets lost among the description.

- **Sections:** Status; Context — the problem and the forces at the time; Decision — stated so a
  later ADR can amend or reverse it; Alternatives — each option rejected and why; Consequences —
  what follows, costs included.
- **Not in an ADR:** class or method listings, configuration reference, step-by-step flows,
  lists of classes added or changed, test plans, follow-up task lists. Code or YAML appears only
  when the decision is about a shape — an interface, a config key — and then only the part
  decided.
- **Status:** `Proposed`, `Accepted`, `Deferred` or `Superseded by ADR-n`, followed by one line
  per later change, such as `Amended by ADR-n: <what changed>`.
- **A proposed ADR is edited freely. An accepted one is not:** only its Status gains lines, and
  factual slips — a typo, a broken link — are fixed in place. A change to an accepted decision is
  a new ADR naming the ADR and the part it amends or supersedes.
