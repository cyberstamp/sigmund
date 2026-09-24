# ADR-007: Policy Schema and Enforcement

## Status

Proposed

## Context

Policy today maps artifact patterns to expected signers:

```yaml
trust:
  "org.apache.maven.*": apache
signature-optional:
  - "com.internal.*"
policy:
  on-untrusted: fail
  listed-evidence: all
  unlisted-evidence: ignore
```

`DefaultTrustPolicy` answers three questions from this: which signers are
expected for an artifact, whether an unsigned artifact is allowed, and what to
do when the result is untrusted. Three limitations block the design direction:

- **"Expected signer" cannot express a new requirement type.** Adding "and a
  builder claim from our CI" has nowhere to go, because the value of a mapping
  is a signer, not a requirement (§3.2).
- **Roles are absent**, so a builder claim silently satisfies a rule meant for a
  publisher — the false-green §3.3 exists to prevent.
- **Enforcement is one dial.** `on-untrusted` conflates outcomes that need
  different treatment: a missing signature is a coverage decision, a failed
  signature is an attack signal (§3.5, §3.6).

ADR-005 supplies the outcome vocabulary and roll-up; ADR-006 supplies
credentials, issuers and matchers. What remains is the document that states what
must be true for an artifact, and what happens when it is not.

## Decision

### Document shape

```yaml
version: 2

issuers:                      # ADR-006: trust grants
  - keys.openpgp.org

signers:
  apache:
    credentials:
      - openpgp4: 4AEE18F83AFDEB23
  acme-ci:
    role: builder
    credentials:
      - issuer: https://token.actions.githubusercontent.com
        source-repository-uri: https://github.com/acme/widget

artifacts:                    # unchanged: named pattern groups
  apache-stack:
    - "org.apache.maven.*"
    - "org.apache.commons.*"

rules:
  - targets: [apache-stack]
    requires:
      - publisher: [apache]

  - targets: ["com.acme.*"]
    requires:
      - publisher: [acme-release]
      - builder: [acme-ci]

  - targets: ["com.internal.*"]
    requires:
      - publisher: [release-team]
    on-no-claim: allow        # what `signature-optional` used to say

defaults:
  claim-set: all              # or: any
  on-unsatisfied: fail
  on-no-claim: warn
  on-indeterminate: warn
  on-not-configured: warn
  by-scope:
    build-tooling:            # populated by the core extension (§2)
      on-no-claim: fail
      on-indeterminate: fail
```

`trust`, `signature-optional` and `policy` are replaced. `artifacts` groups keep
working and expand in `targets`.

### Rules

A rule is `targets` plus `requires`, with optional per-rule enforcement and
claim-set overrides.

- **`targets`** are GAV patterns or `artifacts` group names, matched as today by
  `ArtifactPatternMatcher`. Rules match at GAV level only; classifier and
  extension are not policy dimensions (§3.2). A pattern with more than three
  coordinate segments is a config error rather than silently matching nothing,
  which is what the current matcher does.
- **Most specific rule wins**, by the existing specificity score. One rule
  applies — no merging across rules, so the matched rule fully explains the
  outcome. Two rules with identical specificity for the same target are a config
  error, not a silent pick.
- **`PolicyRuleRef`** (ADR-005) carries the rule's pattern and its location in
  the file, so a surprising verdict traces to the line that caused it.

### Requirements

Each entry in `requires` is a role-scoped clause: a role, and the signers whose
credentials may satisfy it.

```yaml
requires:
  - publisher: [apache, jboss]      # any listed signer satisfies this clause
  - builder: [acme-ci]
```

- **Clauses are conjunctive; signers within a clause are disjunctive.** Two
  clauses mean "a publisher claim AND a builder claim"; two signers in one
  clause mean either will do. Without role-scoped clauses the role dimension is
  decorative (§3.3).
- A clause is satisfied by a **verified claim** whose attester credential
  matches one of the listed signers' matchers *and* whose role equals the
  clause's role. Role comes from the issuer profile's `default-role`, or from a
  `role:` on the signer; a derived-versus-asserted mismatch is a config error
  (ADR-006, §3.3).
- **`claim-set`** governs claims beyond those that satisfied the clauses:
  `all` (default) requires every remaining claim to be verified and accepted;
  `any` records and ignores them. This replaces `listed-evidence`.
  `unlisted-evidence` disappears: evidence from an unlisted signer is a verified
  claim that no clause accepts, which `claim-set: all` turns into `UNSATISFIED`
  and `claim-set: any` ignores.

### Enforcement

Each non-`SATISFIED` outcome has its own setting — `fail`, `warn`, `allow` —
resolved in this order: rule-level, scope-level, `defaults`, code defaults.

| Outcome | Code default | Notes |
|---|---|---|
| `FAILED` | fail | Not overridable at any level; a setting for it is a config error |
| `UNSATISFIED` | fail | A claim exists and policy does not accept it |
| `NO_CLAIM` | warn | Coverage decision; `fail` for build tooling |
| `INDETERMINATE` | warn | `fail` for build tooling; downgraded from cache first (§3.7) |
| `NOT_CONFIGURED` | warn | Nothing applies; zero-config runs are all of these |

`on-no-claim: allow` on a rule is what `signature-optional` used to express,
with an important difference: the artifact is still verified and still counted
as `NO_CLAIM` in coverage (§2.1), and a signature that *is* present is still
checked — so a `FAILED` signature on a tolerated artifact still fails the build.
Today those artifacts are filtered out before assessment and never looked at.

Enforcement decides build failure only. It never changes an outcome, so
observe mode (§5.4) and VSA emission (§6) report the same results a strict run
would.

### Validation

The parser is strict: unknown keys are errors. Beyond that it checks that
signer references in `requires` exist, that every credential matcher can be
asserted by some trusted issuer (ADR-006), that no setting exists for `FAILED`,
that target patterns are GAV-shaped, and that no two rules tie on specificity.
Errors name the file, the location and the fix.

## Consequences

**Removed:** `TrustPolicy.expectedSigners` and `isUnsignedAllowed`,
`DefaultTrustPolicy`, `ListedEvidencePolicy`, `UnlistedEvidencePolicy`,
`UntrustedPolicy`, and the `trust`, `signature-optional` and `policy` sections.

**Added:** `rules`, `requires`, `defaults`, per-rule enforcement, `claim-set`,
and `role:` on a signer.

**`TrustPolicy` becomes** a rule lookup plus a `RequirementEvaluator`
(ADR-005) — `matchRule(subject)` and `evaluate(subject, verifiedClaims)` — so
the roll-up stays independent of schema details.

**Bootstrap** (`generateTrustConfig`) emits `rules` with a single `publisher`
clause per group, and `on-no-claim: allow` for artifacts observed without
evidence, replacing the `signature-optional` list. Roles stay `unknown` unless
an issuer profile supplies one, and an `unknown` role satisfies only a clause
written for `unknown`.

**Behaviour users would notice:** a policy that used to pass with a tolerated
unsigned artifact now also verifies any signature that artifact carries; a
4-segment pattern that silently matched nothing is now an error; evidence from
an unlisted signer under `claim-set: all` is `UNSATISFIED` rather than
`UNTRUSTED` with no explanation of which claim caused it.

**Ordering:** implemented in roadmap phase P2 (schema, evaluator, bootstrap) and
P3 (enforcement, scopes, run modes).
