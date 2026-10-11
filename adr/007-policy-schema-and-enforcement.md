# ADR-007: Policy Schema and Enforcement

## Status

Proposed. Revised 2026-10-11 after a schema design review that settled several
points the original left open or decided differently: field renames (`targets` →
`match`, `artifacts` → `artifact-sets`), `claim-set` → `extra-claims` (global
only), `by-scope` dropped, the enforcement model recast as *policy present
enforces / zero-config observes*, an explicit catch-all pattern, and issuer
validation moved wholly to config-load time. The superseded wording is preserved
in git history; the roadmap decision log is updated alongside the P2 work.

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
- **Only one signer set per target.** A rule cannot say "the publisher's key
  AND our CI's Sigstore identity"; any listed signer satisfies it.
- **Enforcement is one dial.** `on-untrusted` conflates outcomes that need
  different treatment: a missing signature is a coverage decision, a failed
  signature is an attack signal (§3.5, §3.6).

ADR-005 supplies the outcome vocabulary and roll-up; ADR-006 supplies
credentials. What remains is the document that states what must be true for an
artifact, and what happens when it is not.

## Decision

### Document shape

```yaml
version: 2

issuers:                      # ADR-006: default issuers for issuer-less identity entries
  - keys.openpgp.org          #   known name → directory (kind inferred by name)
  - https://token.actions.githubusercontent.com   #   https:// → OIDC

signers:                      # ADR-006
  apache:
    pgp4: 4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12   # keys already seen
    email: release@apache.org                          # keys to come
  acme-release:
    pgp4: 9B1C0E7F2D4A6B83C5E1F09A7D3B2C4E6F8A0B1D
  acme-ci:
    identities:
      - source-repository-uri: https://github.com/acme/widget
        build-config-uri: https://github.com/acme/widget/.github/workflows/release.yml

artifact-sets:                # named GAV-pattern sets — pure load-time labels
  apache-stack:
    - "org.apache.maven.*"
    - "org.apache.commons.*"

rules:
  - match: [apache-stack]     # an artifact-set name, or an inline GAV pattern
    requires: [apache]

  - match: ["com.acme.*"]
    requires: [acme-release, {any-of: [acme-ci, acme-ci-eu]}]   # acme-release AND (acme-ci OR acme-ci-eu)

  - match: ["org.jboss.*"]
    requires: [{any-of: [jboss, redhat]}]                       # either

  - match: ["*"]              # catch-all: "everything else"
    on-no-claim: ignore

defaults:
  extra-claims: reject        # global only; an unlisted extra verified claim → UNSATISFIED
  # relaxation overrides; the values below are the code defaults WHEN A POLICY IS PRESENT:
  #   on-unsatisfied: fail
  #   on-no-claim: fail
  #   on-indeterminate: fail
  #   on-not-configured: fail   # (ignore in zero-config)
  # FAILED is always fail and non-overridable.
```

`trust`, `signature-optional` and `policy` are replaced. The named-set block,
previously `artifacts`, becomes `artifact-sets`; sets keep working and are
referenced by name in `match`.

### Rules

A rule is `match` plus `requires`, with optional per-rule enforcement overrides.

- **`match`** entries are artifact-set names or inline GAV patterns. A `match`
  entry resolves as: a defined artifact-set name → expand to its patterns; else
  a GAV-shaped pattern; else a config error naming the undefined set or the
  malformed pattern. An artifact-set is a pure load-time label with no effect on
  matching — it expands to its patterns, and the matched artifact is scored by
  the individual pattern that matched. The set name is retained only for the
  matched-rule reference in the report.
- Rules match at GAV level only; classifier and extension are not policy
  dimensions (§3.2). A pattern with more than three coordinate segments is a
  config error rather than silently matching nothing.
- **The catch-all `"*"`** is an explicitly permitted pattern — the
  lowest-specificity match for "everything no more-specific rule caught." With a
  catch-all present an artifact always matches some rule, so `NOT_CONFIGURED`
  cannot occur; the remainder is governed by the catch-all's `requires` and
  enforcement. Bootstrap emits one.
- **Most specific rule wins**, by the existing specificity score. One rule
  applies — no merging across rules, so the matched rule fully explains the
  outcome. Two rules of identical specificity for the same target are a config
  error, not a silent pick.
- **The matched-rule reference** on the artifact result (ADR-005) carries the
  rule's pattern (and set name where used) and its location in the file, so a
  surprising verdict traces to the line that caused it.

### Requirements

Each entry in `requires` is a clause: a signer id, or `any-of` with a list of
signer ids.

```yaml
requires:
  - acme-release                    # this signer
  - any-of: [acme-ci, acme-ci-eu]   # and one of these
```

- **Clauses are conjunctive; signers within `any-of` are disjunctive.**
  `requires: [a, b]` means both. The mixed scalar/`any-of` shape is deliberate:
  the single-signer and all-required cases — overwhelmingly the common ones —
  stay terse, and the map appears only for the rarer disjunction. The parser
  normalizes both shapes to a conjunction of disjunctions, `List<Set<String>>`
  by signer id, a scalar clause being a one-member set. Threshold (m-of-n)
  clauses are deferred; `any-of` is 1-of-n.
- A clause is satisfied by a **verified claim** whose proven credentials match
  one of the named signers' credentials (ADR-006).
- **No roles.** A clause names signers, and a signer's credentials already say
  what it is: an OpenPGP key or a CI workflow identity. A role label would add a
  second, unchecked statement of the same thing; it is deferred until an
  attestation consumer needs the capacity spelled out (§3.3).
- **`extra-claims`** (renamed from `claim-set`) governs a verified claim from a
  signer no clause named, *once the required clauses are already satisfied*:
  `reject` (default) makes such an extra claim `UNSATISFIED` — the listed signer
  set is treated as complete; `ignore` records and ignores it. It is set in
  `defaults` only; a per-rule override is deferred until there is demand.
  `reject` replaces `listed-evidence: all`; `ignore` replaces `any`.
  `unlisted-evidence` disappears, subsumed by this one setting. `extra-claims`
  does **not** govern a claim that *fails* cryptographically (always `FAILED`,
  roll-up step 1) or one no verifier supports (set aside) — only an otherwise
  acceptable, unlisted, surplus claim.

### Enforcement

Each non-`SATISFIED` outcome has its own action — `fail`, `warn`, `ignore` —
resolved in this order: rule-level, `defaults`, code default. (There is no
scope level; see "`by-scope` dropped" below.)

| Outcome | Code default | Notes |
|---|---|---|
| `FAILED` | fail | Non-overridable at any level, even in zero-config; a setting for it is a config error |
| `UNSATISFIED` | fail | A claim exists and policy does not accept it |
| `NO_CLAIM` | fail | Configured-only outcome (see roll-up); relax with `on-no-claim: ignore` |
| `INDETERMINATE` | fail | Configured-only; transient infra, relax with `on-indeterminate: warn` once measured to matter |
| `NOT_CONFIGURED` | **fail if a policy is present, `ignore` in zero-config** | The only outcome spanning both worlds |

The model is a single switch tied to **policy presence**:

- **Zero-config (no policy file loaded) observes.** The only outcomes that can
  occur are `NOT_CONFIGURED` (→ `ignore`) and `FAILED` (→ `fail`), so a build
  with no policy never fails except on a signature that does not
  cryptographically verify.
- **A policy present enforces.** Every non-`SATISFIED` outcome defaults to
  `fail`. The per-outcome settings are therefore *relaxation overrides* — an
  author reaches for `on-no-claim: ignore`, a catch-all, or `on-indeterminate:
  warn` to loosen a specific case deliberately. `NOT_CONFIGURED` failing when a
  policy is present is the same observe/enforce switch applied to coverage: if
  you wrote a policy, an artifact outside every rule is an unhandled case, fixed
  by a rule or a catch-all.

This rests on the roll-up precedence (ADR-005, §3.2.1): **"no rule applies"
is decided before "no claim found."** So `NO_CLAIM`, `UNSATISFIED` and
`INDETERMINATE` are *configured-only* outcomes — they require a matched rule —
and only `NOT_CONFIGURED` and `FAILED` can arise in zero-config. That is what
lets the model collapse to one switch.

`on-no-claim: ignore` on a rule is what `signature-optional` used to express,
with an important difference: the artifact is still verified and still counted as
`NO_CLAIM` in coverage (§2.1), and a signature that *is* present is still checked
— so a `FAILED` signature on a tolerated artifact still fails the build. Today
those artifacts are filtered out before assessment and never looked at.

Enforcement decides build failure only. It never changes an outcome, so observe
mode (§5.4) and VSA emission (§6) report the same results a strict run would.

**`by-scope` dropped.** The original proposal carried per-scope enforcement
(`build-tooling` strictest). It is removed: *what* to verify (which scopes/
dependencies) is a goal parameter and extension request-context concern — the
"how" of §5.3 — not a policy dimension, and *how strictly* stays per-outcome and
uniform. This keeps the goal and the core extension applying identical
enforcement (only their coverage differs), so their results agree without
caveat. The "strictest treatment for build tooling" capability (§3.6) returns
with the extension (roadmap P5.5), in whatever shape fits then; no-back-compat
makes adding it later free.

### Validation

The parser is strict and validates at config-load time; errors name the file,
the location and the fix. It checks:

- unknown keys are errors;
- signer references in `requires` resolve to defined signers;
- no setting exists for `FAILED`;
- `match` entries resolve to a defined artifact-set or a GAV-shaped pattern
  (with `"*"` permitted as the catch-all), and no pattern exceeds three
  coordinate segments;
- no two rules tie on specificity.

`requires` has exactly two clause shapes, normalized to one model — a conjunction
of disjunctions. Two edge cases are errors rather than readings:

- **An empty `requires`**, which would read as "a rule applies and nothing is
  required" and make every matched artifact vacuously `SATISFIED`. A rule that
  tolerates artifacts says so through enforcement, such as `on-no-claim: ignore`.
- **A bare scalar**, `requires: acme-release`. `requires` is always a sequence;
  its elements may be scalars.

**Issuer validation is entirely load-time.** Issuer kind is inferred from the
name — a known directory name → directory, another `https://` URL → OIDC,
anything else an error — with no network probing, so classification is
deterministic and tamper-proof. Each kind's attribute vocabulary is known
(directory → a verified email; OIDC → the Fulcio certificate-extension
registry). For every issuer-less identity entry the loader computes which listed
issuers could assert it, by kind and attribute capability, and errors if the
count is **0** ("no listed issuer can assert this — add one") or **greater than
one** ("ambiguous — name the issuer inline"). An entry may still carry an inline
`issuer`, trusted for that entry only and need not be listed.

### Schema

A JSON Schema for the policy document ships as a resource and is published for
editors: with it, YAML language servers in IntelliJ and VS Code offer
completion, hover documentation and unknown-key errors while the file is being
written. It states the structure — keys, value types, the two `requires` clause
shapes as a `oneOf`, `additionalProperties: false` throughout.

**The parser stays authoritative.** The schema cannot express cross-references,
specificity ties or issuer assertability, and a schema validator's errors point
at a JSON path where the parser names the rule and the fix. So the schema is not
consulted at runtime and adds no dependency to verification.

Drift between the two is caught by a test that runs on every build: every valid
fixture and every example in the documentation passes both the schema and the
parser, and every invalid fixture the parser rejects for a structural reason is
rejected by the schema too.

## Consequences

**Removed:** `TrustPolicy.expectedSigners` and `isUnsignedAllowed`,
`DefaultTrustPolicy`, `ListedEvidencePolicy`, `UnlistedEvidencePolicy`,
`UntrustedPolicy`, and the `trust`, `signature-optional` and `policy` sections.

**Added:** `rules` with `match` and `requires` (`any-of` within a clause),
`artifact-sets` (renamed from `artifacts`), `defaults`, per-rule enforcement
overrides, `extra-claims`; the explicit catch-all `"*"`; a published JSON Schema
for the document.

**Not added:** `by-scope` enforcement (deferred to the extension); a per-rule
`extra-claims` override (deferred to demand); threshold (m-of-n) clauses
(deferred); attester roles.

**`TrustPolicy` becomes** a rule lookup plus a `RequirementEvaluator`
(ADR-005) — `matchRule(subject)` and `evaluate(subject, verifiedClaims)` — so
the roll-up stays independent of schema details.

**Bootstrap** (`generateTrustConfig`) emits `rules` with one clause per set —
the observed signer, or `any-of` where a set was observed signed by several — a
catch-all `"*"` with `on-no-claim: ignore` for the remainder, and `artifact-sets`
for the observed groupings.

**`AttesterRole` and `ClaimResult.role` are removed.** Nothing sets a role other
than `UNKNOWN`, and without role-scoped clauses nothing reads one. They return
with attestations if a consumer needs them.

**Behaviour users would notice:** a build with no policy fails only on a
cryptographically failing signature, everything else observed; a build *with* a
policy fails on any non-`SATISFIED` outcome unless the author relaxes it or
writes a catch-all, which makes coverage a deliberate decision; a policy that
used to pass with a tolerated unsigned artifact now also verifies any signature
that artifact carries; a 4-segment pattern that silently matched nothing is now
an error; an extra verified signature from an unlisted signer, under
`extra-claims: reject`, is `UNSATISFIED` with the matched-rule reference naming
the cause.

**Ordering:** implemented in roadmap phase P2 (schema, evaluator, bootstrap) and
P3 (enforcement, run modes). Downstream doc-sync: the design direction §3.6
(drop `by-scope`, record the enforce/observe switch), the roadmap P2.6/P2.7/P3.1
task text, and `configuration.md`/`trust-verification.md` (P2.11).
