# ADR-005: Verification Result Model

## Status

Accepted — implemented by roadmap phase P1. Run-level types are deferred to the
phases that populate them (see *Run result*).

Amended by [ADR-009](009-an-unbound-key-is-never-failed.md): a key its certificate does not bind
is `INDETERMINATE(KEY_UNAVAILABLE)`, never `FAILED`, including when its self-signatures do not
verify.

## Context

Verification today produces two enums and a flat result. `TrustVerifier.assess()`
returns a `TrustResult` carrying a `TrustVerdict` (`TRUSTED`, `UNTRUSTED`,
`UNSIGNED`, `NOT_CONFIGURED`, `VERIFICATION_FAILED`), a list of
`MatchedEvidence` and a list of unmatched `EvidenceResult`. Below it, each
signature check produces a `VerifyResult` carrying a `Verdict` (`PASS`, `FAIL`,
`NO_KEY`, `SKIPPED`).

The [design direction](../docs/sigmund-verification-design-direction.md) sets
requirements this model cannot meet:

- **An attack signal must never look like an infrastructure problem** (§3.5).
  Today a malformed Sigstore bundle produces `FAIL`
  (`SigstoreTool.handleVerificationException`), an unreachable keyserver leaves
  `NO_KEY`, an unsupported algorithm produces `SKIPPED`, and a Sigstore
  trust-root failure throws. All of these are reported as if they were the same
  kind of event, or as if they were verification failures.
- **Results must explain themselves** (§1.1, §3.2). A result that changes
  between runs must carry enough to say why: which rule matched, which trust
  root was used, when the claim was made, which evidence file was consumed, and
  whether the answer came from cache.
- **Coverage is a property of the run** (§2.1) and must be recorded and signed
  alongside verdicts, with counts.
- **The model must be serializable**, because the cache stores full results
  (§3.7) and the VSA serializes them (§6).

Fields also sit at three different granularities, which the current flat result
conflates: a single assertion, a file, and a run.

## Decision

Introduce a three-level result model — claim, artifact, run — with a single
outcome vocabulary, and derive artifact outcomes by one shared roll-up
implementation.

Package: `dev.cyberstamp.sigmund.core`. The project is pre-adoption, so the
existing types are replaced rather than deprecated.

### Vocabulary: evidence and claim

Per §3.1, **evidence** is a file carrying assertions; a **claim** is one
verifiable assertion extracted from it. `VerificationUnit` is renamed `Claim`,
and its permitted subtypes follow:

```java
public sealed interface Claim permits OpenPgpClaim, SigstoreClaim { }
```

A scan of all 52 jars on the compile classpath — sigstore-java 2.2.0 and its
google-oauth transitives, Bouncy Castle, Jackson, resolver and plugin API —
found no class whose name contains `Claim`. The OIDC/JWT collision anticipated
in §3.1 does not exist, so `Claim` is used rather than `VerifiableClaim`.

### Digests

Per §3.2, digests are algorithm-tagged everywhere: subjects, evidence
references and policy references.

```java
public record DigestSet(Map<String, String> values) {
    public static final String SHA_256 = "sha256";
    public static DigestSet sha256(String hex);
    public String sha256();
    public boolean matches(DigestSet other);   // any algorithm both sides carry
}
```

`matches` returns false when the two sets share no algorithm: an undecidable
comparison is not a match.

### Subject

`ArtifactIdentity` is replaced by two records. Verification addresses a file, so
the coordinate carries classifier and extension, and the subject pairs it with
the digest of the bytes verified:

```java
public record ArtifactCoords(
        String namespace, String name, String classifier,
        String extension, String version) {
    public String purl();     // one-way projection, never parsed back (§8)
}

public record ArtifactSubject(ArtifactCoords coords, DigestSet digests) {
    public String purl();
}
```

The split keeps rule matching, which needs only the coordinate, apart from the
digest, which exists only once a file has been read.

A record rather than an interface: subjects are cache keys and serialized
values, so value semantics matter more than letting each build tool supply its
own implementation. Build-tool integrations map their coordinates into it.
Policy rules still match at GAV level only (§3.2); classifier and extension
exist for identification and reporting.

### Claim result

One per claim extracted from evidence.

```java
public record ClaimResult(
        String kind,                       // format name: "openpgp", "sigstore"
        ClaimOutcome outcome,
        IndeterminateReason reason,        // null unless outcome is INDETERMINATE
        List<Credential> attesterCredentials,
        String attesterDisplayName,
        AttesterRole role,
        TrustRootRef trustRoot,
        EvidenceRef evidence,
        Instant claimTime,                 // null when the claim carries none
        ClaimTimeSource claimTimeSource,
        Instant verifiedAt,
        String algorithm,
        String verifiedBy) { }             // tool that produced the outcome
```

```java
public enum ClaimOutcome { VERIFIED, FAILED, INDETERMINATE }

public enum IndeterminateReason {
    KEY_UNAVAILABLE(true),
    TRUST_ROOT_UNAVAILABLE(true),
    DISCOVERY_UNAVAILABLE(true),
    TOOL_UNAVAILABLE(true),
    UNSUPPORTED_ALGORITHM(false),
    EVIDENCE_MALFORMED(false);

    public boolean isTransient();
}

public enum AttesterRole { PUBLISHER, BUILDER, REGISTRY, THIRD_PARTY_VERIFIER, UNKNOWN }

public enum ClaimTimeSource { TRANSPARENCY_LOG, SIGNER }

public record EvidenceRef(Path file, DigestSet digest, String source) { }

public record TrustRootRef(String kind, String identifier) { }
```

The claim kind is the format name rather than an enum: it is the name formats
and toolchains are already configured by, and a parallel enum would have to be
kept in step with it.

`role` is always `UNKNOWN` today: nothing derives or asserts one, and ADR-007
removes the field until an attestation consumer needs it.

`ClaimOutcome` is deliberately not the artifact-level `ArtifactOutcome`: a claim is
never `NO_CLAIM`, never `NOT_CONFIGURED`, and cannot be `UNSATISFIED` on its
own, because satisfaction is a property of requirements over a set of claims.

`isTransient` is what lets operators triage (§3.5): transient reasons are
retried and may be downgraded from cache, permanent ones are not.

Claim time and its source are properties of the claim, so `Claim` exposes
`claimTime()` and `claimTimeSource()` and the result copies them.
`ClaimTimeSource` records whether the time came from a transparency log or from
the signer (§3.4), which is what makes the OpenPGP backdating risk visible in
the record rather than implied (§1.1). §3.4 calls the instant itself the
evaluation basis; the type names its source, which is the part a result has to
carry.

### Artifact result

One per resolved file.

```java
public record ArtifactResult(
        ArtifactSubject subject,
        ArtifactOutcome outcome,
        IndeterminateReason reason,        // null unless outcome is INDETERMINATE
        List<ClaimResult> claims,          // all of them, contributing or not
        Instant verifiedAt) { }

public enum ArtifactOutcome {
    SATISFIED, UNSATISFIED, FAILED, NO_CLAIM, INDETERMINATE, NOT_CONFIGURED
}
```

Two components are added by the phases that produce them, not before:

- **Matched rule** — the rule's pattern and its location in the policy file, so
  a surprising verdict traces to the line that caused it. Added with the policy
  schema (P2.6), which is what records locations.
- **Cache information** — when the result was stored and its age. Added with
  the result cache (P4), if one is built.

### Run result

One per verification run. **Not yet implemented:** the shape below records the
intent, and each part lands with the phase that has something to put in it —
coverage and enforcement mode with P3.6, policy reference with P4.2. Until then
`VerificationReport` holds the artifact results and derives the counts.

```java
public record VerificationRun(
        PolicyRef policy,
        Coverage coverage,
        EnforcementMode enforcementMode,
        List<ArtifactResult> artifacts,
        Map<ArtifactOutcome, Integer> counts) { }

public record PolicyRef(String location, DigestSet digest) { }   // digest null in zero-config

public record Coverage(
        InsertionPoint insertionPoint,
        List<String> scopesCovered,
        boolean buildToolingCovered) { }

public enum InsertionPoint { PLUGIN_GOAL, CORE_EXTENSION, RESOLVER }

public enum EnforcementMode { ENFORCING, OBSERVE }
```

This is the type the VSA serializes (§6) and the type a report renders. Counts
are derived on construction rather than tracked by callers, so the coverage
figures in an attestation cannot drift from the results beside them.

### Roll-up

The artifact outcome is derived from claim results in one place —
`OutcomeRollup` — used by every insertion point, so goal and extension cannot
diverge (§2). It implements §3.2.1:

```
1. any claim FAILED                              -> FAILED
2. claims with UNSUPPORTED_ALGORITHM are set aside; requirements are
   evaluated over the claims that verified
3. no requirement applies                        -> NOT_CONFIGURED
4. requirements met:
   ANY_CLAIM                                     -> SATISFIED
   ALL_CLAIMS and a verified claim unaccepted    -> UNSATISFIED
   ALL_CLAIMS and an INDETERMINATE claim remains -> INDETERMINATE(that reason)
   otherwise                                     -> SATISFIED
5. requirements unmet, in order:
   any remaining INDETERMINATE claim             -> INDETERMINATE(that reason)
   requirements met had the set-aside claims
   been made by the keys they name               -> INDETERMINATE(UNSUPPORTED_ALGORITHM)
   nothing verified and a set-aside claim
   names no key                                  -> INDETERMINATE(UNSUPPORTED_ALGORITHM)
   any claim verified or set aside               -> UNSATISFIED
   nothing found                                 -> NO_CLAIM
```

Setting aside before the `NOT_CONFIGURED` check is not observable, but it keeps
the order the same as §3.2.1.

**Signers only an uncheckable claim names (revised 2026-10-16).** A set-aside
claim proves nothing, but an OpenPGP packet names the key that made it, which
`ClaimResult.declaredIssuer` records apart from the proven credentials. When a
requirement is unmet and would be met had each set-aside claim been made by the
key it names, the requirement is unmet only for want of a tool: an artifact
co-signed with a post-quantum key that a classic-only verifier cannot check is
`INDETERMINATE(UNSUPPORTED_ALGORITHM)` — install a tool that can — not
`UNSATISFIED`, which would send the policy owner looking for a trust problem.
The verified claims are evaluated again alongside the hypothetical ones because a
requirement is a conjunction and the evaluator does not say which clauses are
open: a verified claim may meet one clause and a set-aside claim another. It
cannot excuse a wrong signer: adding claims only meets more clauses, so the step
holds only when every clause the verified claims leave unmet accepts a key some
set-aside claim names. An appended block naming a required co-signer
does turn `UNSATISFIED` into `INDETERMINATE` when the classic signature is
genuine, which is exactly what the honest artifact gets on that verifier; both
block by default. This replaces an earlier "the rule demands a claim kind" step,
which the schema cannot express.

The same named key decides the other way when nothing verified: an artifact whose
only claims are set aside, each naming a key the requirement does not accept, is
`UNSATISFIED`, as it would be had a classic block verified beside them — a tool
would not change the verdict, and the operator's next step is a trust decision,
not an install. Only when some set-aside claim names no key, leaving no signer to
judge, is it `INDETERMINATE(UNSUPPORTED_ALGORITHM)`. The report shows each
set-aside claim's named key, marked as not verified, so the operator can tell
which key the policy would have to name.

```java
public enum ClaimSetMode { ALL_CLAIMS, ANY_CLAIM }
```

`ClaimSetMode` replaces `ListedEvidencePolicy`; `ALL_CLAIMS` stays the default,
matching RPMv6 (§7).

Requirement evaluation itself — what a requirement is, how it is scoped — is
ADR-007. `OutcomeRollup` depends only on an evaluator interface, so the two can
be built and tested independently:

```java
public interface RequirementEvaluator {
    Evaluation evaluate(List<ClaimResult> verifiedClaims);

    record Evaluation(boolean satisfied, List<ClaimResult> accepted,
            List<ClaimResult> unaccepted) { }
}
```

The rule is matched once, before the roll-up, and its `Requirement` is the
evaluator; no rule means no evaluator, which is `NOT_CONFIGURED`.

### Tool-level results

`VerifyResult` and its sealed subtypes stay, since they carry format-specific
detail, but they carry `ClaimOutcome` plus an `IndeterminateReason` instead of
`Verdict`. Current mappings change as follows:

| Situation | Today | ADR-005 |
|---|---|---|
| Signature verifies | `PASS` | `VERIFIED` |
| Signature does not verify | `FAIL` | `FAILED` |
| Signer key not available | `NO_KEY` | `INDETERMINATE(KEY_UNAVAILABLE)` |
| Signature packet names no issuer | `SKIPPED` | `INDETERMINATE(EVIDENCE_MALFORMED)` |
| Verification tool missing or broken | `FAIL` | `INDETERMINATE(TOOL_UNAVAILABLE)` |
| Algorithm unsupported by tool | `SKIPPED` | `INDETERMINATE(UNSUPPORTED_ALGORITHM)` |
| Sigstore bundle unparseable | `FAIL` | `INDETERMINATE(EVIDENCE_MALFORMED)` |
| Sigstore trust root unavailable | thrown | `INDETERMINATE(TRUST_ROOT_UNAVAILABLE)` |

`UnverifiedResult` keeps its role for outcomes produced without a tool, and its
invariant becomes "never `VERIFIED`".

#### Key validity is not signature validity (revised 2026-10-16)

A backend can decline a signature that is cryptographically correct, because it
will not use the key that made it. Reporting that as `FAILED` turns a verifier
decision into an attack signal that blocks every build, and since the toolchain
decides which backend answers, it makes the verdict depend on an argument. Each
backend therefore separates the two:

| Situation | Outcome |
|---|---|
| The signature does not match the artifact's bytes | `FAILED` |
| The key had expired when it signed, or was revoked — as compromised at any time, for another reason before it signed (§3.8) | `FAILED` |
| The key's certificate carries no self-signature binding it — keys.openpgp.org serves such a certificate for an owner who never verified an address | `INDETERMINATE(KEY_UNAVAILABLE)` |
| The verification policy rejects an algorithm the signature or its binding uses | `INDETERMINATE(UNSUPPORTED_ALGORITHM)` |
| The tool threw, or produced no verdict | `INDETERMINATE(TOOL_UNAVAILABLE)` |

Self-signatures that are present, use accepted algorithms and still do not bind
the key are a broken or forged certificate, and stay `FAILED`.

How each backend reaches these:

- **Bouncy Castle** checks `isTestedCorrect()` before `isValid(policy)`, and
  explains an invalid key from its revocation and expiry at the signature's time
  and from the self-signatures it carries.
- **GnuPG** is judged by its `--status-fd` lines, not its exit code: it exits 0
  for a good signature by a revoked key (`REVKEYSIG`) or by a key that had
  expired when it signed (`EXPKEYSIG` with a `KEYEXPIRED` time not after the
  signature's), so an exit-code reading verified both.
- **Sequoia** reports through text: its closing tally separates a *bad signature*
  from a *bad key*, and the detail of a bad key says whether it was revoked,
  expired, rejected by policy, or not bound.

The algorithms accepted are defined once, in `VerificationAlgorithms`, and
translated per backend: Bouncy Castle's `OpenPGPPolicy`, a Sequoia crypto policy
passed through `SEQUOIA_CRYPTO_POLICY`, and GnuPG's defaults, which already
match. On top of each backend's modern defaults they are: SHA-1 and RIPEMD-160
document signatures; SHA-1 and RIPEMD-160 self-signatures at any date; RSA and
DSA keys from 1024 bits. SHA-1 self-signatures are accepted without a cut-off
because the practical attack on SHA-1, a chosen-prefix collision, needs the
victim to sign attacker-prepared data, and a self-signature is made by the key's
owner over their own key — GnuPG exempts them for the same reason, and Sigmund
relies on no third-party certifications. The definition is not configurable: no
one has asked for a different one, and since it changes what is accepted, a
setting for it would belong in the policy file, not in arguments (§5.3). The
Sigmund version recorded with a result pins it (§3.7).

`KeyValidityAgreementTest` runs every row above through all three backends and
requires one answer.

`SignatureEvidenceAdapter` keeps its tool-selection behaviour — first tool that
reaches a verdict wins, transient reasons trigger a key fetch and retry — but
`EvidenceProvider.verify()` returns `List<ClaimResult>` rather than
`List<EvidenceResult>`. `EvidenceResult` and `MatchedEvidence` are absorbed:
proven credentials and provider name live on `ClaimResult`, and the
matched-versus-unmatched split becomes a property of requirement evaluation
rather than of the result shape.

### Serialization

Results are serialized with Jackson to JSON as the input to the run record and
attestations (§6), and to a result cache if one is built (§3.7). Rules: field
names are stable and explicit, enums serialize as their names, `Instant` as
ISO-8601 UTC, `Path` as a string, and `DigestSet` as a plain object.
Serialization is round-trip tested, so a reader gets back what was written.

## Consequences

**Removed:** `TrustVerdict`, `Verdict`, `TrustResult`, `EvidenceResult`,
`MatchedEvidence`, `ArtifactIdentity` (interface), `MavenArtifactIdentity`
(becomes a mapping function to `ArtifactSubject`). `ListedEvidencePolicy` stays
as the config-side setting until the policy schema is replaced (P2.6);
`TrustPolicy.claimSetMode()` maps it to `ClaimSetMode`.

**Renamed:** `VerificationUnit` → `Claim`, `OpenPgpVerificationUnit` →
`OpenPgpClaim`, `SigstoreVerificationUnit` → `SigstoreClaim`.

**Affected beyond the trust path:** `FileSignatureReport` and
`SignatureVerificationReport` render CLI signature verification, which also
used `Verdict`. They move to `ClaimOutcome`, and `ReportVerdict` is removed in
favour of counts by claim outcome, so `sigmund verify-signature` reports
"indeterminate: key unavailable" where it said "no key".

**Behaviour changes users would notice:**

- A hybrid `.asc` verified without Sequoia is `SATISFIED` on the strength of its
  classic signature, where today the unsupported PQC block leaves it
  `UNTRUSTED` under `listed-evidence: all`.
- An unreachable keyserver yields `INDETERMINATE(KEY_UNAVAILABLE)` rather than
  `UNTRUSTED`, which is what makes the cache downgrade of §3.7 meaningful.
- A corrupt Sigstore bundle no longer looks like a failed signature.

**Ordering.** This ADR was implemented by roadmap phase P1, and blocks P2
(requirements), the persistent key store and revocation in P4, and attestation
emission, which serializes these types.

**Not decided here:** credentials (ADR-006); requirement and policy
schema, per-outcome enforcement and what replaces
`signature-optional` (ADR-007). Enforcement reads outcomes; it does not change
how they are derived.
