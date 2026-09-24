# ADR-005: Verification Result Model

## Status

Proposed

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

`ArtifactIdentity` is replaced by a record. Verification addresses a file, so
the subject carries classifier, extension and digest:

```java
public record ArtifactSubject(
        String namespace, String name, String version,
        String classifier, String extension, DigestSet digests) {
    public String purl();     // one-way projection, never parsed back (§8)
}
```

A record rather than an interface: subjects are cache keys and serialized
values, so value semantics matter more than letting each build tool supply its
own implementation. Build-tool integrations map their coordinates into it.
Policy rules still match at GAV level only (§3.2); classifier and extension
exist for identification and reporting.

### Claim result

One per claim extracted from evidence.

```java
public record ClaimResult(
        ClaimKind kind,
        ClaimOutcome outcome,
        IndeterminateReason reason,        // null unless outcome is INDETERMINATE
        List<Credential> attesterCredentials,
        String attesterDisplayName,
        AttesterRole role,
        TrustRootRef trustRoot,
        EvidenceRef evidence,
        Instant claimTime,                 // null when the claim carries none
        ClaimTimeSource claimTimeSource,
        Instant verificationTime,
        String algorithm,
        String verifiedBy) { }             // tool that produced the outcome
```

```java
public enum ClaimKind { OPENPGP_SIGNATURE, SIGSTORE_BUNDLE, DSSE_ATTESTATION }

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

`ClaimOutcome` is deliberately not the artifact-level `Outcome`: a claim is
never `NO_CLAIM`, never `NOT_CONFIGURED`, and cannot be `UNSATISFIED` on its
own, because satisfaction is a property of requirements over a set of claims.

`isTransient` is what lets operators triage (§3.5): transient reasons are
retried and may be downgraded from cache, permanent ones are not.

`ClaimTimeSource` records whether the time used came from a transparency log or
from the signer (§3.4), which is what makes the OpenPGP backdating risk visible
in the record rather than implied (§1.1). §3.4 calls the instant itself the
evaluation basis; the type here names its source, which is the part a result has
to carry.

### Artifact result

One per resolved file.

```java
public record ArtifactResult(
        ArtifactSubject subject,
        Outcome outcome,
        IndeterminateReason reason,        // null unless outcome is INDETERMINATE
        PolicyRuleRef matchedRule,         // null when NOT_CONFIGURED
        List<ClaimResult> claims,          // all of them, contributing or not
        Instant verificationTime,
        CacheInfo cache) { }               // null when computed fresh

public enum Outcome {
    SATISFIED, UNSATISFIED, FAILED, NO_CLAIM, INDETERMINATE, NOT_CONFIGURED
}

public record PolicyRuleRef(String pattern, String location) { }

public record CacheInfo(Instant storedAt, Duration age, Outcome cachedOutcome) { }
```

`PolicyRuleRef.location` carries where the rule came from in the policy — file
and node path — so a surprising verdict can be traced to the line that caused
it.

### Run result

One per verification run.

```java
public record VerificationRun(
        PolicyRef policy,
        Coverage coverage,
        EnforcementMode enforcementMode,
        List<ArtifactResult> artifacts,
        Map<Outcome, Integer> counts) { }

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
1. any claim FAILED                         -> FAILED
2. no requirement applies                   -> NOT_CONFIGURED
3. claims with UNSUPPORTED_ALGORITHM are set aside;
   if a requirement demands that claim kind -> INDETERMINATE(UNSUPPORTED_ALGORITHM)
4. requirements met, claim-set mode honoured -> SATISFIED
5. otherwise, in order:
   ALL_CLAIMS and a verified claim unaccepted -> UNSATISFIED
   any remaining INDETERMINATE claim          -> INDETERMINATE(that reason)
   any verified claim                         -> UNSATISFIED
   claims set aside in step 3                 -> INDETERMINATE(UNSUPPORTED_ALGORITHM)
   nothing found                              -> NO_CLAIM
```

```java
public enum ClaimSetMode { ALL_CLAIMS, ANY_CLAIM }
```

`ClaimSetMode` replaces `ListedEvidencePolicy`; `ALL_CLAIMS` stays the default,
matching RPMv6 (§7).

Requirement evaluation itself — what a requirement is, how roles scope it — is
ADR-006. `OutcomeRollup` depends only on a predicate interface, so the two can
be built and tested independently:

```java
public interface RequirementEvaluator {
    EvaluationResult evaluate(ArtifactSubject subject, List<ClaimResult> verifiedClaims);
}
```

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

`SignatureEvidenceAdapter` keeps its tool-selection behaviour — first tool that
reaches a verdict wins, transient reasons trigger a key fetch and retry — but
`EvidenceProvider.verify()` returns `List<ClaimResult>` rather than
`List<EvidenceResult>`. `EvidenceResult` and `MatchedEvidence` are absorbed:
proven credentials and provider name live on `ClaimResult`, and the
matched-versus-unmatched split becomes a property of requirement evaluation
rather than of the result shape.

### Serialization

Results are serialized with Jackson to JSON for the cache (§3.7) and as the
input to VSA emission (§6). Rules: field names are stable and explicit, enums
serialize as their names, `Instant` as ISO-8601 UTC, `Path` as a string, and
`DigestSet` as a plain object. Serialization is round-trip tested, because the
cache reads back what it wrote.

## Consequences

**Removed:** `TrustVerdict`, `Verdict`, `TrustResult`, `EvidenceResult`,
`MatchedEvidence`, `ArtifactIdentity` (interface), `MavenArtifactIdentity`
(becomes a mapping function to `ArtifactSubject`), `ListedEvidencePolicy`.

**Renamed:** `VerificationUnit` → `Claim`, `OpenPgpVerificationUnit` →
`OpenPgpClaim`, `SigstoreVerificationUnit` → `SigstoreClaim`.

**Affected beyond the trust path:** `ReportVerdict`, `FileSignatureReport` and
`SignatureVerificationReport` render CLI signature verification, which also
uses `Verdict`. They move to `ClaimOutcome`, so `sigmund verify-signature`
reports "indeterminate: key unavailable" where it said "no key".

**Behaviour changes users would notice:**

- A hybrid `.asc` verified without Sequoia is `SATISFIED` on the strength of its
  classic signature, where today the unsupported PQC block leaves it
  `UNTRUSTED` under `listed-evidence: all`.
- An unreachable keyserver yields `INDETERMINATE(KEY_UNAVAILABLE)` rather than
  `UNTRUSTED`, which is what makes the cache downgrade of §3.7 meaningful.
- A corrupt Sigstore bundle no longer looks like a failed signature.

**Ordering.** This ADR is implemented by roadmap phase P1 and blocks P2
(requirements and roles), P4 (cache, which stores these types) and P8 (VSA,
which serializes them).

**Not decided here:** requirement and policy schema, attester-role assertion
and mismatch handling, per-outcome enforcement, what replaces
`signature-optional` — all ADR-006. Enforcement reads outcomes; it does not
change how they are derived.
