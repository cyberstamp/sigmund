# ADR-010: Evidence Without Claims

## Status

Proposed. Amends [ADR-005](005-verification-result-model.md): adds an `IndeterminateReason`, a
component of `ArtifactResult`, and a file-level use of the reasons.

## Context

A signature file or bundle resolved for an artifact can yield no claim, in two ways. It can fail
to be read: a permission it lacks, a file removed after resolution, an I/O error. Sigmund threw,
so one such file ended `verify` for every artifact of the build with "Verification failed", and
`dependency-signers` reported the artifact `TOOL_UNAVAILABLE`, blaming a tool that was never
asked. Or it can be read and hold no signature: an empty `.asc`, or one without an armored block,
such as an error page saved under the signature's name. Sigmund read that as no evidence at all,
`NO_CLAIM`, so a rule tolerating unsigned modules let a damaged signature file through unseen,
while the same garbage in a Sigstore bundle was a malformed claim.

ADR-005's model has no place for either. A `ClaimResult` stands for a claim extracted from
evidence, and there is none; an unread file has no digest either, which an `EvidenceRef` must
carry. No reason of ADR-005's describes a file that could not be read: `EVIDENCE_MALFORMED` says
the bytes are bad and will stay bad, `DISCOVERY_UNAVAILABLE` says a network source could not be
queried, and §3.5 of the design direction holds that a delivered Sigstore bundle cannot be
transiently `INDETERMINATE`.

## Decision

A file that yields no claim is recorded on the artifact's result, beside its claims and not
among them, with the reason it yielded none:

```java
public record EvidenceWithoutClaims(Path file, String source, IndeterminateReason reason,
        DigestSet digest, String message) { }

public record ArtifactResult(..., List<ClaimResult> claims,
        List<EvidenceWithoutClaims> evidenceWithoutClaims, Instant verifiedAt) { }
```

The reason is one of two:

- `EVIDENCE_UNREADABLE`, a new transient reason: the file could not be read, and no digest is
  recorded.
- `EVIDENCE_MALFORMED`: the bytes were read, and their digest recorded, but hold no signature
  the file's format recognises. A file that held some signature, however damaged, still yields a
  claim, which is `EVIDENCE_MALFORMED` itself; so the reason now applies to a claim and to a
  file alike, meaning the same thing.

The run goes on: the artifact's other files and every other artifact are verified. The roll-up
counts each such file as an unresolved claim, with its reason when no claim's own reason comes
first. An artifact whose only evidence yielded no claim is `INDETERMINATE`, never `NO_CLAIM`,
which is kept for no evidence found; one whose claims meet its rule is `INDETERMINATE` under
`extra-claims: reject`, since the file may hold a claim from a signer the rule does not accept,
and `SATISFIED` when any claim will do.

## Alternatives

- **A placeholder `ClaimResult` standing for the file.** It would flow through the roll-up and
  the reports unchanged, but needs an `EvidenceRef` without a digest for an unread file and a
  claim kind taken from the file name alone, and calls something a claim that holds none.
  Rejected.
- **`DISCOVERY_UNAVAILABLE` for an unread file.** Transient, and unused so far, but defined as
  network discovery, and using it would blur a source that could not be asked with a file that
  was found. Rejected.
- **`EVIDENCE_MALFORMED` for an unread file.** Permanent: it would tell an operator the bytes are
  bad when none were read, and a later run that reads the file would contradict it. Rejected.
- **Keep `NO_CLAIM` for a file holding no signature.** It treats found evidence as absent, lets a
  rule tolerating unsigned modules pass a damaged file unseen, and makes the OpenPGP and
  Sigstore formats disagree on the same garbage. Rejected; an attacker gains nothing from the
  change either way, since deleting the file yields `NO_CLAIM`.
- **Keep ending the run on an unread file.** One bad file among hundreds of dependencies hides
  every other result. Rejected.

## Consequences

- A file that yields no claim is never `FAILED` and never `NO_CLAIM`, and blocks or warns as the
  matched rule's `on-indeterminate` says. A repository serving empty `.asc` files for unsigned
  artifacts makes them `INDETERMINATE`; such an artifact is tolerated with `on-indeterminate`,
  not `on-no-claim`.
- Every report of an `ArtifactResult` has to show `evidenceWithoutClaims`, since the file is what
  an operator has to fix; `verify` shows it at every detail level.
- Direct signature verification (`verify-signature`) is handed a single file and still reports an
  unreadable one as an error; a caller of `Sigmund.verify` that checks many files catches
  `UnreadableEvidenceException`, as `dependency-signers` does, and reads a file with no claims
  from its empty report.
- One more reason for reports and docs to name.
