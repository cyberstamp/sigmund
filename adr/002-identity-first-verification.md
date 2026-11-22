# ADR-002: Identity-First Verification with Extensible Signing SPI

## Status

Accepted. Replaces the SignatureTool SPI and facade design of ADR-001, since removed.
Amended by [ADR-005](005-verification-result-model.md): the verification result model.
Amended by [ADR-006](006-identity-and-credential-model.md): the credential model.
Amended by [ADR-007](007-policy-schema-and-enforcement.md): the policy schema and enforcement.

## Context

Sigmund began as two concrete runners, `GpgRunner` and `SqRunner`, with no shared interface.
Orchestration, the CLI and the Maven plugin referenced them directly, and identity matching,
policy and signature checking were interleaved in a Maven goal.

Yet the configuration already said "this artifact should be from Alice", not "verify the GPG
signature": signatures were evidence for a question about identity. The code did not reflect
that.

Two forces shaped the structure:

- **OpenPGP is splitting.** GnuPG follows LibrePGP, whose v5 keys are incompatible with the v6
  keys of RFC 9580 that Sequoia implements. v4 is the common ground; v5 and v6 are not one
  format that every tool handles.
- **Signing is not only OpenPGP.** Sigstore is keyless and OIDC-based, Maven Central accepts it
  alongside OpenPGP, and other systems — JAR signing, OCI signing — may follow.

## Decision

1. **Identity first.** The question Sigmund answers is "is this artifact from someone I
   trust?". A signature is evidence for the answer, not the answer.

2. **Two layers.** Identity verification (`TrustVerifier`, `EvidenceProvider`,
   `SignerIdentity`, the policy) sits above signature operations (`SignatureTool`,
   `SignatureFormat`, `Claim`, `VerifyResult`). One `SignatureEvidenceAdapter` per format
   bridges them. `EvidenceProvider` stays separate from `SignatureTool`, so evidence that is not
   a signature — a provenance attestation — can be added without pretending to be one.

3. **A format owns its files; formats are curated, tools are pluggable.** A `SignatureFormat`
   detects its files, parses them into claims and combines signatures. `Claim` and
   `VerifyResult` are sealed in core: a new format brings new packet structures, verification
   semantics and credential types, which warrant core review. A new tool for an existing format
   is added through a `SignatureToolFactory`, discovered by `ServiceLoader`, or `addTool()`.

4. **Credential types are named after the key version** — `pgp4`, `pgp6` — not after a tool or
   an algorithm family, because LibrePGP and RFC 9580 have diverged and a tool's support can
   change. A LibrePGP v5 type, if ever needed, is a type of its own.

5. **A credential's type follows the packet the tool verified.** A signature can never claim
   its own type.

6. **Operations only some tools support are capability interfaces** — `KeyGenerator`,
   `CertExporter`, `SecretKeyExporter`, `KeyImporter`, `SignerIdentityResolver` — rather than
   methods every tool must stub.

7. **Errors.** An examined signature's outcome is a result, never an exception. A failure that
   kept verification from being attempted is an unchecked `SigmundException`
   (`ToolExecutionException` for a tool). A configuration error fails when the file is loaded or
   the tools are built (`PolicyConfigException`), not when an artifact is assessed.

8. **A facade with one session per use case.** `Sigmund` builds the tools; `Signer` signs and
   `TrustVerifier` assesses artifacts against a policy; direct signature verification is on
   `Sigmund` itself.

9. **Tools are configured when they are built.** Each tool's `tools.<name>` settings name its
   own keys; the requested credential types choose which of those keys sign. The asserted
   signer (`signing.signer`) never selects a key: a tool may use it only to refuse early, and
   core checks after signing that every signature proves it.

10. **One `sigmund.yaml`, parsed in core, never merged.** The first file found wins. Finding an
    artifact's evidence is the caller's job — a Maven goal, the CLI — not core's.

## Alternatives

- **Routing the signer's credentials to tools.** First adopted: the signer's fingerprints
  chose which tool signed with which key. Replaced by decision 9, because a tool could sign with
  only one key, and profiles chose tools rather than keys.
- **One "OpenPGP" credential type, or types named after tools or algorithm families.** Rejected
  by decision 4: one type would hide that a v6 key cannot be checked by GnuPG, and a tool name
  says nothing about the key.
- **Open, unsealed formats.** Rejected by decision 3: a plug-in format would bring its own
  verification semantics and credentials into the policy without review.
- **Merging configuration files.** Rejected by decision 10: what a build accepts would depend on
  files outside the project, and a merged policy would be hard to read as a whole.

## Consequences

- Adding a tool for an existing format needs no core change; adding a format does.
- The same claim gives the same outcome whichever tool answers, which makes backend agreement a
  requirement the tests enforce rather than a property of one tool.
- Signing and verification share the identity model: `signing.signer` is checked with the same
  matching verification uses.
- GnuPG's v5 keys are not supported until a type exists for them.
