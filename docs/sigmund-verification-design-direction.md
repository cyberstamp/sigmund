# Sigmund: Conceptual Design Direction for Artifact Verification

Status: discussion document. Not a spec, not an ADR. Intended as shared context
for conversations with the Maven and Gradle maintainers.

Sections 1–6 are the substance of those conversations. Sections 7–10 are
background: scope rationale, sequencing, and open questions.

This document is revised in place as the design evolves. Implementation order
and progress are tracked in the
[verification roadmap](sigmund-verification-roadmap.md); decisions that settle
points left open here are recorded as ADRs under `adr/`.

---

## 1. Core principle: verify at resolution time

The interception point determines what evidence is available and what the
verification can prevent.

| Point | Evidence available | Can it prevent execution? |
|---|---|---|
| Publish (registry-side) | Full artifact | Only for that registry's own publishing flow |
| **Resolution / fetch** | Coordinate, bytes, claims travelling alongside. No resolved graph yet. | **Yes** |
| Post-build / SBOM | Full resolved graph | No — build plugins and extensions have already executed |
| Deploy / admission | Final image | Yes, but far downstream; cosign's territory |

Build-time code execution is what makes resolution-time the load-bearing
position: a Maven plugin runs *during* the build, so post-hoc verification
cannot stop the attack class that matters most.

**Consequence for SBOMs:** the SBOM is the *record* of verification, not its
input. Verification happens at fetch; the SBOM and any VSA capture what was
verified. This inverts the intuitive direction and resolves the apparent
conflict between "SBOM-driven verification" and "verify on pull."

### 1.1 Threat model

Stated explicitly, because the value of the design depends on it and
overclaiming here is easy.

**Defended against:**

- Repository or mirror compromise — substituted bytes carry no valid signature
  from the expected identity.
- Publisher account takeover producing releases under a different key — for
  policies that name key material. A policy naming an attested identity
  (subject plus issuer) inherits the issuer's account security instead: whoever
  controls the OIDC account, or the email address at the directory, can bind a
  new key to that identity. Sigstore keyless has this property by construction;
  the guarantee therefore depends on the credential kind in use.
- Typosquat and dependency-confusion packages, to the extent policy is
  coordinate-scoped.
- Silent republication of an existing coordinate with different content.

The common shape: the attacker cannot produce the expected identity's
signature. That is the boundary.

**Not defended against:**

- A legitimate publisher shipping a malicious version under their real key.
  Trust is in the identity, not the code. This is the xz shape and no signature
  scheme catches it.
- Compromise of the publisher's signing key or CI identity.
- Malicious code already trusted at bootstrap time.

**Trust establishment is TOFU.** `generateTrustConfig` snapshots observed state
and treats it as the baseline. This is deliberate, and the same choice Gradle
made — the alternative is a manual key-vetting exercise nobody completes — but
it means the *initial* trust decision is unverified and only *changes* from it
are detected.

**Verification outcomes are stable except for defined events.** A claim is
judged at its evaluation basis (§3.4), so key expiry, superseded or retired
revocation, and trust-root rotation after signing do not change an outcome. A
previously `SATISFIED` result legitimately changes only on hard revocation
(compromise or unspecified reason, §3.8), a policy change, or a verifier change
such as retiring an algorithm — and the result must record which.
Infrastructure unavailability yields `INDETERMINATE`, served from cache where
possible (§3.7), never a different verdict. Any other change between runs is a
defect; identity matching that depends on mutable keyserver data is the main
example. For OpenPGP, the evaluation basis is publisher-asserted, so a leaked
but unrevoked key can backdate signatures — a residual risk stated here rather
than hidden.

Unexplained nondeterminism in CI is a well-known way to get a tool switched
off, so the result model (§3) must carry enough to explain any differing
outcome from the record.

---

## 2. Insertion points and what each can claim

Resolution-time integration in Maven requires a resolver-level hook that does
not exist today. There are three positions, not two, and the near-term work
sits in the middle one.

| Position | Timing | Covers build tooling | Blocking | Needs upstream |
|---|---|---|---|---|
| Plugin goal | after download | no | yes, but skippable | no |
| Core extension | at resolution | yes | listener: awkward; resolver wrapper: yes | no |
| Resolver integration | at resolution | yes | yes | yes |

**Plugin goal** — bound to an early lifecycle phase (`validate`), resolving the
dependency graph itself through the resolver API rather than declaring
`requiresDependencyResolution`. That is deliberate: the annotation fixes
resolution scope at build time, so a single goal could not verify the shipping
graph by default and the test graph on request. Self-resolution makes scope a
runtime parameter, which §3.6 depends on.

Gives up: timing (artifacts are already on disk), coverage (plugin and
extension dependencies resolve before any goal runs), and enforcement position
(a goal can be skipped, reordered, or omitted from a profile). Coverage is the
load-bearing gap — those are the artifacts that execute during the build, which
is the threat the interception-point argument turns on.

**Core extension** — a `build/extensions` or `.mvn/extensions.xml` component
registering a `RepositoryListener` or wrapping the resolver. Runs inside the
build, no fork of Maven, and covers plugin and extension dependencies.
`.mvn/extensions.xml` loads before the build proper, so coverage starts early
enough to matter. A `RepositoryListener` is notification rather than
interception — failing from a callback has messy error-reporting semantics and
may not reliably abort — so real blocking means wrapping the resolver
component.

Maven Resolver 1.9 added an option between the two:
`ArtifactResolverPostProcessor`, the SPI behind the trusted-checksums feature.
It runs after artifacts are resolved and before results are returned to the
caller, and a failure there fails the resolution cleanly. If an extension can contribute one, and plugin
and extension resolution pass through it, it gives interception without
replacing a resolver component. Both conditions need confirming before the
extension commits to a hook.

Two constraints apply whichever hook is used:

- **Re-entrancy.** Evidence sidecars (`.asc`, `.sigstore.json`) and a policy
  artifact (§5.2) are themselves fetched through the resolver, so fetching them
  from inside the hook re-enters it. Evidence and policy resolution must bypass
  verification explicitly rather than recurse.
- **Scope visibility.** A resolution request carries a request context that
  separates plugin from project resolution, but not the dependency scope
  (`compile`, `test`) the goal sees when it builds the graph. The extension can
  reliably tell build tooling from project dependencies; finer per-scope
  enforcement (§3.6) needs the graph.

**Resolver integration** — the upstream conversation. What it adds over an
extension is mostly the difference between opt-in-per-project and default
behaviour, plus clean abort semantics.

Both the plugin and the extension are worth keeping. The best mode of
operation is still an open research question, and having both lets that
question be answered with data rather than argument. The requirement is that
they produce identical results from the same policy.

### 2.1 Coverage is a property of the result

The insertion point changes what an attestation can honestly claim. A
goal-produced result covers the project's declared dependency graph. An
extension-produced result covers everything the resolver touched. Those are
different assurances wearing the same word.

A goal-produced attestation is a claim made by a build whose own tooling was
not verified. Still useful — most real threats are in shipped dependencies —
but a downstream consumer deserves to see which one it is holding.

So the result model carries a coverage scope, and the VSA serializes it:

```
coverage:
  insertion-point: plugin-goal | core-extension | resolver
  scopes-covered: [compile, runtime, test]
  build-tooling-covered: false
  enforcement-mode: enforcing | observe
  artifacts-verified: 412
  artifacts-no-claim: 387
```

Counts matter. "Verified" against a policy where 387 of 412 dependencies
produced `NO_CLAIM` is a very different assurance from full coverage, and
partial coverage will be the normal case for years (§9). A VSA that hides it is
misleading by omission.

Coverage is self-reported and signed: a consumer that trusts the verifier
identity trusts its coverage claim, on the same basis it trusts the verdict.

### 2.2 Gradle asymmetry

Gradle already verifies during resolution. There is no degraded path to design
and no upstream argument to win about *where* — only about *what*: identity
rather than fingerprint, Sigstore, PQC, staleness. Maven needs a new position;
Gradle needs a better primitive in an existing one.

---

## 3. The load-bearing abstraction: the verification result model

Most of the forward-looking value is here, because this is the only part that
is expensive to retrofit.

### 3.1 Evidence and claims

Two terms, and they are not synonyms:

- **Evidence** is the file carrying assertions — the `.asc`, the Sigstore
  bundle, the DSSE envelope.
- **Claim** is a single verifiable assertion extracted from it.

One evidence file can carry several claims. A hybrid `.asc` with classic and
PQC blocks already is that case, and a bundle carrying both a signature and a
provenance predicate will be another. This describes existing pipeline
structure rather than adding any: evidence is parsed into claims, each claim is
routed and verified independently.

The API should use both terms as defined. `EvidenceProvider` locates and parses
evidence. The unit of verification is a claim — the type currently named
`VerificationUnit` should be renamed accordingly, before the SPI is public.
(Check for collision with OIDC/JWT "claims" in the Sigstore dependency chain;
`VerifiableClaim` is the fallback name if `Claim` is ambiguous in context.)

### 3.2 Contents of a result

A result must not be a boolean or a signer string. It has three levels, because
its fields describe three different things: a single assertion, an artifact,
and a verification run.

**Claim result** — one per claim extracted from evidence:

- **Claim kind** — detached OpenPGP signature, Sigstore bundle, DSSE
  attestation.
- **Attester identity and role** — who, and in what capacity (§3.3).
- **Trust root used** — keyring, Fulcio/TUF, or delegated-verifier root.
- **Evidence reference** — the file the claim came from, by digest, and which
  source supplied it (§4).
- **Temporal fields** — claim time and evaluation basis (§3.4).
- **Claim outcome** — verified, `FAILED`, or `INDETERMINATE` with a reason.

**Artifact result** — one per resolved file:

- **Subject** — resolved artifact identity (GAV + classifier/extension) plus
  digest; purl projection available.
- **Matched policy rule** — which rule applied, and its location in the policy.
- **Claim results** — all of them, including claims that did not contribute to
  the outcome.
- **Verification time** (§3.4) and, where the outcome came from the cache, cache
  age (§3.7).
- **Outcome** — §3.5, derived from the claim results as described in §3.2.1.
  `NO_CLAIM` is an artifact outcome, not a claim kind.

**Run result** — one per verification run:

- **Policy reference** — location and digest (§3.7, §5.2).
- **Coverage** — §2.1, including the per-outcome counts.
- **Enforcement mode** — enforcing or observe (§5.4).

**Policy schema follows from it.** Express config as "requirements this target
must satisfy," not "the expected signer for this target." The first form admits
a new requirement type (provenance) without breaking existing configs; the
second does not.

**Rules target GAV, not individual files.** Every file under one GAV — jar,
pom, sources, javadoc, classified variants — is produced by the same module
build and shares its signer, builder and publishing path, so a rule matches
group, artifact and version patterns only. Results stay per file, because
evidence and digests are per file: a sources jar published without a bundle
yields its own `NO_CLAIM` under the same rule. Classifier-scoped rules are
deferred until a concrete case needs them; platform-specific classifiers built
by separate jobs with different builder identities are the likeliest one.

**Digests are algorithm-tagged.** Subject, evidence and policy digests are
recorded as an algorithm-to-value map — the in-toto `DigestSet` shape,
`{"sha256": "…"}` — never as a bare value. SHA-256 is required: it is what
Sigstore bundles, Rekor entries, in-toto Statements and Central's published
checksums already use, and it is recomputable with standard tooling. Faster
alternatives such as BLAKE3 offer no security gain at the same output size and
would have to be computed alongside SHA-256 rather than instead of it.
Additional algorithms can be added without a format change; matching uses any
algorithm both sides share.

### 3.2.1 From claim results to an artifact outcome

The artifact outcome is derived in a fixed order; each step applies only if the
earlier ones did not decide.

1. **Any claim `FAILED` → `FAILED`.** A valid claim alongside a failing one does
   not mask it. This matches RPMv6 (§7), where every signature on a package must
   verify, and it is why `FAILED` cannot be overridden.
2. **Claims no available verifier supports are set aside** — recorded in the
   result, excluded from evaluation. This happens before requirements are
   evaluated, because evaluation only ever sees claims that verified. It is the
   graceful degradation that makes hybrid `.asc` work: a verifier without PQC
   support evaluates the classic block exactly as an older RPM system does. If
   policy explicitly requires a claim of that kind, the requirement cannot be met
   and the outcome is `INDETERMINATE` with `unsupported-algorithm`.
3. **No requirement applies → `NOT_CONFIGURED`**, with the set-aside claims still
   recorded.
4. **Requirements met → `SATISFIED`**, subject to the claim-set mode. Under the
   default *all-claims* mode, every remaining claim must also be verified and
   accepted by policy. Under the lenient *any-claim* mode, remaining claims are
   recorded and ignored once requirements are met.
5. **Otherwise**, in order:
   - under all-claims mode, a verified claim that policy does not accept →
     `UNSATISFIED`;
   - any remaining `INDETERMINATE` claim → `INDETERMINATE` with that claim's
     reason, because the verdict cannot be decided without it;
   - any verified claim → `UNSATISFIED`;
   - claims set aside in step 2 → `INDETERMINATE` with `unsupported-algorithm`;
   - nothing found → `NO_CLAIM`.

Setting aside unsupported claims cannot make an untrusted artifact pass:
requirements are still evaluated only over claims that verified. An attacker who
appends an unverifiable block gains nothing.

### 3.3 Attester role

Role is not derivable from identity, but the slot has to be filled from
somewhere. Three sources:

- **Structurally implied by claim kind.** A Fulcio cert with a GitHub Actions
  workflow identity is structurally a builder claim; the OIDC issuer and SAN
  shape say so. A SLSA provenance predicate names its builder explicitly. In
  practice the issuer carries this: a trusted issuer declares the default role
  for identities it asserts, so derivation is configured rather than hardcoded
  per backend.
- **Asserted by policy.** Necessary where structure cannot distinguish — an
  OpenPGP key could belong to a publisher, a distro, or an internal reviewer,
  and nothing in the signature says which.
- **Carried in the evidence.** A VSA's `verifier.id` identifies a third-party
  verifier by construction.

The rule: **structure proposes, policy disposes.** A role is derived where the
claim shape permits, policy may assert one, and a mismatch is a config error
rather than a silent override — silently accepting a builder claim where a
publisher was required is exactly the false-green this dimension exists to
prevent.

Roles: `publisher`, `builder`, `registry`, `third-party-verifier`, and
`unknown` for a bare OpenPGP signature with no policy assertion. `unknown` is
common today and must be visible in the result rather than defaulted to
`publisher`.

Requirements can then be role-scoped — "a publisher claim AND a builder claim,"
or "a publisher claim is sufficient." Without role-scoped requirements the
dimension is decorative.

### 3.4 Time

Three clocks, all needed in the result:

- **Claim time** — when the signature or attestation was made.
- **Verification time** — when Sigmund evaluated it. Becomes `timeVerified` in
  a VSA and drives cache freshness.
- **Evaluation basis** — the instant against which validity was judged.

The basis is **per claim kind**, not global:

- *Sigstore*: the signed entry timestamp carried in the bundle. Log-asserted,
  not publisher-controlled. `sigstore-java` applies it when checking Fulcio
  certificate validity — inherited from the library rather than implemented
  here. This is what makes short-lived Fulcio certs verifiable long after
  issuance.
- *OpenPGP*: the signature creation subpacket. Publisher-controlled, therefore
  weaker evidence — a compromised key can backdate. Without a timestamp
  authority there is no independent check, and the result records which basis
  was used.

### 3.5 Outcomes

The load-bearing split is between an attack signal and an infrastructure
problem. These must never collapse into one state.

| Outcome | Meaning | Who acts |
|---|---|---|
| `SATISFIED` | Requirements met | nobody |
| `UNSATISFIED` | Claim valid, identity or role does not match policy | policy owner |
| `FAILED` | Cryptographic verification failed | security — the attack signal |
| `NO_CLAIM` | No evidence found | coverage decision, not an incident |
| `INDETERMINATE` | Evidence present, verification could not complete | infrastructure |
| `NOT_CONFIGURED` | No requirement applies | nobody |

`NO_CLAIM` replaces `UNSIGNED`, which stops being accurate once provenance
exists: an artifact can be unsigned but attested, or signed but unattested.

`INDETERMINATE` carries a machine-readable reason, because operators triage
these differently:

- `key-unavailable` — OpenPGP only; signer's key absent locally and keyserver
  unreachable or lacking it. Transient.
- `trust-root-unavailable` — Sigstore; TUF metadata missing or too stale.
  Transient.
- `discovery-unavailable` — evidence might exist but the source could not be
  queried. Transient; only arises for network-backed discovery.
- `tool-unavailable` — the verification tool could not be run, or broke while
  running. Transient. A tool that throws is one tool's failure, not the run's:
  the remaining tools still get their turn at the claim, and the exception is
  logged so the cause survives the reason code.
- `unsupported-algorithm` — permanent.
- `evidence-malformed` — permanent.

Lumping transient and permanent reasons together makes a permanently
unverifiable artifact look like a flaky network forever.

Note a real asymmetry: **Sigstore verification of a delivered bundle is fully
local and cannot produce a transient `INDETERMINATE`.** Transient states belong
to OpenPGP key resolution and to network-backed discovery. A build whose
dependencies are all Sigstore-signed with sidecar bundles verifies
deterministically offline.

### 3.6 Enforcement

Each non-`SATISFIED` outcome gets its own setting rather than a single
strictness dial. `FAILED` is non-overridable by default — a signature that does
not verify is not a coverage question.

Scope matters. `compile` and `runtime` ship; `test` does not; plugin and
extension dependencies execute during the build and deserve the strictest
treatment, which is an argument the resolver-integration case can use directly.
Scope granularity depends on the insertion point (§2): the goal knows `compile`,
`runtime` and `test`; the extension reliably knows only build tooling versus
project.

Default posture for `INDETERMINATE` with no cache entry: fail for
plugin/extension scope, warn elsewhere, with the bootstrap command populating
the cache so a normal first run does not hit it. This is a product judgment
about adoption, not a security one, and is worth revisiting with maintainer
input.

### 3.7 Caching

A cached prior result **downgrades `INDETERMINATE` to its cached outcome**,
with cache age recorded in the result. Offline builds then work if verification
has happened before, and fail informatively if it has not — instead of the tool
silently deciding that unreachable means fine.

That makes the cache part of the trust model rather than an optimization:

- Keyed by artifact digest **and** policy digest, so a policy change
  invalidates. The policy digest is the SHA-256 of the policy file's raw
  content, computed before parsing — not of the parsed model in memory. When
  policy is resolved by GAV (§5.2) that file is the resolved artifact, so the
  policy digest equals the artifact's own digest. Raw content rather than a
  canonical form, because a consumer checking a VSA's policy digest (§6) must be
  able to recompute it with `sha256sum` rather than by reimplementing Sigmund's
  parser and normalization. The cost is that a formatting-only edit changes the
  digest and triggers one re-verification. The policy must therefore be
  self-contained: anything that affects the verdict lives in the file, never in
  a file it references. With no policy file (zero-config), the digest is absent
  and the result says so, rather than digesting built-in defaults.
- Sigmund's own base configuration — the shipped defaults the project policy is
  layered over — is digested separately and recorded alongside. Two digests
  rather than one over the merged result, so each stays recomputable from a file
  and a changed default is visible instead of hidden inside the policy digest.
- Stores the full result, not a boolean.
- TTL is a policy setting.
- `-o` is cache-only, never fail-open.

Key freshness is a separate TTL from result freshness, because key state is
what actually goes stale (§3.8).

### 3.8 Revocation

Genuinely unsolved for OpenPGP, and worth saying so rather than implying
coverage.

Revocation is a signature packet on the key, distributed via keyservers.
Nothing pushes it; a build verifying against a locally cached key never learns
the key was revoked, so a compromised publisher key keeps passing indefinitely.
Some refresh cadence is required for revocation to mean anything.

Retroactivity should honour the reason code: **compromise invalidates prior
signatures; superseded or retired does not.** Treating all revocation as
retroactive breaks every historical artifact signed by anyone who ever rotated
a key, which is most careful publishers.

A revocation with no reason code, or with "no reason specified", is treated as
hard — retroactive — as RFC 9580 requires. Many real revocations carry no
reason, so retroactive invalidation is more common in practice than announced
compromises alone would suggest. The result records the reason code that was
applied, so a publisher whose rotation invalidated history can see why and
reissue the revocation with a soft reason.

Key expiry is not revocation. A signature whose creation time falls within the
key's validity period stays valid after the key expires; a signature created
after expiry is `FAILED`.

Identity matching must not depend on unattested key data. A user ID is
self-certified — anyone can put any address on a key — so a UID proves an
identity only when the source that served it vouched for the binding.
keys.openpgp.org publishes a UID only after the address owner confirms it, and
is Sigmund's default keyserver, so the default fetch path does obtain verified
bindings; what matters is recording *which* source supplied the key and
accepting identity assertions only from issuers the policy trusts.

Directory bindings are current state, not history. keys.openpgp.org associates
an address with a single key, and verifying it for a new key removes it from the
previous one, which is still served without the identity. So rotation unbinds
the signatures the old key made: a verifier that cached the binding keeps it,
a first-time verifier does not. Key material stays the backbone for third-party
dependency verification — stable, offline, historically complete — and attested
identities are opt-in. Whole-key revocations are distributed for keys with no
verified user ID, so revocation checking is unaffected.

Sigstore inverts this. Short-lived certs mean there is nothing to revoke; the
question is whether the bundle verifies and whether policy still trusts the
identity. The remaining operational dependency is TUF trust-root rotation,
inherited from `sigstore-java` — the only local decision is how stale a trust
root may be before `trust-root-unavailable` applies.

---

## 4. Evidence discovery

**Discovery is network-bound; verification is not.** This is what keeps
resolution-path latency tractable. Sigstore bundles verify locally — cert chain
to the Fulcio root, signature over the artifact, and the Rekor inclusion proof
and signed entry timestamp all carried inside the bundle. The expensive part is
finding evidence, and sidecar delivery makes that free.

Three cases, of which only one is open:

**Case 1 — cooperating publisher, sidecar.** A `.sigstore.json` or DSSE
envelope published alongside the artifact, as `.asc` is today. Works now, needs
nothing new, is what Sigmund already produces on the signing side. Discovery is
a filename convention. Limitation: publisher opt-in, and only from the point
they start.

**Case 2 — digest lookup in a transparency log.** Search Rekor by artifact
digest to *locate* a bundle that was not delivered alongside the artifact.
Verification of what is found is still local. The network cost is discovery
only — one lookup per artifact with no local hit — which makes this the only
source with a per-artifact network profile. Opt-in `ProvenanceSource`, not a
default.

**Case 3 — third-party attestations about artifacts already published.**
Someone other than the publisher asserting something about
`com.example:lib:1.0` — a scanner, an internal review, a distro. There is
nowhere to put it: sidecars cannot be published next to artifacts you do not
own, and Central is immutable. This is the genuinely unsolved case and needs
either a repository-layout convention or an out-of-band store. The realistic
first answer is an org-internal store; whether there is appetite for an
attestation-path convention in the Maven repository layout, served by Central,
is a concrete question for the Maven maintainers and Central's operators.

Implication: an ordered `ProvenanceSource` SPI with results **merged rather
than first-match**, since multiple attesters about one artifact is normal
rather than a conflict. The result records which source supplied each piece of
evidence — a claim from an internal store carries different weight from one
found in a public log, and policy may reasonably distinguish them.

---

## 5. Policy: distribution and control

### 5.1 One authoritative config

One policy per project, resolved at the reactor root — the directory containing
the aggregator, or `.mvn/` alongside it. Submodule builds resolve upward.

Per-module policy is rejected: the effective policy would depend on which
module is being built, so the same dependency could reach different verdicts
from the root and from a submodule. That produces "passes locally, fails in CI"
and it breaks delegation, since a VSA covering a reactor build could not state
what policy it applied. If per-module scoping is ever needed, the sane form is
rules keyed by module coordinate *within* the single file.

Default lookup locations apply unless overridden by a config option or command
line argument. Zero-config keeps working, which matters for the
`dependency-signers` on-ramp where someone pastes one command into a project
they do not own.

### 5.2 Policy as a resolvable artifact

The config's location is a parameter, resolving either to a local file or to a
policy artifact GAV. That gives org-wide distribution — point every project at
the same artifact via a shared parent POM property or CI setting — with no
merge semantics to define.

Policy as an artifact in a Maven repository has a useful recursive property: it
can be signed and verified by the same machinery. The base case is a small local
trust anchor naming the identity permitted to publish policy. Small enough to
review once, and the one thing that cannot be delegated.

Resolving the policy artifact is itself a resolution the extension intercepts
(§2). It is verified against the local trust anchor only — never against the
policy it is about to load.

The policy artifact must be pinned to an exact version. A policy that changes
underneath the build is a supply-chain problem in its own right, and a floating
version makes the policy digest recorded in a VSA meaningless.

### 5.3 What arguments may and may not do

**Arguments may configure how verification is performed. They may not
configure what is required.**

Configurable by argument: keyservers to fetch key material from, active
discovery sources, timeouts, offline behaviour, config location.

Policy-file only: trust requirements, accepted identities, trusted issuers,
roles, enforcement settings.

**Fetching a key and trusting a source to say who someone is are different
grants**, and they split on this line. Fetching by fingerprint cannot change
acceptance, so keyservers stay arguments. Deciding that a server's word binds an
address to a key does change acceptance — adding a non-verifying keyserver would
otherwise turn unverified user IDs into matches — so the issuer list is
policy-only.

The line holds because widening discovery can never make an untrusted artifact
pass. Consulting an extra keyserver can only resolve a `NO_CLAIM` or
`key-unavailable` into an actual verdict — possibly `FAILED`. It changes what
can be *seen*, not what is *accepted*. Anything touching requirements or
enforcement changes the verdict itself and belongs under review.

This is exactly what the policy-authoring loop needs: run with wide keyserver
and discovery settings, see what claims exist, decide what the policy should
say, propose the change as a diff.

### 5.4 Observe mode

A run mode, not a policy setting: verify everything against the policy, report
every result, exit zero regardless. Two uses — seeing the blast radius before
enforcing, and iterating on policy without a red build each time.

Observe mode changes whether the build fails; it does not change whether
verification happened. A VSA's `verificationResult` is a claim about the
artifact against the policy, not about the build's exit code, so an
observe-mode VSA is honest as long as the result reflects the actual outcome —
including `FAILED` where something failed, with the build still green.

Therefore: **VSAs always carry the policy reference, and observe mode neither
suppresses nor degrades the attestation.** Enforcement mode is recorded
alongside coverage (§2.1), which is what a consumer needs to avoid inferring
"this build was gated" from the mere existence of a VSA. Emission remains off
by default in observe mode as an ergonomics choice — someone exploring with
wide discovery settings is usually not producing a record they want to keep.

---

## 6. Attestation lifecycle: inbound and outbound

Two distinct artifacts, worth separating early because they have different
consumers and different distribution problems.

- **Inbound** — "I verified my dependencies." Lives in the build record;
  attached to the container image where one exists. Consumed by release gates
  and auditors.
- **Outbound** — "this release was built from verified inputs." Ships with the
  release. Consumed by downstream builds.

**Realistic consumers today, ranked:**

1. **Your own downstream build.** The delegation and caching case SLSA
   explicitly designed for. A hermetic productization build that cannot reach
   keyservers can carry a signed VSA instead of re-verifying hundreds of
   dependencies. This is the loop with actual return, and it does not wait on
   ecosystem adoption.
2. **A release gate you write.** Verify DSSE signature, check `verifier.id`
   against an allowlist, policy digest against expected, result, coverage,
   freshness.
3. **Admission controllers** — via OCI only.
4. **Compliance evidence** — CRA technical documentation and similar. Human and
   GRC consumption.

**Acceptance policy is not just an allowlist of verifier identities.** A
consumer may require a minimum coverage scope: "accept VSAs from our platform
team, but only where build tooling was covered." That needs the coverage fields
of §2.1 to exist in order to be expressible.

**Prerequisite that sinks most VSA plans:** the VSA must be signed, and the
consumer needs a trust root for Sigmund's *verifier* identity — a distinct
trust root from the artifact-signer one, and they must not be confused. A team
that trusts `alice@corp` to sign `com.corp:*` does not thereby trust her to
vouch for third-party artifacts. Inside one organization this is easy (Sigstore
keyless with CI's OIDC identity). Across organizations it is chicken-and-egg.
Plan VSA as an intra-org format.

**Loop guard:** a VSA is terminal evidence and is never itself resolved via
another VSA. Cap delegation depth at one hop.

**Staleness:** record the policy digest in the VSA and reject receipts whose
digest does not match the current policy, unless foreign policy is explicitly
accepted. Without this, VSAs become a way to smuggle in old decisions.

---

## 7. Background: scope decision

**Target: artifacts served from Maven repositories, verified in the dependency
resolution path of the build tools that consume them — natively integrated
into Maven and Gradle first.**

"Maven" names two different things, and the design keeps them apart:

- **The Maven repository** — a format and an ecosystem: the layout, GAV plus
  classifier and extension as coordinates, per-file checksums and sidecar
  evidence such as `.asc`, and the repositories that serve it, Central first
  among them. It defines *what* is verified.
- **The Maven build tool** — one consumer of that format among several. Gradle,
  sbt and Coursier, Bazel's `rules_jvm_external`, Mill and JBang resolve from
  the same repositories with the same conventions. A build tool defines *where*
  verification is inserted (§2).

The target is scoped by the repository format, not by language and not by
build tool. "JVM artifacts" would be too narrow — Maven repositories also carry
Android AARs, Kotlin multiplatform and Scala.js artifacts, WebJars and native
classifiers, all of which verify the same way — and it says nothing about the
layout, coordinates and evidence conventions that verification actually relies
on.

The durable asset is the trust model — policy format, keyring and identity
handling, attestation discovery, result model — and it depends only on the
repository format. Core may use repository concepts (coordinates, layout,
sidecar conventions) freely and build-tool types (Maven plugin API, project
model, resolver session, Gradle API) never. Each build tool gets a thin
integration over the core library and API rather than an independent
implementation.

| Candidate | Verdict | Reason |
|---|---|---|
| Maven repositories | Genuine gap | Central mandates signatures on publish; effectively no consumer verifies them. Mandatory production, near-zero consumption. |
| Maven (build tool) | Nothing in the resolution path | No resolution-time verification; needs a new insertion point (§2). |
| Gradle (build tool) | Aging, not absent | Verification exists (`verification-metadata.xml`, PGP + checksums). Fingerprint trust rather than identity, no Sigstore path, no PQC, metadata files rot because staleness isn't detectable. Fixing this is an upstream conversation, not a competing plugin. |
| Other Maven-repository consumers | Not yet assessed | Same artifacts and evidence; integration follows once the core API is stable. |
| RPM | No gap, useful precedent | See below. |
| npm / PyPI | Recently modernized | Registry-integrated answers already shipped (`npm audit signatures`, PEP 740 attestations). An external second-best here is force-fit. |
| Go | Different model entirely | No publisher signature; checksum-database consistency instead. Not the same problem. |

**RPM as precedent.** `rpm`/`dnf` verify at install time, the correct
interception point, so there is no gap to fill. The value is that RHEL 10.1
independently arrived at two constructions Sigmund also uses:

- RPMv6 allows multiple signatures per package and requires *all* of them to
  verify for the package to be trusted — matching Sigmund's default
  verification mode, and putting `--lenient` in a clearer light as the
  deliberate exception. RPM enforces it at the format level; for Sigmund it is
  the default claim-set mode, with the lenient setting as a documented escape.
- Red Hat's hybrid packages carry a v6 ML-DSA-87+Ed448 signature alongside a v4
  RSA signature; RPM 6 systems verify both, older systems validate only the
  classic signature. The same construction in a different container — two
  signatures over one artifact, under two keys, classic retained for
  compatibility — arrived at independently.

  The containers differ, and so does how cleanly each degrades. RPM gives each
  signature its own header tag: `RPMSIGTAG_RSAHEADER` and `DSAHEADER` in v4,
  the algorithm-agnostic `RPMSIGTAG_OPENPGPHEADER` added in v6. An older RPM
  reads the tags it knows and ignores the rest, so degradation is a designed-in
  format feature and ordering means nothing. Sigmund concatenates two armored
  blocks into one detached `.asc`, classic first so Central and existing tooling
  succeed — degradation by convention rather than by design, and imperfect:
  GnuPG verifies the classic block but returns exit code 2 on the unknown v6
  packet. Verification support is asymmetric too: RPM 6 checks both signatures
  through its own OpenPGP backend, while Sigmund needs Sequoia `sq` for the PQC
  block because Bouncy Castle does not yet recognize the RFC 9980 algorithm IDs.

Red Hat signs its own packages this way today; publisher-side PQC signing
tooling remains a technology preview.

### Cross-ecosystem

Treated as a **constraint on the output, not a delivery scope**. **purl is the
cross-ecosystem identity; the internal coordinate is the repository's own.**

An abstract internal coordinate would be the wrong generalization. What
ecosystems share is namespace, name and version plus *some* set of variant
qualifiers, and those qualifiers differ: Maven has classifier and extension,
PyPI has wheel tags and sdist-versus-wheel, RPM and Debian have architecture
(and RPM epoch and release), while npm, Go and NuGet have no file-level variant
at all. A type covering all of them degenerates into a qualifier map — which is
exactly what purl is, and why purl belongs on output rather than in matching
(§8).

So the internal coordinate is Maven's, named in purl's vocabulary (`namespace`,
`name`, `version`) so the projection is a mapping rather than a translation.
What carries across ecosystems is the purl emitted in results, VSAs and
SBOM-facing output, plus a first-class attester role (§3.3), which is the
dimension that would otherwise be flattened into a misleading
`trusted-signer: X` (§8). Another ecosystem would bring its own coordinate type
and its own purl projection, rather than contorting this one. Costs nothing now,
forecloses nothing later. No adapters shipped.

---

## 8. Background: alignment with existing standards

### Aligns well

- **in-toto Statement / DSSE envelope** — clean transport and binding layer.
  Artifact digest to predicate, signature outside. Generic enough that
  non-provenance predicates fit the same verifier later.
- **Sigstore trust root** — Fulcio cert chain plus the inclusion proof and
  signed entry timestamp carried in the bundle, verified locally, is the same
  endpoint whether the payload is a signature bundle or a DSSE envelope. The
  existing `sigstore` module is a reusable foundation, not a parallel path.
- **SLSA provenance predicate** — builder identity, source repo and commit,
  build parameters. Directly expressible as policy requirements alongside
  signer requirements.
- **purl as an output identifier** — the correlation surface across VSAs, SBOM
  annotation, and purl-keyed VEX data.
- **Group/namespace-scoped trust** — Gradle already proves this granularity
  works in practice (`<trusted-key id=... group=...>`). Most policy entries are
  prefix-scoped, not per-artifact.
- **Bootstrap-then-review workflow** — generate config from observed state,
  review as a PR diff. Already Sigmund's model via `generateTrustConfig`;
  Gradle's `--write-verification-metadata` is the reference UX.

### Partially aligns — adopt with care

- **VSA (`slsa.dev/verification_summary`)** — fits the provenance half of
  Sigmund; fits the signature half poorly. `verifiedLevels` is spec'd for SLSA
  level determinations, and "signed by a trusted publisher identity" is not a
  SLSA level. Macaron hits the same wall and emits `verifiedLevels: []`.
  `dependencyLevels` has the same problem. Adopt VSA as *a serializer* of the
  result model, never as the result model.
- **purl as a config identifier** — the verification unit is a *file* (jar,
  pom, sources, each with its own `.asc`), which Maven coordinates address
  directly via classifier and extension and purl pushes into qualifiers. purl
  also has no standard wildcard semantics for prefix-scoped policy.
  **Resolution: purl is a one-way projection, computed from the resolved
  coordinate on output, never parsed back into one for matching.** Subjects,
  digests and results are per file, identified by GAV plus classifier and
  extension; policy rules match at GAV level (§3.2). The normalization risk is
  specifically in round-tripping, which the design forbids — which is what
  makes the "costs nothing" claim in §7 true rather than optimistic. The one
  unavoidable exception is VSA *consumption*, where the subject is purl-keyed:
  match on digest first and treat the purl as a label, so the failure mode
  stays closed.
- **Gradle `verification-metadata.xml`** — right granularity, wrong trust
  primitive (key fingerprints, not identities), and a known rot problem:
  Gradle cannot determine that an entry is stale, so files accumulate. Treat as
  an interop target (generate from policy, import trusted-keys) rather than a
  format to replace.

### Does not align — do not force

- **SBOM as verification input** — see §1. Wrong direction and wrong timing.
- **A flattened "trusted signer" notion across ecosystems** — the attester role
  differs categorically: publisher key (Maven repositories), registry key signing on the
  publisher's behalf (npm), CI workflow identity (PyPI trusted publishing, npm
  provenance), distro vendor (RPM). Rendering all of these as
  `trusted-signer: X` yields identical green checks for very different
  assurance. Attester role must be a first-class policy dimension (§3.3).
- **OCI-style attestation storage for JARs** — cosign and policy-controller
  work because images have an attachment convention and admission controllers
  read it. There is no equivalent for a JAR on Central, and sidecars cannot be
  published next to third-party artifacts regardless.

---

## 9. Open questions

- **Enforcement policy for partial coverage.** Most dependencies will lack
  attestations for a long time. This is where the 2023 SLSA proof-of-concept
  Maven plugin stalled — the specific reason it stalled is worth confirming
  before citing, since a wrong characterization of someone else's project is
  costly in this audience. If the reason was that near-zero attestation
  coverage made any enforcing default fail everything, it is direct support for
  per-scope `NO_CLAIM` settings and for shipping in observe mode first.
- **Policy composition and inheritance.** Deliberately deferred. One
  authoritative config avoids defining merge semantics now. If org-plus-local
  composition is added later, the hard part is that "local may only add" is not
  the right rule — adding an acceptable identity to an inherited requirement is
  a *loosening*, not a tightening.
- **Staleness detection for generated policy** — the concrete improvement over
  Gradle's current behaviour, and worth designing rather than inheriting.
- **Key refresh cadence** for revocation to be meaningful (§3.8).
- **A repository-layout convention for attestations on Central** — determines
  whether discovery case 3 is solvable at all.
- **Whether `verifiedLevels` should carry non-SLSA properties** (the source
  track permits additional asserted properties) or stay empty as Macaron does.
- **Trust root distribution for verifier identity** in the delegated case.
- **Whether `ArtifactResolverPostProcessor` is a sufficient extension hook** —
  whether plugin and extension resolution pass through it, and whether an
  extension can contribute one (§2). A concrete question for the Maven
  maintainers.

---

## 10. Implementation sequence

Ordered so that each phase is demonstrable on its own and each is forced by the
one before it. This is the outline; tasks, dependencies and status are tracked
in the [verification roadmap](sigmund-verification-roadmap.md).

0. **Design records** — result model levels and roll-up (§3.2, §3.2.1); policy
   schema (§3.2, §3.3, §3.6).
1. **Vocabulary and result model** — evidence versus claim; subject with digest;
   the outcome vocabulary with reason codes, including correcting tools that
   report format or infrastructure problems as `FAILED`; verification and
   reporting moved into a core API with no build-tool types, because extensions see
   resolution requests rather than projects. Validated against the two shapes
   already shipping — detached `.asc` and Sigstore bundles — so DSSE lands later
   as a third fitting case rather than as scaffolding for a hypothetical.
2. **Policy as requirements** — role derivation and assertion; role-scoped
   requirements; bootstrap emitting the new schema.
3. **Enforcement and run modes** — per-outcome, per-scope settings; observe
   mode; argument surface split per §5.3; one policy at the reactor root.
4. **Cache, keys, revocation** — result cache per §3.7; key freshness;
   revocation reason codes per §3.8; bootstrap populating the cache.
5. **Maven core extension** — hook choice (§2); verification at resolution;
   coverage from the insertion point; identical results to the goal from the
   same policy. The first real coverage increase, and the demo for the upstream
   conversation.
6. **Policy distribution** — version-pinned policy artifact; local trust anchor
   for the policy-publishing identity.
7. **Provenance as claims** — DSSE and in-toto Statement parsing; SLSA
   provenance predicate as credentials, identity-only first; `ProvenanceSource`
   SPI, merged not first-match, with Rekor digest lookup opt-in.
8. **Attestations** — VSA emission as a serializer of the result model; VSA
   consumption with a separate verifier trust root, policy-digest staleness,
   one-hop loop guard and digest-first subject matching; outbound attestations.
9. **Gradle** — backend behind Gradle's dependency-verification surface, or
   `verification-metadata.xml` interop as the fallback that needs no upstream
   change.

Deferred: staleness detection for generated config; policy composition;
claims-aware provenance matching; classifier-scoped policy rules;
cross-ecosystem adapters.

---

## Appendix: decisions taken in this revision

| Area | Decision |
|---|---|
| Result levels | Claim, artifact and run results; artifact outcome derived in a fixed order; any `FAILED` claim dominates; claims no verifier supports are set aside unless explicitly required |
| Outcomes | Six-state vocabulary; `NO_CLAIM` replaces `UNSIGNED`; `INDETERMINATE` with transient/permanent reason codes |
| Enforcement | Per-outcome and per-scope; `FAILED` non-overridable; strictest for plugin/extension scope |
| Caching | Part of the trust model; digest + policy digest key, policy digest over the raw policy file content, not the parsed model; base-config digest recorded separately; policy self-contained; downgrades `INDETERMINATE`; `-o` never fail-open |
| Threat model | Stated explicitly; TOFU named as a limitation; outcomes stable except hard revocation, policy change or verifier change; OpenPGP backdating named as residual risk |
| Time | Three clocks; evaluation basis per claim kind; Sigstore basis inherited from `sigstore-java` |
| Revocation | Honour reason codes — compromise and unspecified retroactive, rotation forward-only; expiry judged at signature time; identity matching independent of keyserver-served user IDs; separate key TTL |
| Scope | Artifacts in Maven repositories, whatever the language; the repository format defines what is verified, each build tool where; core uses repository concepts, never build-tool types |
| Cross-ecosystem | purl on output is the portable identity; the internal coordinate stays the repository's own, named in purl's vocabulary |
| Insertion points | Three, not two; keep plugin and extension both; coverage recorded in the result and the VSA; `ArtifactResolverPostProcessor` a candidate extension hook; evidence and policy resolution bypass verification; extension scope limited to build tooling versus project |
| Vocabulary | Evidence = file, claim = assertion; rename `VerificationUnit` → `Claim` |
| Credentials | Two kinds — key material, and an attested identity of subject plus issuer; a bare email is not an identity; identity assertions only from policy-named issuers; key source recorded always |
| Attester role | Structure proposes, policy disposes; issuer carries the default role; `unknown` added; requirements are role-scoped |
| Digests | Algorithm-tagged `DigestSet` maps; SHA-256 required; further algorithms additive |
| Policy granularity | Rules match GAV prefixes; results stay per file; classifier and extension are not policy dimensions |
| purl | One-way projection only; digest-first matching on VSA consumption |
| Discovery | Three cases; discovery is network-bound, verification is not; only third-party retrofit is open |
| Sigstore | Verification is local; no transient failure mode for delivered bundles |
| Policy | One authoritative config per project at reactor root; no per-module; version-pinned policy artifact; composition deferred |
| Arguments | May configure how verification runs, never what is required |
| Observe mode | Run mode; VSA keeps policy reference; enforcement mode recorded; emission off by default |
| RPM | Independent precedent for all-signatures-must-verify and hybrid classic-plus-PQC signing; different container — header tags degrading by design, against concatenated armored blocks degrading by convention |
