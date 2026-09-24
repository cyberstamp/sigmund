# ADR-006: Identity and Credential Model

## Status

Proposed

## Context

`SignerIdentity` holds a list of `Credential`s, and `TrustVerifier` trusts an
artifact when a credential proven by evidence overlaps with a credential listed
for an expected signer. Three credential types exist today:
`FingerprintCredential`, `EmailCredential` and `SigstoreCredential`.

The attraction of `EmailCredential` was backend independence: one identity that
holds whether the signer uses OpenPGP or Sigstore, surviving key rotation.
`Credential`'s javadoc states this explicitly — an email entry matches both
OpenPGP, via UID parsing, and Sigstore, via the certificate SAN.

Examining how each is proven shows the types are not comparable:

- A **fingerprint** is proven by the signature. Nothing else has to be trusted,
  and it works offline.
- A **Sigstore SAN** is proven by a Fulcio certificate: an OIDC provider
  authenticated the subject, and the binding is inside the signed bundle and
  timestamped in Rekor.
- An **OpenPGP UID** is self-certified. The key owner signed their own claim to
  an address. Any key can carry any address.

The last case makes email matching as implemented unsound: a key generated for
the occasion, carrying `alice@example.org` in its UID, satisfies a policy
naming that address — and, because the types are interchangeable, also
satisfies a policy written for a Sigstore identity.

There is a real binding available, but it is a property of *where the key came
from*, not of the key. keys.openpgp.org distributes a UID only after the
address owner confirms it by email, and `DiscoveryConfig.DEFAULT_KEYSERVER` is
already that server, so Sigmund's default fetch path does obtain verified
bindings. What is missing is that nothing records which source supplied the key
material: `BcRunner.fetchKey` returns early when the local store already holds a
key with UIDs, whichever source put it there, and it loops the configured
keyservers taking the first answer that carries UIDs — so adding a
non-verifying keyserver silently turns unverified UIDs into matches.

Confirmed from the keys.openpgp.org FAQ, and load-bearing for the design: an
address is associated with a single key, and verifying it for a new key means
it "will no longer appear in any key for which it was previously verified".
Non-identity data is still served for the old key. So identity bindings are
current-state only, and rotation unbinds signatures the old key made.

## Decision

Model every proven fact as a credential of one of two kinds, and make identity
assertions come from explicitly trusted issuers.

### Two credential kinds

```java
public sealed interface Credential permits KeyCredential, IdentityCredential {
    String type();
    String displayName();
    boolean matches(Credential other);
}

/** Key material, proven by the signature itself. No issuer, no network. */
public record KeyCredential(String algorithmFamily, String fingerprint) implements Credential { }

/** An identity asserted by a third party: the issuer, plus what it attested. */
public record IdentityCredential(
        String issuer,
        Map<String, String> attributes) implements Credential { }
```

`subject` is one attribute, not the identifier. A GitHub Actions SAN —
`https://github.com/acme/widget/.github/workflows/release.yml@refs/tags/v1.2.3`
— carries the tag, so it changes with every release and cannot appear in a
policy that survives dependency upgrades. The stable attributes are the Fulcio
certificate extensions: `source-repository-uri`, `build-config-uri`,
`build-trigger`, `runner-environment`. `configuration.md` already recommends
`issuer` plus `source-repository-uri` for this reason, and that guidance is the
model rather than an exception to it.

`EmailCredential` is removed. A bare email is not an identity, because it does
not say who vouches for it. `SigstoreCredential` becomes an `IdentityCredential`
whose issuer is the OIDC issuer, whose subject is the SAN, and whose workflow
fields — source repository, build trigger, runner environment — become
attributes. `FingerprintCredential` becomes `KeyCredential`.

Matching keeps today's semantics: the issuer must be equal, and every attribute
the policy specifies must be present in the proven credential and equal. A
policy that specifies fewer attributes matches more broadly, so at least one
attribute besides the issuer is required — an entry naming only an issuer would
accept every identity it ever asserts, and is a config error. A `KeyCredential`
never matches an `IdentityCredential`.

Choosing attributes is a trade-off between stability and precision, and the
docs must state it: `source-repository-uri` alone accepts any workflow in that
repository, including ones that are not the release pipeline, so pairing it
with `build-config-uri` — and, where it matters, `build-trigger` and
`runner-environment` — is the recommended shape.

### Trusted issuers

Identity assertions are accepted only from issuers the policy names:

```yaml
issuers:
  keys.openpgp.org:
    kind: openpgp-directory
    asserts: [email]
  https://token.actions.githubusercontent.com:
    kind: oidc
    asserts: [workflow]
    default-role: builder
  acme-vetted-keyring:
    kind: local-store
    path: /etc/sigmund/trusted-keys.d
    asserts: [email]
    default-role: publisher
```

- **`kind`** selects how a binding is proven: `oidc` from a Fulcio certificate,
  `openpgp-directory` from a UID served by that directory, `local-store` from a
  UID in a curated local key store. An `openpgp-directory` issuer carries its own
  lookup endpoint and is queried in its own right, whatever the `keyservers`
  argument says — otherwise a command-line keyserver change would decide whether
  an identity resolves.
- **`asserts`** bounds what an issuer may claim, so a directory that only
  verifies email addresses cannot be the source of a workflow identity.
- **`default-role`** feeds role derivation (§3.3): structure proposes via the
  issuer, policy disposes per signer, and a mismatch is a config error.
- **The list is empty by default.** Fetching a key by fingerprint and trusting a
  server to say who someone *is* are different grants, so the default keyserver
  does not become a default issuer. With no issuers configured, only
  `KeyCredential` matching happens — which is what bootstrap generates. A
  credential matcher no trusted issuer can assert is a config error naming the
  signer, the attribute and the stanza to add, never a silently inert entry.

**Well-known issuers carry profiles, so the common case is one line:**

```yaml
issuers:
  - keys.openpgp.org
  - https://token.actions.githubusercontent.com
```

A scalar entry naming a known issuer expands to its profile; the map form
overrides fields or defines an issuer with no profile; a scalar that matches no
profile is an error asking for `kind` and `asserts`.

**Profiles live in a base configuration file, not in code.** Sigmund ships a
`sigmund-base.yaml` resource, locates and reads it before the project policy,
and layers the project policy over it — the super-POM arrangement. It is a real
file, so it can be printed, diffed and versioned, and an organization can
replace it with its own (pinned as an artifact, §5.2) to standardize profiles
across projects.

**The base config declares, it does not grant.** It carries issuer *profiles* —
kind, asserts, lookup endpoint, trust root, default role — and never the list of
trusted issuers. Trust stays in the project policy, which selects from the
profiles by name. Otherwise a shipped file would quietly decide who may vouch
for identities, which is exactly what the empty default exists to prevent.

Because a profile change alters what an unchanged policy means, the run result
records the **effective expanded issuer configuration**, the base config's own
digest alongside the policy digest (§3.7), and the Sigmund version, since
defaults that live in code change with a release. A VSA consumer then sees what
actually applied, and `sigmund effective-config` prints it with the origin of
each value.

**The boundary is enforced by the schema, not by discipline.** The base config
is a separate document type with its own parser and its own root, not a
`SigmundConfig` with some sections ignored. Its schema admits exactly:

| Section | Why it is safe |
|---|---|
| `version` | Schema version |
| `issuer-profiles` | Declares how an issuer's assertions are proven; asserts nothing by itself |
| `keyservers` | Fetch endpoints; fetching cannot change acceptance (§5.3) |
| `tools` | Tool discovery, paths, toolchain priority |

There is no `issuers` key in this schema, so the trusted-issuer list cannot be
expressed in the base config even by mistake — the grant has no syntax there.
Likewise absent: `signers`, rules, requirements, enforcement settings and TTLs.
Unknown keys are an error rather than being skipped, so a policy file fed in as
a base config fails loudly, and so does the reverse: the policy parser rejects
`issuer-profiles`.

Enforcement defaults stay in code rather than in the base config, which keeps
the invariant sharp: **nothing in the base config can, on its own, cause an
artifact to be accepted or a build to pass.** Code defaults remain visible
through `effective-config` and are pinned by the recorded Sigmund version.

Two checks back this up:

- A **build-time test** loads the shipped `sigmund-base.yaml` through the strict
  parser, asserts it parses with no unknown keys, and asserts the two parsers
  reject each other's documents. It runs on every build, not only at release.
- **Load-time validation** applies the same strict parser to an
  organization-supplied base config, which matters more: a replaced base config
  is an input that changes what policies mean, so it is resolved as a
  version-pinned artifact and verified against the local trust anchor exactly as
  a policy artifact is (§5.2).

### Matchers expand at load

What a signer declares is not a credential but a pattern with the issuer left
open. Policy holds **matchers**; evidence proves **credentials**:

```java
public sealed interface CredentialMatcher permits KeyMatcher, IdentityMatcher {
    boolean matches(Credential proven);
}
```

`IdentityMatcher` may carry no issuer, meaning "any trusted issuer that asserts
these attributes". `Credential.matches(Credential)` becomes
`CredentialMatcher.matches(Credential)`, which is what the code already does —
today the two sides share a type only by coincidence.

One list per signer, with entries distinguished by their keys, replacing the
`email:`/`pgp4:`/`sigstore:` siblings of the current schema:

```yaml
signers:
  alice:
    credentials:
      - openpgp4: 4AEE18F83AFDEB23     # key material
      - email: alice@example.org       # issuer filled in by expansion
  release-bot:
    credentials:
      - issuer: https://token.actions.githubusercontent.com
        source-repository-uri: https://github.com/acme/widget
        build-config-uri: https://github.com/acme/widget/.github/workflows/release.yml
```

`issuer` is a reserved key in an entry; every other key is an attested
attribute. A per-signer `issuers` list narrows expansion for entries that omit
the issuer.

At config load each matcher expands against the trusted issuers whose `asserts`
covers the attributes it names, producing explicit `(issuer, attributes)`
matchers. Expansion happens once, at load, rather than as wildcard matching at
verification time, so that matching stays exact, the result records which issuer
matched, and adding a trusted issuer visibly widens the effective policy — a
change the policy digest captures (§3.7).

### Key-material provenance

Every claim records where the key material that proved it came from — keyserver
URL, local store, GnuPG keyring, evidence sidecar — in the `ClaimResult`'s
`TrustRootRef` (ADR-005). Provenance is recorded always; it is *consulted* only
for identity assertions.

This is the distinction that makes the model sound: a hostile source cannot
forge a fingerprint match, because the signature proves the key material. It can
forge a UID. So a UID becomes an `IdentityCredential` only when the source that
supplied it is a trusted issuer; otherwise the address is display text in the
report and proves nothing.

`BcRunner.fetchKey` changes accordingly: it records the source of every key it
stores, and stops preferring whichever keyserver returns UIDs.

### Directory bindings are current-state

An `openpgp-directory` binding is observed at fetch time, not signing time, and
is not part of the signed evidence. Consequences, all of which are recorded
rather than hidden:

- The binding carries its own observation time and is stored with the key, under
  the key-freshness TTL (§3.7), not the result cache.
- Offline with no cached binding, an identity requirement is
  `INDETERMINATE(KEY_UNAVAILABLE)`, never a pass.
- Rotation unbinds history: after a publisher verifies the address for a new
  key, the old key is served without the UID, so signatures it made no longer
  prove the identity. A verifier that cached the binding keeps it; a first-time
  verifier does not.

Therefore **fingerprints remain the backbone for third-party dependency
verification** — stable, offline and historically complete — and bootstrap
keeps emitting them. Identity credentials are opt-in, and most useful for
first-party and forward-looking trust.

Whole-key revocations are distributed for keys with no verified UID, so
revocation checking (§3.8, P4.7) is unaffected by identity binding.

### Consequence for §5.3

The argument surface splits more finely than §5.3 states. `keyservers` remains
argument-configurable, because fetching by fingerprint cannot change what is
accepted. `issuers` is policy-only, because it decides whether an identity
assertion is accepted at all. Without this split, adding a non-verifying
keyserver on the command line would widen acceptance.

### Consequence for the threat model

§1.1 claims defence against publisher account takeover producing releases under
a different key. That holds for `KeyCredential` policies. For
`IdentityCredential` policies the guarantee is inherited from the issuer:
whoever controls the OIDC account, or the email address at the directory, can
bind a new key to the identity. This is the same property Sigstore keyless has
by construction, and §1.1 must state that the guarantee depends on the
credential kind in use.

## Consequences

**Removed:** `EmailCredential`, and UID text as a matching input.

**Renamed and reshaped:** `FingerprintCredential` → `KeyCredential`;
`SigstoreCredential` → `IdentityCredential` with attributes; `Credential`
becomes a sealed interface over the two kinds, with a parallel
`CredentialMatcher` hierarchy for the policy side.

**Config:** a new top-level `issuers` section; one `credentials` list per signer
carrying both key material and attested attributes, with an optional per-signer
`issuers` narrowing. The `sigstore:` block folds into that list, since its
fields are exactly the attested attributes. An `email:` entry with no issuer
trusted to assert it is rejected with a message naming the signer and the
stanza to add.

**Behaviour users would notice:** a policy naming an email stops matching until
an issuer is trusted for it; a key in the local GnuPG keyring carrying that
address no longer satisfies it; `sigmund inspect-signer` reports the source that
supplied each key.

**Deferred:** attribute wildcards — `*@example.org` for an email, or a ref
pattern such as `.../release.yml@refs/tags/*` for a SAN subject, which would
make subject matching usable without per-release churn; WKD as an issuer kind;
pinning a local store by digest so identity assertions from it are reproducible.

**Ordering:** implemented in roadmap phase P2, with the key-provenance and
binding-freshness parts landing in P4.6. ADR-007 defines requirements, policy
schema and enforcement on top of these credentials.
