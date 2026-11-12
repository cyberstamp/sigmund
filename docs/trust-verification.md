# Trust Verification

This guide covers identity-based trust verification for Maven dependencies using Sigmund. Trust verification goes beyond checking that signatures are valid — it answers the question: **"Is this artifact from someone I trust?"**

**Note:** This is distinct from signature verification, which only confirms that signatures are cryptographically valid. For basic signature verification, see [Signature Verification](verification.md).

## Contents

- [Concept](#concept)
  - [How It Works](#how-it-works)
- [The sigmund.yaml Trust Configuration](#the-sigmundyaml-trust-configuration)
  - [1. Signers](#1-signers)
  - [2. Rules](#2-rules)
  - [3. Enforcement](#3-enforcement)
  - [4. Verification Settings](#4-verification-settings)
- [Complete Example](#complete-example)
- [Running Trust Verification](#running-trust-verification)
  - [Example Output](#example-output)
  - [Outcomes](#outcomes)
  - [How an Outcome Is Derived](#how-an-outcome-is-derived)
  - [Exit Codes](#exit-codes)
  - [Maven Properties](#maven-properties)
- [Generating Trust Configuration](#generating-trust-configuration)
  - [Generated File Structure](#generated-file-structure)
  - [Generation Options](#generation-options)
- [Updating Trust Configuration](#updating-trust-configuration)
  - [Update Options](#update-options)
- [Recommended Workflow](#recommended-workflow)
  - [Initial Setup](#initial-setup)
  - [CI Integration](#ci-integration)
  - [Updating When Dependencies Change](#updating-when-dependencies-change)
  - [Handling Untrusted Dependencies](#handling-untrusted-dependencies)
- [Troubleshooting](#troubleshooting)
- [See Also](#see-also)

> **Note:** The examples in this guide use the `sigmund` plugin prefix (e.g., `mvn sigmund:verify`). This requires adding the plugin to your project's `pluginManagement`:
>
> ```xml
> <pluginManagement>
>   <plugins>
>     <plugin>
>       <groupId>dev.cyberstamp.sigmund</groupId>
>       <artifactId>sigmund-maven-plugin</artifactId>
>       <version>0.0.2</version>
>     </plugin>
>   </plugins>
> </pluginManagement>
> ```
>
> Alternatively, replace `sigmund` with the full plugin coordinates, e.g.:
> `mvn dev.cyberstamp.sigmund:sigmund-maven-plugin:0.0.2:verify`

## Concept

Trust verification combines signature verification with an identity policy:

1. **Signature verification** — confirms that an artifact's `.asc` signature is cryptographically valid
2. **Identity matching** — extracts signer credentials from the verified signature (fingerprints, email addresses, OIDC identities)
3. **Trust policy evaluation** — checks whether the proven credentials match your expected signers for that artifact

For example, you might trust artifacts from `io.quarkus.*` when signed by that project's release key, and artifacts from `com.fasterxml.jackson.*` when signed by the key of the maintainer who releases them. Trust verification enforces these rules automatically during your build.

### How It Works

Sigmund's `verify` goal:
1. Resolves your project's dependencies
2. Downloads each artifact's signature files — `.asc`, and `.sigstore.json` bundles when the
   `sigmund-sigstore` module is on the plugin's classpath ([Enabling Sigstore Support](maven-plugin.md#enabling-sigstore-support)) — from the artifact's repositories
3. Verifies each signature and extracts proven credentials
4. Finds the most specific rule in `sigmund.yaml` for each artifact and checks the proven credentials against what it requires
5. Reports each artifact's outcome, grouped by outcome and then by attester
6. Fails the build for any outcome the policy does not tolerate

## The `sigmund.yaml` Trust Configuration

Trust policies are defined in `sigmund.yaml` in your project root. Trust verification uses four parts of it; [Configuration Reference](configuration.md) documents every key.

### 1. Signers

The `signers` section defines trusted identities. Each signer has a unique ID and one or more credentials that can prove their identity.

#### Two Forms

**Minimal form** — a single email address, vouched for by a listed issuer:
```yaml
issuers:
  - keys.openpgp.org
signers:
  jackson-release: "jackson-release@example.org"
```

**Object form** — credential keys; unknown keys are errors:
```yaml
signers:
  jane:
    pgp4: "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
    email: "jane@example.com"
```

The signer's ID (`jane`) is how rules and reports refer to it.

#### Credential Types

A signer carries key material, identities, or both:

| Type | YAML Key | Description | Example |
|------|----------|-------------|---------|
| OpenPGP v4 | `pgp4` | 40-character v4 fingerprint, or a list of them | `4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12` |
| OpenPGP v6 | `pgp6` | 64-character v6 fingerprint, or a list of them | `D62AAB339E45E5EA2FD036872B01D46A517A2991EF8B8F67C32CF07A49CBDAA0` |
| Email | `email` | Address vouched for by an issuer | `dev@example.com` |
| Identities | `identities` | List of complete identities: an issuer and the attributes it attested | (see below) |

Fingerprints must be full; a 64-bit key ID is rejected at load because colliding key IDs can be generated.

An **email address is only as good as whoever vouches for it**. A user ID on an OpenPGP key proves nothing — anyone can put any address on a key they generate — so an address matches only when an issuer vouched for it: a directory that verifies addresses before publishing them (`keys.openpgp.org`), or the OIDC provider behind a Sigstore certificate. Issuers are listed once in the top-level `issuers` section, which a bare `email:` uses, or named on an entry under `identities`. See [issuers](configuration.md#issuers).

**Fingerprints for the keys already seen, an address for keys to come.** A fingerprint is stable, works offline and proves every signature the key ever made, but it covers only that key. An address lets the policy accept a key the publisher generates later: when a signature's key is not pinned, the directory is asked which verified addresses it serves for that key. Directory bindings are current state — after a rotation the directory serves the old key without the address — so keep the old fingerprints alongside the address — `pgp4` and `pgp6` take a list, and
[updating the trust configuration](#updating-trust-configuration) adds a confirmed new key to it.

**Identities** — each entry is complete: who vouched (`issuer`) and what they attested. A CI workflow attested by a Sigstore certificate:
```yaml
signers:
  github-actions:
    identities:
      - issuer: "https://token.actions.githubusercontent.com"
        source-repository-uri: "https://github.com/myorg/myrepo"
        build-config-uri: "https://github.com/myorg/myrepo/.github/workflows/release.yml@refs/heads/main"
```

`issuer` may be omitted to accept the issuer listed in `issuers` that can attest the entry — exactly one may; when two listed OIDC issuers could, name the issuer on the entry. Attribute names are checked at load, and a misspelling is an error suggesting the nearest known name. One signer may carry several identities, such as the same address vouched for by `keys.openpgp.org` and by an OIDC provider.

**Multiple credentials per signer:**
```yaml
signers:
  alice:
    pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"  # v4 fingerprint
    pgp6: "D62AAB339E45E5EA2FD036872B01D46A517A2991EF8B8F67C32CF07A49CBDAA0"  # v6 fingerprint
    email: "alice@example.com"
```

When a signature is verified, Sigmund extracts the credentials it proves: the full fingerprints of the signing key and its primary key, the identity in a Sigstore certificate, and — only when a policy entry needs it and no pinned fingerprint already matched — the addresses a directory verified for the key. A signer matches if **any** of their configured credentials matches **any** proven credential.

### 2. Rules

The `rules` section says what each set of artifacts must satisfy. A rule has a `match` list of
artifact patterns and a `requires` list of clauses:

```yaml
signers:
  apache:
    pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
  quarkus-team:
    pgp4: "BBE7232D7991050B54C8EA0ADC08637CA615D22C"
  redhat:
    pgp4: "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"

rules:
  - match: ["org.apache.maven.*", "org.apache.commons.*"]
    requires: [apache]
  - match: ["io.quarkus.*"]
    requires: [{any-of: [quarkus-team, redhat]}]
```

**Clauses are all required; `any-of` accepts one of its signers.** `requires: [a, b]` needs a
claim from `a` and one from `b` — "the publisher's key and our CI's workflow" is two clauses.
`requires: [{any-of: [a, b]}]` needs either. A clause is satisfied by a verified claim that proves
any of that signer's credentials.

**Patterns match the module, not the file.** A pattern names group, artifact and version —
`io.quarkus`, `io.quarkus:quarkus-core`, `io.quarkus:quarkus-core:3.0.0` — and covers every file
published under it. `io.quarkus.*` covers the group and every group below it; a trailing `*` on
artifact or version is a plain prefix; `"*"` matches everything. See
[Artifact Patterns](configuration.md#artifact-patterns).

**The most specific rule wins, and only it applies:**

```yaml
signers:
  core-team:
    pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
  quarkus-team:
    pgp4: "BBE7232D7991050B54C8EA0ADC08637CA615D22C"

rules:
  # Most specific - this artifact
  - match: ["io.quarkus:quarkus-core"]
    requires: [core-team]

  # Less specific - the group and everything below it
  - match: ["io.quarkus.*"]
    requires: [quarkus-team]

  # Least specific - everything else
  - match: ["*"]
    on-no-claim: warn
```

For `io.quarkus:quarkus-core:3.0.0` the first rule applies, and only `core-team` is accepted for
it. Two rules that could select the same artifact with equal specificity are rejected when the
policy loads, so the outcome never depends on the order rules are written in.

**Signers the rule does not name.** Once the requirements are met, a verified claim from a signer
no clause names makes the artifact `UNSATISFIED` under the default `extra-claims: reject` — the
rule's signers are taken as the complete list. Set `extra-claims: ignore` on the rule, or in
[`defaults`](configuration.md#defaults) for every rule, to let the requirements alone decide.

**Rules without `requires`.** A rule may require nothing, typically for artifacts known to be
published unsigned. It still matches, so those artifacts are verified and reported:

```yaml
rules:
  - match: ["com.internal.*", "org.example:test-utils"]
    on-no-claim: ignore
```

A signature that does appear on such an artifact must verify — `FAILED` is never tolerated. A
signed one is `UNSATISFIED`, since its signer is one no clause names; give it a rule of its own,
or add `on-unsatisfied: ignore` to tolerate it too.

### 3. Enforcement

What an outcome does to the build is set per rule (`on-…` keys) or for every rule in `defaults`,
each `fail`, `warn` or `ignore`:

```yaml
signers:
  apache:
    pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"

rules:
  - match: ["org.apache.*"]
    requires: [apache]
    on-indeterminate: warn

defaults:
  on-no-claim: warn
```

With a policy declared, every outcome other than `SATISFIED` fails the build unless the policy
relaxes it, and an artifact no rule matches (`NOT_CONFIGURED`) fails too. `FAILED` always fails,
and a setting for it is an error. A file without `rules` is not a policy: verification only
observes, failing on `FAILED` alone. `defaults` without `rules` is an error. See
[Policy and Enforcement](configuration.md#policy-and-enforcement) for the full resolution order.

These settings live only in `sigmund.yaml`. They change what is accepted, so they belong in the
reviewed file and cannot be set from the command line.

### 4. Verification Settings

The `verification` section controls how Sigmund fetches what it needs, never what it accepts:

```yaml
verification:
  resolve-signers: true
  import-to-keyring: false
  keyservers:
    - hkps://keys.openpgp.org
```

| Setting | Default | Description |
|---------|---------|-------------|
| `resolve-signers` | `true` | Fetch unknown keys from keyservers, and ask directories named in `issuers` for verified addresses |
| `import-to-keyring` | `false` | Import fetched keys to the local keyring |
| `keyservers` | `hkps://keys.openpgp.org` | List of keyservers for fetching OpenPGP keys |

**Keyservers supply key material only.** The signature proves the key whoever served it, and a user ID a keyserver serves never becomes an identity, so adding a keyserver such as `keyserver.ubuntu.com` cannot widen what is accepted. Identities come only from `issuers`; `keys.openpgp.org` is both the default keyserver and the directory Sigmund can ask for verified addresses.

## Complete Example

Here's a full `sigmund.yaml` with all trust-related sections:

```yaml
# Issuers trusted to vouch for identities
issuers:
  - keys.openpgp.org

# Trusted signers
signers:
  # Key already seen, plus an address for keys to come
  apache:
    pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
    email: "apache-release@example.org"

  quarkus-team:
    pgp4: "BBE7232D7991050B54C8EA0ADC08637CA615D22C"
    email: "quarkus-release@example.org"

  # Minimal form: email string
  jackson-release: "jackson-release@example.org"

  # Multiple keys and an address
  alice:
    pgp4: "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
    pgp6: "D62AAB339E45E5EA2FD036872B01D46A517A2991EF8B8F67C32CF07A49CBDAA0"
    email: "alice@example.com"

# Named groups of patterns
artifact-sets:
  apache-stack:
    - org.apache.maven.*
    - org.apache.commons.*

# What each set of artifacts must satisfy
rules:
  - match: [apache-stack]
    requires: [apache]

  - match: ["io.quarkus.*"]
    requires: [quarkus-team]

  # Both must have signed
  - match: ["com.example:shared-lib"]
    requires: [alice, jackson-release]

  - match: ["com.fasterxml.jackson.core:jackson-databind"]
    requires: [jackson-release]

  # Published unsigned
  - match: ["com.internal.*", "org.example:legacy-lib"]
    on-no-claim: ignore

# Policy-wide settings
defaults:
  extra-claims: reject
  on-indeterminate: warn

# How verification runs
verification:
  resolve-signers: true
  import-to-keyring: false
  keyservers:
    - hkps://keys.openpgp.org
```

## Running Trust Verification

Use the `sigmund:verify` goal to verify that all dependencies are signed by trusted signers:

```bash
mvn sigmund:verify
```

The goal reads `sigmund.yaml` from your project root, or the file given with
`-Dsigmund.trustConfig`. Without a file at the default location it runs without a policy and logs
that it is observing only.

### Example Output

A project with six dependencies, a policy requiring `alice` for `org.example.*` and `dave` for
`com.acme:widget`, and one module tolerated unsigned:

```
[INFO] SATISFIED (2)
[INFO]   openpgp VERIFIED by bc (EdDSA) - Alice Example <alice@example.org>
[INFO]     org.example:core:1.0
[INFO]     org.example:util:1.0
[ERROR]
[ERROR] UNSATISFIED (1)
[ERROR]   openpgp VERIFIED by bc (EdDSA) - Mallory Example <mallory@example.org>
[ERROR]     org.example:extra:1.0 [blocks]
[INFO]
[INFO] NO_CLAIM (1) — ignored: 1 by rules[2] 'com.acme:internal'
[ERROR]
[ERROR] INDETERMINATE (1)
[ERROR]   openpgp INDETERMINATE (KEY_UNAVAILABLE: no local key store or configured keyserver has it) by bc (EdDSA)
[ERROR]     com.acme:widget:1.0 [blocks]
[ERROR]
[ERROR] NOT_CONFIGURED (1)
[ERROR]   openpgp VERIFIED by bc (EdDSA) - Bob Example <bob@example.org>
[ERROR]     net.other:lib:1.0 [blocks]
```

The build then fails with `Verification blocked the build for 3 artifact(s): org.example:extra:1.0
(UNSATISFIED), com.acme:widget:1.0 (INDETERMINATE), net.other:lib:1.0 (NOT_CONFIGURED)`. The name
after a verified claim is the user ID on the key — display text, never what the policy matched:
`extra` is `UNSATISFIED` because Mallory's key is not one `alice` holds, whatever its user ID says.

Results are grouped by outcome, and within an outcome by who attested them. Each artifact line
says what its outcome does — `[blocks]`, `[warning]` or `[ignored]` — and is logged at that
severity. Ignored artifacts are counted in their outcome's heading, with the rule or `defaults`
that tolerated them, and listed only with `-Dsigmund.detail`. Detail also shows the credentials
proven, the trust root, and the evidence each claim was read from.

### Outcomes

| Outcome | Meaning |
|---------|---------|
| **SATISFIED** | The claims found meet what the matched rule requires |
| **UNSATISFIED** | Verification succeeded, but not by the signers the rule requires — or, under `extra-claims: reject`, also by one it does not name |
| **FAILED** | A signature does not match the artifact, or its key was revoked or had expired when it signed — or was revoked as compromised, at any time ([details](verification.md#outcomes-and-reasons)). An attack signal, never tolerated |
| **NO_CLAIM** | No evidence was found at all |
| **INDETERMINATE** | Evidence was found but could not be checked; the reason says why — a key that could not be fetched or used, an algorithm Sigmund does not accept, a tool that did not run |
| **NOT_CONFIGURED** | No rule matches this artifact |

An artifact a rule tolerates reaches the same outcome as any other; what the rule changes is
whether that blocks.

### How an Outcome Is Derived

An artifact may carry several claims — a hybrid `.asc` with a classic and a post-quantum
signature is two. Its outcome follows from them in a fixed order:

1. **Any claim `FAILED` → `FAILED`.** A valid signature alongside a failing one does not mask it.
2. **Claims no installed tool supports are set aside.** A post-quantum block that only `sq` can
   check is ignored when `sq` is not installed, so the classic block decides — and a block an
   attacker appends gains nothing, since only claims that verified count.
3. **No rule matches → `NOT_CONFIGURED`.**
4. **The rule's requirements are met → `SATISFIED`.** Under the default `extra-claims: reject`,
   only if no other verified claim comes from a signer the rule does not name (`UNSATISFIED`)
   and every claim could be checked (`INDETERMINATE`).
5. **Otherwise, in order:** a claim that could not be checked → `INDETERMINATE`, since it might
   have satisfied the rule; requirements that set-aside claims would meet, had the keys they
   name made them → `INDETERMINATE` with `unsupported-algorithm` — a co-signer whose
   post-quantum signature this verifier cannot check is not a wrong signer; nothing verified
   and a set-aside claim names no key → `INDETERMINATE` with `unsupported-algorithm`, since
   there is no signer to judge; any other claim, verified or set aside → `UNSATISFIED`, since
   every signer in view is one the rule does not accept; nothing found → `NO_CLAIM`.

   The key a set-aside claim names is not proven. The report shows it as
   `declared issuer … (not verified)`, so a rule can be extended to name it; the claim still
   has to verify before the rule accepts it.

### Exit Codes

| Exit Code | Condition |
|-----------|-----------|
| `0` | Nothing found blocks the build |
| `1` | An outcome the policy does not tolerate: `FAILED` always, and any other outcome whose action is `fail` |

### Maven Properties

Properties configure how verification runs — where keys come from, which files are checked, how
much is reported; what it accepts comes only from `sigmund.yaml`. See
[`sigmund:verify`](maven-plugin.md#sigmundverify) for the full list.

## Generating Trust Configuration

Instead of writing `sigmund.yaml` by hand, generate it from your project's actual dependency signatures:

```bash
mvn sigmund:dependency-signers \
  -Dsigmund.generateTrustConfig=true
```

This creates a `sigmund.yaml` in your project root by:
1. Resolving all project dependencies
2. Downloading and verifying their signatures
3. Grouping artifacts by the signers whose credentials they proved
4. Asking `keys.openpgp.org` which addresses it has verified for each signer's keys, and writing
   one as the signer's `email:` next to its fingerprints — the one on the key, when verified.
   A signer's ID is taken from the user ID on its key — unverified display text, to rename
   freely — or is `signer-N` when no user ID is known
5. Collapsing common groupId prefixes into wildcard patterns (e.g., `io.quarkus.*`)
6. Writing a requirement rule per group, and one rule tolerating the modules found without a signature

The generated file can be used directly with `mvn sigmund:verify`. It has no catch-all: a
dependency added later matches no rule and fails as `NOT_CONFIGURED` until an update adds it.

**A key whose signatures could not be checked here is still pinned, and marked.** The signature
names its key, so the rule requires the key that signed; but when no copy of it could be used —
such as a key `keys.openpgp.org` serves without the self-signatures that bind it, until its owner
verifies an address — `verify` reports the artifact `INDETERMINATE` until a usable copy is
available. The file marks the key, and the run ends with a warning naming each such signer with
the reason, once:

```yaml
  signer-2:
    pgp4: "C7BE5BCC9FEC15518CFDA882B0F3710FA64900E7"  # signature could not be checked here
```

```
[WARNING] The signatures of 2 signer(s) written could not be checked here; sigmund:verify reports their artifacts INDETERMINATE until a usable copy of each key is available:
[WARNING]   signer-2: the copy from hkps://keys.openpgp.org carries no self-signature binding the key
[WARNING]   signer-3: the copy from hkps://keys.openpgp.org carries no self-signature binding the key
[WARNING] Import each publisher's key from a source you trust (gpg --import, sq cert import).
```

Importing the key into GnuPG's or Sequoia's store resolves it: `gpg` verifies from its keyring,
and Bouncy Castle reads the same keyring. Take the key from where the publisher announces it — its
project's `KEYS` file or release page — rather than any keyserver: a key from a keyserver that
does not verify addresses proves the signature as well, but the user ID it carries is the
publisher's claim alone.
Trust established this way is trust on first use — the snapshot is accepted as it is, and only
changes from it are detected — so review it before committing. When any signer is named by an
address, the file lists `keys.openpgp.org` under `issuers`: the trust is stated in the file, not
assumed by Sigmund, and removing that line and the `email:` lines leaves fingerprints only.

### Generated File Structure

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/cyberstamp/sigmund/main/core/src/main/resources/sigmund.schema.json
issuers: [keys.openpgp.org]

signers:
  alice-developer:
    pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
    email: "alice@example.org"
  bob-example:
    pgp4: "BBE7232D7991050B54C8EA0ADC08637CA615D22C"  # user ID on the key, unverified: Bob Example <bob@example.org>
  signer-3:
    pgp4: "9A1C2E3D4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C"  # signature could not be checked here

rules:
  - match: com.example:specific-lib
    requires: alice-developer
  - match: io.quarkus.*
    requires: alice-developer
  - match: org.apache.maven.*
    requires: bob-example
  - match: com.acme:widget
    requires: signer-3
  - match: [com.internal.utils:helper-lib]
    on-no-claim: ignore
```

The first line points editors at the published schema, for completion and validation as the
file is edited — see [editor support](configuration.md#editor-support). `alice-developer` is
named by the address `keys.openpgp.org` verified for its key; `bob-example`'s key has no
verified address, so its user ID is shown as a comment, for recognizing the key only; and
`signer-3`'s signatures could not be checked here, as [above](#generating-trust-configuration).

An artifact observed with several signatures gets all their signers in `requires`, so each must
keep signing it — with one exception: a publisher's classic and post-quantum keys, carrying the
same user ID and signing exactly the same artifacts, become one signer holding both
fingerprints, so either signature satisfies the rule and a verifier without Sequoia still
reaches a verdict on the classic one. A matching user ID alone never combines keys, since user
IDs are unverified.

**Tips:**
- Review the generated file before committing — rename signer IDs to something meaningful; where a key is not named by its verified address, a comment shows the user ID it carries — unverified, and never used for matching
- Adjust wildcard patterns if they're too broad or too narrow
- Add `email:` for signers whose future keys you want to accept, with the directory listed under `issuers`

### Generation Options

| Property | Description |
|----------|-------------|
| `sigmund.generateTrustConfig` | Generate a new `sigmund.yaml`. Set to `true` for project root, or provide a file path. |
| `sigmund.overwrite` | Allow overwriting an existing file (default: `false`) |
| `sigmund.resolveSigners` | Overrides `verification.resolve-signers`, default `true`. `false` works offline: keys are not fetched and the directory is not asked, so no `email:` is written |
| `sigmund.keyservers` | Comma-separated keyserver list (default: `hkps://keys.openpgp.org`) |

## Updating Trust Configuration

After adding new dependencies, update your existing `sigmund.yaml` instead of regenerating it:

```bash
mvn sigmund:dependency-signers \
  -Dsigmund.updateTrustConfig=true
```

The update adds what the policy does not cover yet, preserving existing content, comments and
formatting:

- An artifact **no rule matches** gets a requirement rule for its signers, or a rule tolerating it
  when it carries no signature.
- An artifact matched only by a **rule without `requires`** — a catch-all, or the rule listing
  unsigned modules — gets a requirement rule once it is signed. When it was listed by name among
  the unsigned modules, it is moved out of that list, since the same pattern in two rules would
  tie.
- A signer the file already defines is reused when it proves the same key, rather than defined
  again. A new signer is named by its key's verified address as in a generated file; when the
  file does not list `keys.openpgp.org` under `issuers`, the address is written as an
  `identities` entry naming the directory, so adding a signer never widens what the listed
  issuers vouch for.
- A **rotated key** is pinned. When an artifact under a requirement is signed by a key its rule
  does not pin, and a directory confirms that key for the address of a signer the rule requires,
  the fingerprint is added to that signer, with a comment recording which directory confirmed
  which address — a single fingerprint becomes a block list, one key per line, so each key
  keeps its own comment:

  ```yaml
  signers:
    alice:
      pgp4:
        - "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
        - "BBE7232D7991050B54C8EA0ADC08637CA615D22C"  # pinned by update: https://keys.openpgp.org confirmed alice@example.com
      email: "alice@example.com"
  ```

  The address
  already accepts the key, but only while the directory serves it: once the publisher rotates
  again the binding is gone, and the pinned fingerprint keeps proving these artifacts offline.
  With `resolve-signers: false` the directory is not asked, and the key is listed for review.
  keys.openpgp.org serves v4 keys only, so a new v6 key — a hybrid publisher's post-quantum
  key — cannot be confirmed: under the default `extra-claims: reject` it is listed for review
  even when its v4 partner was pinned, because its claim alone would leave the artifact
  unsatisfied. The review line names the confirmed key it signed alongside, as context only:
  anyone who can change an `.asc` can add a signature to it, and put any user ID on their key.

Otherwise it never rewrites what a **requirement** already covers. An artifact now signed by a
key or identity its rule does not name is listed under **Needs review** instead: a changed signer
is what verification exists to catch, and accepting it is your decision. So is a module to move
out of a hand-written list update cannot safely edit, and a rotated key for a signer it cannot
edit — one written as an address, or an organization with `members`. The result is parsed and
checked before it is written; if it would not load, nothing is written and the goal fails with
the reason.

After updating, review the changes with `git diff`.

### Update Options

| Property | Description |
|----------|-------------|
| `sigmund.updateTrustConfig` | Update an existing `sigmund.yaml`. Set to `true` for project root, or provide a file path. |
| `sigmund.resolveSigners` | Overrides `verification.resolve-signers`, default `true`. `false` works offline: keys are not fetched and the directory is not asked, so no `email:` is written |

## Recommended Workflow

Here's a complete workflow for setting up and maintaining trust verification:

### Initial Setup

1. **Generate the initial trust config:**
   ```bash
   mvn sigmund:dependency-signers \
     -Dsigmund.generateTrustConfig=true
   ```

2. **Review and refine the generated `sigmund.yaml`:**
   - Rename signer IDs to meaningful names
   - Verify wildcard patterns match your intent
   - Remove or adjust signers you don't trust

3. **Test trust verification:**
   ```bash
   mvn sigmund:verify
   ```

4. **Commit the config:**
   ```bash
   git add sigmund.yaml
   git commit -m "Add dependency trust configuration"
   ```

### CI Integration

Add trust verification to your CI pipeline by running it before tests:

```yaml
# GitHub Actions example
- name: Verify dependency trust
  run: mvn sigmund:verify

- name: Run tests
  run: mvn test
```

Or configure it in your `pom.xml` to run automatically during the `validate` phase:

```xml
<build>
  <plugins>
    <plugin>
      <groupId>dev.cyberstamp.sigmund</groupId>
      <artifactId>sigmund-maven-plugin</artifactId>
      <version>0.0.2</version>
      <executions>
        <execution>
          <goals>
            <goal>verify</goal>
          </goals>
        </execution>
      </executions>
    </plugin>
  </plugins>
</build>
```

### Updating When Dependencies Change

When you add or upgrade dependencies:

1. **Update the trust config:**
   ```bash
   mvn sigmund:dependency-signers \
     -Dsigmund.updateTrustConfig=true
   ```

2. **Review the changes, and anything listed under Needs review:**
   ```bash
   git diff sigmund.yaml
   ```

3. **Verify trust:**
   ```bash
   mvn sigmund:verify
   ```

4. **Commit the updates:**
   ```bash
   git add sigmund.yaml
   git commit -m "Update trust config for new dependencies"
   ```

### Handling Untrusted Dependencies

When `mvn sigmund:verify` reports artifacts it does not accept, you have several options:

**Option 1: Add the signer** (if you trust them):
```yaml
signers:
  new-signer:
    pgp4: "BBE7232D7991050B54C8EA0ADC08637CA615D22C"

rules:
  - match: ["com.example.*"]
    requires: [new-signer]
```

**Option 2: Tolerate a missing signature** (if the artifact is published unsigned):
```yaml
rules:
  - match: ["com.example:artifact"]
    on-no-claim: ignore
```

**Option 3: Remove the dependency** (if you don't trust it or can replace it)

**Option 4: Warn instead of failing while you investigate** — relax the outcome in the policy,
for that rule or in `defaults`, and restore it once resolved:
```yaml
rules:
  - match: ["com.example.*"]
    requires: [new-signer]
    on-unsatisfied: warn
```

## Troubleshooting

### "Config file not found"

The goal reports this only for a file given explicitly with `-Dsigmund.trustConfig`. Check the
path; without the property, a missing `${project.basedir}/sigmund.yaml` just means verification
runs without a policy.

### The build observes but never fails

The log says the run is observing only: no file was found at the default location, or the file
declares no `rules`. Only a file with a policy enforces.

### An artifact is UNSATISFIED for a signer you trust

This usually means:
1. The signer's credentials changed (a new key) — run `mvn sigmund:dependency-signers` to see the key that signed, and add its fingerprint
2. A more specific rule matched than the one you expected — compare the artifact's coordinate with every rule whose pattern matches it; the most specific wins
3. The artifact carries an extra signature from a signer the rule does not name, under `extra-claims: reject`

### An artifact is INDETERMINATE

A claim was found but could not be checked; the reason in the report says why — usually a key no
store or keyserver could supply in usable form, or a post-quantum block without `sq`. See
[Signature Verification troubleshooting](verification.md#troubleshooting) for each reason and what
to do. A rule can tolerate it while you sort it out (`on-indeterminate: warn`), but it is not
accepted as `SATISFIED`.

### "NO_CLAIM" for artifacts that should be signed

The artifact might not have a `.asc` signature file in the repository. Check Maven Central or your artifact repository. If the artifact is legitimately unsigned, tolerate it with a rule and `on-no-claim: ignore`.

### Fingerprint mismatches

Fingerprints are case-insensitive, and written as the full fingerprint without spaces. These are equivalent:
- `4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12`
- `4aee18f83afdeb23468b2e5a2d7baf3c1e9f5a12`

A fingerprint with spaces, or a 16-character key ID, is rejected when the file loads.

### "FAILED" results

The signature does not match the artifact, or the key that made it was revoked or had expired
when it signed — or was revoked as compromised, which fails every signature it made. This is different from `UNSATISFIED`, where the signature is valid but the signer
is not accepted. Verify that:
1. The artifact and signature files match
2. The artifact hasn't been tampered with
3. The signing key has not been revoked — check the key on a keyserver

A key a verification tool will not use — one served without its binding signatures, or bound with
an algorithm Sigmund does not accept — is `INDETERMINATE`, never `FAILED`; see
[Outcomes and reasons](verification.md#outcomes-and-reasons).

## See Also

- [Configuration Reference](configuration.md) — every `sigmund.yaml` key
- [Signature Verification](verification.md) — cryptographic signature verification without trust policies
- [Signing Guide](signing.md) — signing your own artifacts
- [Getting Started](getting-started.md) — installation and basic usage
