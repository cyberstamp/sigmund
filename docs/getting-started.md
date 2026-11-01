# Getting Started

This guide walks you through your first experience with Sigmund — discovering who signed your dependencies and enforcing trust policies based on signer identity.

## Contents

- [Prerequisites](#prerequisites)
- [See Who Signed Your Dependencies](#see-who-signed-your-dependencies)
- [Generate a Trust Policy](#generate-a-trust-policy)
- [Enforce the Policy](#enforce-the-policy)
- [Update When Dependencies Change](#update-when-dependencies-change)
- [Next Steps](#next-steps)

## Prerequisites

Sigmund requires:

- **JDK 17 or later** — Check with `java -version`
- **Maven 3.9 or later** — Check with `mvn -version`

No external tools are required for this walkthrough. Sigmund includes a pure-Java Bouncy Castle backend that handles classic OpenPGP signature verification without needing `gpg` or `sq` installed. Sigstore bundle (`.sigstore.json`) verification is also available when you add `sigmund-sigstore` as a plugin dependency — see [Enabling Sigstore Support](maven-plugin.md#enabling-sigstore-support).

> **Note:** The examples in this guide use the `sigmund` plugin prefix (e.g., `mvn sigmund:dependency-signers`). This requires adding the plugin to your project's `pluginManagement`:
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
> `mvn dev.cyberstamp.sigmund:sigmund-maven-plugin:0.0.2:dependency-signers`

## See Who Signed Your Dependencies

Run the `dependency-signers` goal on any Maven project to inspect signatures on all its dependencies:

```bash
mvn sigmund:dependency-signers
```

Sample output:

```
Signer: Alice Developer <alice@example.com>
   PGP4 (EdDSA): 4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12
     com.example:lib-a:1.0
     com.example:lib-b:2.0

Signer: Bob Maintainer (Code signing key) <bob@example.org>
   PGP4 (RSA): BBE7232D7991050B54C8EA0ADC08637CA615D22C
     org.example:parser:3.1

Signer: Carol Release <carol@example.net>
   PGP4 (ECDSA): 9C1F2E7D4B6A08355E3D21C7A9B04F6E12D83A57
     net.example:tool:2.4

UNSIGNED
  com.example:internal-util:1.0

Summary: All clear: 5 dependencies, 4 PGP4 signature(s), 3 unique key(s)
PQ coverage: 0/5 dependencies have a post-quantum signature
```

The output groups artifacts by signer. Each signer shows their name and email (if known) and key fingerprints. Classical v4 signatures (RSA, EdDSA) and post-quantum v6 signatures (ML-DSA) are reported separately. Unsigned artifacts appear in their own section. When you add `sigmund-sigstore` as a plugin dependency ([Enabling Sigstore Support](maven-plugin.md#enabling-sigstore-support)), `.sigstore.json` bundles are also resolved and verified — Sigstore signers appear with their OIDC identity (email or workflow URI) instead of a PGP fingerprint.

Sigmund fetches unknown keys from `keys.openpgp.org` by default to resolve signer identities. The fetched keys are only kept in memory for the duration of the build and are not persisted to disk.

### Why Some Signers Appear as UNKNOWN

In most projects some signers appear like this:

```
Signer: UNKNOWN (key unavailable)
   PGP4 (RSA): C7BE5BCC9FEC15518CFDA882B0F3710FA64900E7 (key unavailable: the copy from hkps://keys.openpgp.org carries no self-signature binding the key)
     com.google.code.gson:gson:2.11.0
```

Sigmund found no usable copy of the signing key, so it could not check the signature. The reason in parentheses says why:

- **`the copy from hkps://keys.openpgp.org carries no self-signature binding the key`** — the most common case. `keys.openpgp.org` is a **verifying keyserver**: it publishes a key's user IDs (name and email) only after the key's owner confirms the address through a verification link, and until then serves the key without them. Older keys carry their self-signatures — the signatures by which a key states what it may be used for — only on those user IDs, so the copy served cannot be used to check anything.
- **`no local key store or configured keyserver has it`** — the key is not published where Sigmund looked.
- **`the signature names only a key ID, which is not looked up on keyservers`** — the signature carries a short key ID rather than a full fingerprint, and Sigmund fetches keys by fingerprint.

`keys.openpgp.org` is the default because the names it does publish are backed by a verified email address. Keyservers such as `keyserver.ubuntu.com` accept uploads from anyone, so anyone can upload a key claiming to be `Alice Developer <alice@example.com>`.

### Resolving More Keys

Which keyservers to ask is your choice: each one learns which keys your build looks up. To resolve more keys, add a keyserver such as `keyserver.ubuntu.com`:

```bash
mvn sigmund:dependency-signers \
  -Dsigmund.keyservers=hkps://keys.openpgp.org,hkps://keyserver.ubuntu.com
```

Keys it serves with their user IDs become usable, and their signers show a name and email. A key you hold in GnuPG's or Sequoia's own store (`gpg --import`, `sq cert import`) is used too.

**Important:** The names and emails returned by keyservers other than `keys.openpgp.org` are **not verified**. Anyone can upload a key to those servers claiming any identity. Treat these as hints for investigation, not proof of who signed an artifact. Trust decisions in `sigmund.yaml` should be based on key fingerprints, not on self-reported names.

## Generate a Trust Policy

Once you've reviewed who signed your dependencies, generate an initial `sigmund.yaml` trust configuration:

```bash
mvn sigmund:dependency-signers \
  -Dsigmund.generateTrustConfig=true
```

This creates a `sigmund.yaml` file in your project root based on actual dependency signatures.

**signers** — Declares known signers by their full key fingerprints. When `keys.openpgp.org` has verified an address for a signer's key — its owner confirmed the address before the directory published it — the signer is named by that address too, and the file trusts the directory under `issuers`. A key without one shows the user ID it carries as a comment on its fingerprint, to help you recognize it:

```yaml
issuers: [keys.openpgp.org]

signers:
  alice-developer:
    pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
    email: "alice@example.com"
  bob-builder:
    pgp4: "BBE7232D7991050B54C8EA0ADC08637CA615D22C"  # user ID on the key, unverified: Bob Builder <bob@example.org>
```

The comment is unverified because a user ID is self-certified; it is also kept when the key's user ID shows a different address from the one the directory verified. The fingerprint proves the key already seen, offline. The address accepts a key Alice generates later, once she verifies the address for it, and the next update pins that key's fingerprint too. The user ID itself is never used for matching — anyone can put any address on a key. What the address trusts is the directory's verification and Alice's mailbox; to rely on fingerprints only, remove the `email:` lines and `issuers`. A signer whose key has no verified address, or a run with `-Dsigmund.resolveSigners=false`, gets the fingerprint alone. See [issuers](configuration.md#issuers).

**rules** — What each group of artifacts must satisfy. A requirement rule per group of artifacts signed alike, and one rule listing the modules that carried no signature:

```yaml
issuers: [keys.openpgp.org]

signers:
  alice-developer:
    pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
    email: "alice@example.com"

rules:
  - match: com.example.*
    requires: alice-developer
  - match: [com.internal:util]
    on-no-claim: ignore
```

`com.example.*` covers the group and every group below it. An artifact signed by several parties gets them all in `requires`, as a list such as `[alice-developer, bob]`, and every one must keep signing. A publisher's classic and post-quantum keys — the same user ID, signing exactly the same artifacts — become one signer with both fingerprints, so either signature satisfies its rule. The last rule tolerates `com.internal:util` being unsigned; it stays a list even with one module, since an update removes a module from it once that module starts being signed. It is still verified, so a signature that does appear on it must verify. See [rules](configuration.md#rules) for the full syntax.

The generated file deliberately has no catch-all rule: a dependency you add later matches no rule, fails verification as `NOT_CONFIGURED`, and enters the policy only through an update you review.

## Enforce the Policy

Run the `verify` goal to enforce the trust policy:

```bash
mvn sigmund:verify
```

**On success**, you'll see output like:

```
[INFO] SATISFIED (2)
[INFO]   openpgp VERIFIED by bc (EdDSA) - Alice Developer <alice@example.com>
[INFO]     com.example:lib-a:1.0
[INFO]     com.example:lib-b:2.0
[INFO]
[INFO] NO_CLAIM (1) — ignored: 1 by rules[1] 'com.internal:util'
```

Results are grouped by outcome, and within an outcome by who attested them.
`com.internal:util` reached `NO_CLAIM` because no signature was found for it; the
heading counts it and names the rule that tolerates it, and the artifact itself is
listed only with `-Dsigmund.detail`. Detail also shows the key each group proved,
the trust root it was checked against, and the evidence file behind each artifact.

**When untrusted artifacts are found**, the build fails:

```
[ERROR] UNSATISFIED (1)
[ERROR]   openpgp VERIFIED by bc (RSA) - Bob Malicious <bob@evil.com>
[ERROR]     com.example:lib-c:1.0 [blocks]

[ERROR] Verification blocked the build for 1 artifact(s): com.example:lib-c:1.0 (UNSATISFIED)
```

The signature verified — `UNSATISFIED` says the policy does not accept the
signer, not that the cryptography failed. That case is `FAILED`, and no setting
tolerates it.

Each outcome's handling is set in the policy, per rule or in `defaults`: `fail`,
`warn` or `ignore`. To see the blast radius of a stricter policy without failing
the build, relax it while you look — for example, report unsigned artifacts
everywhere as warnings:

```yaml
signers:
  alice-developer:
    pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"

rules:
  - match: com.example.*
    requires: alice-developer

defaults:
  on-no-claim: warn
```

These settings live only in `sigmund.yaml`, never on the command line: they change
what is accepted, so they belong in the reviewed file. See
[Policy and Enforcement](configuration.md#policy-and-enforcement).

## Update When Dependencies Change

When you add or upgrade dependencies, update `sigmund.yaml` to include new signers and artifacts:

```bash
mvn sigmund:dependency-signers \
  -Dsigmund.updateTrustConfig=true
```

This adds what the policy does not cover yet, preserving all existing content including comments and formatting:

- an artifact no rule matches gets a requirement on its signers, or, if it carries no signature, a rule tolerating that;
- a module that was listed as unsigned and is now signed moves out of that list into a requirement rule of its own.

It never rewrites what a requirement already covers, with one exception: a rotated key. When an artifact is signed by a new key that the directory confirms for the address of the signer its rule requires — the publisher verified the address for the new key — the update adds the fingerprint to that signer, so the signatures keep verifying after the publisher rotates again. Any other new signer is listed under **Needs review** instead — a changed signer is exactly what verification exists to catch, so accepting it is your decision. The update is checked before it is written: a result that would not load is not written.

Review changes before committing:

```bash
git diff sigmund.yaml
```

This workflow lets you incrementally maintain trust policies as your dependency graph evolves.

## Next Steps

- **[Trust Verification](trust-verification.md)** — Deep dive into trust configuration, wildcard patterns, and policy customization
- **[Signing Guide](signing.md)** — Sign your own artifacts with GPG, Bouncy Castle, Sigstore, or hybrid post-quantum keys
- **[Migrating from maven-gpg-plugin](migrating-from-gpg-plugin.md)** — Drop-in replacement guide for existing GPG workflows
- **[Migrating from sigstore-maven-plugin](migrating-from-sigstore-maven-plugin.md)** — Migration guide for existing Sigstore workflows
