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

No external tools are required for this walkthrough. Sigmund includes a pure-Java Bouncy Castle backend that handles classic OpenPGP signature verification without needing `gpg` or `sq` installed. Sigstore bundle (`.sigstore.json`) verification is also available when the `sigmund-sigstore` module is on the classpath — see [Signing with Sigstore](signing.md#signing-with-sigstore) for setup.

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

Signer: NOT VERIFIED
   PGP4 (RSA): B2A3CF1E8D4F5A6B7C9D0E1F2A3B4C5D6E7F8A9B
     com.other:tool:3.0

Signer: UNKNOWN (key not in keyring)
   PGP4 (DSA): D1031D14464180E0
     com.internal:messaging:2.1

UNSIGNED
  com.internal:util:1.0

Summary: All clear: 4 dependencies, 3 PGP4 signature(s), 0 PGP6 signature(s), 2 unique key(s)
```

The output groups artifacts by signer. Each signer shows their name and email (if known) and key fingerprints. Classical v4 signatures (RSA, EdDSA) and post-quantum v6 signatures (ML-DSA) are reported separately. Unsigned artifacts appear in their own section. When the `sigmund-sigstore` module is on the classpath, `.sigstore.json` bundles are also resolved and verified — Sigstore signers appear with their OIDC identity (email or workflow URI) instead of a PGP fingerprint.

Sigmund fetches unknown keys from `keys.openpgp.org` by default to resolve signer identities. The fetched keys are only kept in memory for the duration of the build and are not persisted to disk.

### Why Many Signers Appear as NOT VERIFIED

You'll notice that many signers show as `NOT VERIFIED` rather than with a name and email. This is expected and is a consequence of how `keys.openpgp.org` — Sigmund's default keyserver — works.

Unlike older keyservers, `keys.openpgp.org` is a **verifying keyserver**: it only publishes a key's user ID (the name and email) after the key owner confirms their email address through a verification link. Keys whose owners haven't completed this step are served without user IDs — Sigmund gets the key material (enough for signature verification) but not the identity information, so the signer is reported as `NOT VERIFIED`.

This is why `keys.openpgp.org` is the default rather than alternatives like `keyserver.ubuntu.com` or the legacy SKS pool. Those servers accept key uploads from anyone without any identity verification, which means anyone can upload a key claiming to be `Alice Developer <alice@example.com>`. The `keys.openpgp.org` model trades convenience for integrity: fewer names are visible, but the names you do see are backed by verified email ownership.

### Resolving More Signer Names

To resolve more signer names, you can add additional keyservers such as `keyserver.ubuntu.com` and `pgp.mit.edu`:

```bash
mvn sigmund:dependency-signers \
  -Dsigmund.keyservers=hkps://keys.openpgp.org,hkps://keyserver.ubuntu.com,hkps://pgp.mit.edu
```

With these additional keyservers, most signers will now show names and emails — including those previously listed as `NOT VERIFIED` or `UNKNOWN (key not in keyring)`.

**Important:** The names and emails returned by keyservers other than `keys.openpgp.org` are **not verified**. Anyone can upload a key to those servers claiming any identity. Treat these as hints for investigation, not proof of who signed an artifact. Trust decisions in `sigmund.yaml` should be based on key fingerprints, not on self-reported names.

## Generate a Trust Policy

Once you've reviewed who signed your dependencies, generate an initial `sigmund.yaml` trust configuration:

```bash
mvn sigmund:dependency-signers \
  -Dsigmund.generateTrustConfig=true
```

This creates a `sigmund.yaml` file in your project root based on actual dependency signatures. The generated file contains three sections:

**signers** — Declares known signers with their key fingerprints and email addresses:

```yaml
signers:
  alice-developer:
    pgp4: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
    pgp6: "D62AAB339E45E5EA2FD036872B01D46A517A2991..."
    email: "alice@example.com"
```

**trust** — Maps artifact patterns to trusted signers:

```yaml
trust:
  com.example:*: alice-developer
  com.other:tool: [signer-2, signer-3]
```

**signature-optional** — Lists artifacts allowed to carry no signature:

```yaml
signature-optional:
  - com.internal:util
```

Wildcard patterns like `com.example:*` trust all artifacts from a group. Multiple signers can be specified as a YAML array when an artifact is co-signed.

## Enforce the Policy

Run the `verify` goal to enforce the trust policy:

```bash
mvn sigmund:verify
```

**On success**, you'll see output like:

```
SATISFIED (2)
  openpgp VERIFIED by bc (Ed25519) - Alice Developer <alice@example.com>
    com.example:lib-a:1.0
    com.example:lib-b:2.0

NO_CLAIM (1)
    com.internal:util:1.0
```

Results are grouped by outcome, and within an outcome by who attested them.
`com.internal:util` reached `NO_CLAIM` because no signature was found for it;
listing it under `signature-optional` is what keeps that from failing the build.
Add `-Dsigmund.detail` to see the key each group proved, the trust root it was
checked against, and the evidence file behind each artifact.

**When untrusted artifacts are found**, the default behavior is to fail the build:

```
UNSATISFIED (1)
  openpgp VERIFIED by bc (RSA) - Bob Malicious <bob@evil.com>
    com.sketchy:malware:1.0

[ERROR] Verification blocked the build for 1 artifact(s): com.sketchy:malware:1.0 (UNSATISFIED)
```

The signature verified — `UNSATISFIED` says the policy does not accept the
signer, not that the cryptography failed. That case is `FAILED`, and no setting
tolerates it.

The `on-untrusted` setting controls failure behavior. The default is `fail`. Set it to `warn` in `sigmund.yaml` to report issues without failing the build:

```yaml
policy:
  on-untrusted: warn
```

Or override it per-build with `-Dsigmund.onUntrusted=warn`.

## Update When Dependencies Change

When you add or upgrade dependencies, update `sigmund.yaml` to include new signers and artifacts:

```bash
mvn sigmund:dependency-signers \
  -Dsigmund.updateTrustConfig=true
```

This appends new entries to the existing `sigmund.yaml` file, preserving all existing content including comments and formatting. New signers are added to the `signers` section, new trust patterns to the `trust` section, and artifacts found without a signature to the `signature-optional` section.

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
