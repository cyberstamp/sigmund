# Sigmund — Artifact Signing and Trust Verification for Maven

A Maven plugin and CLI for signing artifacts, verifying signatures, and enforcing dependency trust policies. Supports classic OpenPGP (GPG or pure-Java Bouncy Castle), post-quantum hybrid signing (RFC 9980 via Sequoia), and Sigstore keyless signing.

## Overview

Sigmund is a signing and trust verification tool for Maven. It verifies who signed each dependency against a policy of trusted signers — keys, verified email addresses or CI workflow identities, across OpenPGP and Sigstore — and can generate that policy from the signatures your dependencies already carry, giving you visibility into and control over your software supply chain.

Sigmund is also a drop-in replacement for `maven-gpg-plugin` and `sigstore-maven-plugin`. It supports hybrid post-quantum cryptography (PQC) — `.asc` files containing both a classic signature (RSA/EdDSA) and a PQC v6 signature (ML-DSA-87+Ed448 via Sequoia, RFC 9980). A pure-Java Bouncy Castle backend handles classic OpenPGP with zero external tool dependencies. The Sigstore backend provides keyless signing via OIDC — no long-lived keys to manage — producing `.sigstore.json` bundles alongside or instead of OpenPGP signatures.

## Try It Now

See who signed your dependencies — no POM changes required, just copy-paste into any Maven project:

```bash
mvn dev.cyberstamp.sigmund:sigmund-maven-plugin:0.0.2:dependency-signers
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

In most projects some signers appear as `UNKNOWN (key unavailable)`, with the reason on the key line — most often that `keys.openpgp.org`, the default keyserver, served the key without its user IDs, which it publishes only once the key's owner verifies an email address. See the [Getting Started guide](docs/getting-started.md#why-some-signers-appear-as-unknown) for what each reason means and how to resolve more keys.

To shorten subsequent commands, add the plugin to your `pluginManagement`:

```xml
<build>
  <pluginManagement>
    <plugins>
      <plugin>
        <groupId>dev.cyberstamp.sigmund</groupId>
        <artifactId>sigmund-maven-plugin</artifactId>
        <version>0.0.2</version>
      </plugin>
    </plugins>
  </pluginManagement>
</build>
```

Now you can use the `sigmund` prefix:

```bash
mvn sigmund:dependency-signers
```

Generate an initial trust config from your project's actual signatures:

```bash
mvn sigmund:dependency-signers -Dsigmund.generateTrustConfig=true
```

Then enforce trust policies:

```bash
mvn sigmund:verify
```

## Key Features

- **Dependency signature verification and trust enforcement** — Verify signatures on all project dependencies and enforce policies based on who signed them. Start by observing, then enforce once the policy matches what you expect.
- **Drop-in replacement for maven-gpg-plugin** — Use existing GPG keys or Bouncy Castle's pure-Java backend for classic OpenPGP with no external dependencies.
- **Sigstore keyless signing** — OIDC-based signing with no long-lived keys to generate, store, or rotate. Produces `.sigstore.json` bundles. Identity-validated: configure expected OIDC identities and catch mismatches before artifacts are signed. CI-tuned defaults (ambient GitHub Actions OIDC, no browser popups).
- **Hybrid PQC + classic signing** — ML-DSA-87+Ed448 and Ed25519/RSA in one `.asc` file (RFC 9980). Existing tools see only the classic signature; PQC-aware tools verify both.
- **Multi-format signing** — Produce both `.asc` (OpenPGP) and `.sigstore.json` (Sigstore) in a single build. Cross-backend identity matching lets one `email` entry match both OpenPGP and Sigstore signatures, vouched for by the issuers you list — keys.openpgp.org for OpenPGP, an OIDC provider for Sigstore.
- **Four signing backends** — BC (pure Java, always available), Sequoia sq (PQC support), GnuPG (legacy compatibility), and Sigstore (keyless OIDC). The toolchain chooses which tools run, and in what order.
- **CLI for key management and custom workflows** — Generate keys, sign artifacts, verify signatures, and export certificates outside Maven.

## Quick Signing Example

Sign your Maven artifacts with GPG, Bouncy Castle, or both. First, check which signing keys are configured:

```bash
mvn sigmund:signer-info
```

```
gpg: pgp4 RSA 41A2197725BD63EB00D071D46A7F5DB1C68BDB81 (Alice <alice@example.com>)
```

The `sign` goal runs in the `verify` phase when added to your build's plugins, or directly:

```bash
mvn sigmund:sign
```

Without configuration, every installed tool that has a default signing key signs: in practice GnuPG's default key, plus Sequoia's if its configuration names one. Bouncy Castle signs only when given a key — in `sigmund.yaml`, or through `SIGMUND_BC_SIGNING_KEY` for [ephemeral CI signing](docs/signing.md#ephemeral-ci-signing), where it signs alone unless `signing.toolchain` names the tools. List tools under `signing.toolchain` to choose exactly which ones sign.

Configure a specific signing key in `sigmund.yaml`:

```yaml
tools:
  gpg:
    signing-fingerprint: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
```

Or use a BC-generated key:

```yaml
tools:
  bc:
    signing-fingerprint: "ABCDEF1234567890ABCDEF1234567890ABCDEF12"
```

For hybrid PQC signing, generate a PQC key with Sequoia and add it to the config:

```bash
sq key generate --own-key --userid "Your Name <you@example.com>" --cipher-suite mldsa87-ed448 --profile rfc9580
```

Then configure both classic and PQC in `sigmund.yaml`:

```yaml
tools:
  gpg:
    signing-fingerprint: "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12"
  sq:
    signing-fingerprint: "D62AAB339E45E5EA2FD036872B01D46A517A29911A2B3C4D5E6F7A8B9C0D1E2F"
```

Run `mvn sigmund:sign` to sign with both — classic signature first, PQC signature second, combined in one `.asc` file.

## Documentation

- [Getting Started](docs/getting-started.md) — Quick start guide for dependency trust verification
- [Migration from maven-gpg-plugin](docs/migrating-from-gpg-plugin.md) — How to migrate from maven-gpg-plugin
- [Migration from sign-maven-plugin](docs/migrating-from-sign-maven-plugin.md) — How to migrate from sign-maven-plugin (s4u)
- [Migration from sigstore-maven-plugin](docs/migrating-from-sigstore-maven-plugin.md) — How to migrate from sigstore-maven-plugin
- [Signing Guide](docs/signing.md) — Signing artifacts with GPG, BC, or hybrid PQC
- [Signature Verification](docs/verification.md) — How signature verification works
- [Trust Verification](docs/trust-verification.md) — Enforcing dependency trust policies
- [Maven Plugin Reference](docs/maven-plugin.md) — Complete plugin goal and configuration reference
- [CLI Reference](docs/cli-reference.md) — Command-line tool usage
- [Configuration Reference](docs/configuration.md) — `sigmund.yaml` configuration options
- [Architecture Overview](docs/architecture.md) — Tools, key stores and the signing and verification pipelines
- [Known Limitations](docs/limitations.md) — Current limitations and workarounds

## Project Status

**Version:** 0.0.2
**License:** Apache License 2.0  
**Issues:** [GitHub Issues](https://github.com/cyberstamp/sigmund/issues)

This is an early-stage project under active development. The API and configuration format may change before the 1.0 release.
