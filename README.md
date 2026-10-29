# Sigmund — Artifact Signing and Trust Verification for Maven

A Maven plugin and CLI for signing artifacts, verifying signatures, and enforcing dependency trust policies. Supports classic OpenPGP (GPG or pure-Java Bouncy Castle), post-quantum hybrid signing (RFC 9980 via Sequoia), and Sigstore keyless signing.

## Overview

Sigmund is a general-purpose signing and trust verification tool for Maven that brings dependency signature verification to the Maven ecosystem — a capability no other tool provides. It can verify who signed each dependency in your project and enforce trust policies based on signer identity, giving you visibility into and control over your software supply chain.

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

Signer: NOT VERIFIED
   PGP4 (RSA): B2A3CF1E8D4F5A6B7C9D0E1F2A3B4C5D6E7F8A9B
     com.other:tool:3.0

Signer: UNKNOWN (key not in keyring)
   PGP4 (DSA): D1031D14464180E0
     com.internal:messaging:2.1

UNSIGNED
  com.internal:util:1.0

Summary: All clear: 4 dependencies, 3 PGP4 signature(s), 0 PQC signature(s), 2 unique key(s)
```

Many signers appear as `NOT VERIFIED` because `keys.openpgp.org` (the default keyserver) only publishes identity information for keys whose owners have verified their email. See the [Getting Started guide](docs/getting-started.md#why-many-signers-appear-as-not-verified) for details on resolving signer names.

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

- **Dependency signature verification and trust enforcement** — Verify signatures on all project dependencies and enforce policies based on signer identity. No alternative tool offers this capability today.
- **Drop-in replacement for maven-gpg-plugin** — Use existing GPG keys or Bouncy Castle's pure-Java backend for classic OpenPGP with no external dependencies.
- **Sigstore keyless signing** — OIDC-based signing with no long-lived keys to generate, store, or rotate. Produces `.sigstore.json` bundles. Identity-validated: configure expected OIDC identities and catch mismatches before artifacts are signed. CI-tuned defaults (ambient GitHub Actions OIDC, no browser popups).
- **Hybrid PQC + classic signing** — ML-DSA-87+Ed448 and Ed25519/RSA in one `.asc` file (RFC 9980). Existing tools see only the classic signature; PQC-aware tools verify both.
- **Multi-format signing** — Produce both `.asc` (OpenPGP) and `.sigstore.json` (Sigstore) in a single build. Cross-backend identity matching lets a signer configured with just an `email` credential match both OpenPGP and Sigstore signatures.
- **Four signing backends** — BC (pure Java, always available), Sequoia sq (PQC support), GnuPG (legacy compatibility), and Sigstore (keyless OIDC). Configurable priority and toolchain selection.
- **CLI for key management and custom workflows** — Generate keys, sign artifacts, verify signatures, and export certificates outside Maven.

## Quick Signing Example

Sign your Maven artifacts with GPG, Bouncy Castle, or both. First, check which signing keys are configured:

```bash
mvn sigmund:signer-info
```

```
gpg: RSA 41A2197725BD63EB00D071D46A7F5DB1C68BDB81 (Alice <alice@example.com>)
```

The `sign` goal is bound to the `verify` phase for release profiles, but you can run it directly:

```bash
mvn sigmund:sign
```

The plugin uses GPG by default if available, falling back to the Bouncy Castle backend. Configure a specific signing key in `sigmund.yaml`:

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
- [Architecture Overview](docs/architecture.md) — Three-tool system and key management
- [Known Limitations](docs/limitations.md) — Current limitations and workarounds

## Project Status

**Version:** 0.0.2
**License:** Apache License 2.0  
**Issues:** [GitHub Issues](https://github.com/cyberstamp/sigmund/issues)

This is an early-stage project under active development. The API and configuration format may change before the 1.0 release.
