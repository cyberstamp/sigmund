# Sigmund Resolver Connector

Verifies every artifact Maven downloads from a remote repository against the Sigmund trust
policy in `sigmund.yaml`, before it reaches the local repository. An artifact whose outcome
blocks fails resolution with a `SigmundVerificationException`, and its file is deleted.

Requires Maven Resolver 2.0.8 or later (Maven 3.10 or Maven 4) and Java 17.

## Setup

Add the extension to the project's `.mvn/extensions.xml`:

```xml
<extensions>
  <extension>
    <groupId>dev.cyberstamp.sigmund</groupId>
    <artifactId>sigmund-resolver-connector</artifactId>
    <version>${sigmund.version}</version>
  </extension>
</extensions>
```

Put a `sigmund.yaml` in the project root — `mvn sigmund:dependency-signers
-Dsigmund.generateTrustConfig=true` writes one for the project's dependencies — and turn
verification on:

```bash
mvn -Dsigmund.resolver.verify.enabled=true verify
```

## Configuration

Set as user properties (`-D…` or `.mvn/maven.config`):

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `sigmund.resolver.verify.enabled` | Boolean | `false` | Verify downloaded artifacts. |
| `sigmund.resolver.config` | String | unset | Path of the `sigmund.yaml` to use. Unset, it is located from `maven.multiModuleProjectDirectory`, then the user config (`~/.config/sigmund/sigmund.yaml`). |
| `sigmund.resolver.sign.enabled` | Boolean | `false` | Reserved for signing on deploy; signing is not implemented yet. |

A `sigmund.yaml` that cannot be loaded fails the build; it never disables verification.

## How it decides

For each artifact download the extension also fetches its signature sidecars (`.asc`, …) into
a temporary directory, then hands the artifact and sidecars to Sigmund. The policy's enforcement
for the outcome decides: `fail` blocks the artifact, `warn` logs it, `ignore` lets it through.
See [the configuration reference](../docs/configuration.md#how-enforcement-is-resolved).

- **Every download is judged, including plugins, their dependencies and POMs.** With `rules`, an
  artifact no rule matches is `NOT_CONFIGURED`, which fails by default. Add a catch-all rule, or
  set `defaults: on-not-configured: warn` while the policy grows.
- **A missing signature is no claim**, which `on-no-claim` judges (`fail` by default with a
  policy). Any other failure to fetch a signature — a timeout, a server error — fails the
  artifact, so a network fault cannot turn a required signature into "unsigned".
- **Without `rules`** there is no policy: verification observes, and only a signature that does
  not match its bytes (`FAILED`) blocks.
- Existence checks and explicit requests for a signature file pass through unverified.
- Signatures are not kept in the local repository.

## Limits

- **Only remote downloads are verified.** An artifact already in the local repository is not
  re-verified when a build uses it; start from an empty local repository to verify everything.
  Verifying cache hits is a follow-up (an `ArtifactResolverPostProcessor`, which needs the
  signatures kept next to the artifacts).
- **The extension's own dependencies are not verified**: Maven resolves them before the
  extension is active.
- Verification of parallel downloads is serialized.
