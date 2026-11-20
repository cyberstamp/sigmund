# Sigmund Resolver Connector

Verifies every artifact Maven downloads from a remote repository against the Sigmund trust
policy in `sigmund.yaml`, before it reaches the local repository. An artifact whose outcome
blocks fails resolution with a `SigmundVerificationException`, and its file is deleted.

**Maven 3.10 or later only** (Maven 4 included), on Java 17. The extension is built on Maven
Resolver 2 pipeline connectors (Resolver 2.0.8+), which Maven 3.9 and older do not have: it does
not work with Maven 3.9 or older, and will not. See
[ADR-010](../adr/010-resolution-time-verification-in-a-pipeline-connector.md).

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
-Dsigmund.generateTrustConfig=true` writes one for the project's dependencies. That file has no
rules for the build's plugins, which the extension verifies too, so until it does, let them
through with a warning:

```yaml
defaults:
  on-not-configured: warn
```

Then turn verification on:

```bash
mvn -Dsigmund.resolver.verify.enabled=true verify
```

## Configuration

Set as user properties (`-D…` or `.mvn/maven.config`):

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `sigmund.resolver.verify.enabled` | Boolean | `false` | Verify downloaded artifacts. |
| `sigmund.resolver.config` | String | unset | Path of the `sigmund.yaml` to use. Unset, it is `sigmund.yaml` in the build's root directory (the one holding `.mvn`), then the user config (`~/.config/sigmund/sigmund.yaml`). |
| `sigmund.resolver.sign.enabled` | Boolean | `false` | Reserved for signing on deploy; signing is not implemented yet. |

A `sigmund.yaml` that cannot be loaded fails the build; it never disables verification. The
file in use is logged at INFO. When none is found, a warning says so, and verification only
observes (see below).

## How it decides

For each artifact download the extension also fetches its signature sidecars (`.asc`, …) to
their place next to the artifact in the local repository, then hands the artifact and sidecars
to Sigmund. The policy's enforcement for the outcome decides: `fail` blocks the artifact, `warn`
lets it through with a warning, `ignore` lets it through (logged at debug). See
[the configuration reference](../docs/configuration.md#how-enforcement-is-resolved).

A blocked artifact's error names the outcome, its reason, the rule that decided and the
evidence read, for example `org.example:lib:1.0 FAILED, action FAIL, rules[0]
'org.example:*'; evidence lib-1.0.jar.asc sha256:…`.

- **Every download is judged, including plugins, their dependencies and POMs.** With `rules`, an
  artifact no rule matches is `NOT_CONFIGURED`, which fails by default. Add a catch-all rule, or
  set `defaults: on-not-configured: warn` while the policy grows.
- **A missing signature is no claim**, which `on-no-claim` judges (`fail` by default with a
  policy). Any other failure to fetch a signature — a timeout, a server error — fails the
  artifact, so a network fault cannot turn a required signature into "unsigned".
- **Without `rules`** there is no policy: verification observes, and only a signature that does
  not match its bytes (`FAILED`) blocks.
- Existence checks and explicit requests for a signature file pass through unverified.
- An artifact that passes keeps its signatures next to it in the local repository, registered
  like any downloaded artifact, so later requests for them are served locally.
- A blocked artifact, or one that could not be verified, is deleted together with its
  signatures, so no unverified file stays in the local repository.

## Limits

- **Only remote downloads are verified.** An artifact already in the local repository is not
  re-verified when a build uses it; start from an empty local repository to verify everything.
  Verifying local hits against the stored signatures is a follow-up (an
  `ArtifactResolverPostProcessor`).
- **The extension's own dependencies are not verified**: Maven resolves them before the
  extension is active.
- Verification of parallel downloads is serialized.
