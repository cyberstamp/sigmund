# Sigmund Resolver Connector

Verifies every artifact Maven resolves against the Sigmund trust policy in `sigmund.yaml`:
downloads before they reach the local repository, and artifacts served from the local repository
before a build uses them. An artifact whose outcome blocks fails resolution with a
`SigmundVerificationException`.

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

Two components share one check:

- **The repository connector** verifies downloads. For each artifact it also fetches the
  signature sidecars (`.asc`, …) to their place next to the artifact in the local repository.
- **The artifact resolver post-processor** verifies what resolution returns from the local
  repository, against the signatures stored next to it. A file the connector verified in the
  same build is not checked again; neither are the build's own modules.

Either way the artifact and its signatures go to Sigmund. The policy's enforcement for the outcome decides: `fail` blocks the artifact, `warn`
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
- A blocked download, or one that could not be verified, is deleted together with its
  signatures, so no unverified file stays in the local repository.
- A blocked artifact from the local repository fails resolution but stays where it is: it was
  there before, and the policy may be what changed.
- Artifacts installed locally (`mvn install`) are judged like any other: unsigned, they are no
  claim.

## Limits

- **Signatures are not fetched for cached artifacts.** An artifact cached before verification
  was enabled has no signature next to it and is no claim, which fails by default under a
  policy. Delete such artifacts from the local repository (or start from an empty one) so they
  are downloaded again with their signatures. Fetching them from the post-processor would
  re-enter resolution while it holds the artifacts' locks.
- **The extension's own dependencies are not verified**: Maven resolves them before the
  extension is active.
- Verification of parallel downloads is serialized.
