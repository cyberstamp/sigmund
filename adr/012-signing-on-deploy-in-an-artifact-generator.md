# ADR-012: Signing on Deploy in a Resolver Artifact Generator

## Status

Proposed.

## Context

Sigmund signs through the `sigmund:sign` goal and the CLI. A goal has to be bound in every
project that deploys, runs before deploy whether or not anything is deployed, and attaches its
signatures by the project model. Maven Resolver 2 offers `ArtifactGenerator`s: components that,
given the artifacts of an install or deploy request, contribute more artifacts to it — the hook
Resolver's own GnuPG and Sigstore signers use. The resolver extension (ADR-010) already loads
Sigmund and locates `sigmund.yaml` on Maven 3.10 and later.

## Decision

The `sigmund-resolver-connector` extension signs in an `ArtifactGeneratorFactory`, enabled by
`sigmund.resolver.sign.enabled`:

- It signs deploy requests only, never installs: a signature is for what others consume.
- It signs each artifact that gets checksums, with the signer `sigmund.yaml`'s `signing` and
  `tools` sections configure — the same signer as the goal and the CLI, a named profile
  included — and deploys each signature file as a sub-artifact beside its artifact.
- It runs first among generators (priority 20000) and signs nothing when the request already
  holds signatures, so a build that attaches its own keeps them.
- It reads `sigmund.yaml` without compiling the policy (§ "Signing never compiles the policy").

## Alternatives

- **Only the `sigmund:sign` goal.** Kept, but it needs binding per project and cannot see what is
  actually deployed. Rejected as the only way.
- **Signing installs too.** Puts signatures into local repositories nobody consumes from, and
  needs the key on every developer machine. Rejected.
- **Running after Resolver's GnuPG generator and backing off on its signatures.** A configured
  GnuPG signer would win silently over the configured Sigmund signer. Rejected: Sigmund signs
  first, and the other generators back off on its `.asc`.

## Consequences

- Deploy-time signing needs no plugin configuration in the project; Maven 3.9 and older are not
  supported.
- A signing failure fails the deploy, before anything is uploaded.
- A protected key's passphrase is found as for the goal: an environment variable, else a console
  prompt, which an unattended build does not have.
- The signer's tool selection is shared with the goal and the CLI through
  `Sigmund.Builder.addSigningTools`.
