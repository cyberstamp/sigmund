# ADR-010: Resolution-Time Verification in a Resolver Pipeline Connector

## Status

Proposed.

## Context

Design direction §2 places verification at resolution time, because build plugins and extensions
execute before any goal can check them. It leaves the hook open between a `RepositoryListener`,
a wrapped resolver component and an `ArtifactResolverPostProcessor`, and roadmap P5.1 asks for
that choice to be settled before the extension is built on it.

Maven Resolver 2.0.8 added pipeline repository connectors: a `PipelineRepositoryConnectorFactory`
contributed by an extension wraps the connector that transfers artifacts from one remote
repository, ordered by priority. Maven 3.10 and Maven 4 ship Resolver 2; Maven 3.9 and older ship
Resolver 1.x, which has no pipeline connectors.

The forces:

- **Blocking must be clean.** A failure has to fail resolution with an error naming the artifact,
  not depend on how Maven handles an exception from a callback.
- **Coverage must include build tooling.** Plugin, extension and POM downloads matter most.
- **Evidence must not re-enter verification** (§2, re-entrancy): fetching an `.asc` must not be
  verified as an artifact in its own right.
- **A network fault must not downgrade a requirement.** A signature that could not be fetched is
  not the same as a signature that does not exist.

## Decision

Sigmund verifies downloads in a pipeline repository connector, shipped as the
`sigmund-resolver-connector` extension, which requires Maven Resolver 2.0.8 or later and so
Maven 3.10 or later.

- The connector wraps the transferring connector (priority 20000, inside the offline and
  remote-repository-filtering connectors), so it sees exactly what is fetched from a remote
  repository.
- For each artifact it requests the signature sidecars of the configured tools in the same
  transfer batch, stored next to the artifact in the local repository. Sidecars are fetched by
  the connector, not resolved through the resolver, so they do not re-enter verification; an
  explicit request for a sidecar passes through unverified.
- A missing sidecar (not found) is no claim, which the policy judges; any other sidecar transfer
  failure fails the artifact.
- An artifact whose outcome the policy blocks, or that could not be verified, fails its download
  with a transfer exception; its file and sidecars are deleted. An artifact that passes keeps its
  sidecars, registered with the local repository manager.

## Alternatives

- **`RepositoryListener`.** Notification, not interception: an artifact is already in place when
  the listener hears of it, and failing from a callback does not reliably abort resolution.
  Rejected.
- **`ArtifactResolverPostProcessor`.** Runs after resolution, on local-repository hits as well as
  downloads, and fails resolution cleanly. But the artifact is already installed in the local
  repository when it runs, and it would have to resolve the sidecars itself, through the
  resolver it is part of. Rejected as the first hook; kept as the way to re-verify local hits
  (see Consequences), which the sidecars this decision keeps make possible.
- **Wrapping a resolver component** (`ArtifactResolver`). Replaces a core component rather than
  adding one, collides with any other extension doing the same, and has to reimplement the
  bookkeeping around transfers. Rejected.
- **Sidecars in a temporary directory, discarded after verification.** Keeps the local
  repository free of signatures, but leaves nothing to re-verify a local hit against and makes
  every later tool fetch the signature again. Rejected.
- **Supporting Maven 3.9.** Would need one of the rejected hooks for Resolver 1.x. Rejected: the
  extension is Maven 3.10+ only.

## Consequences

- An artifact already in the local repository is not verified again when a build uses it. Closing
  that needs an `ArtifactResolverPostProcessor` checking local hits against the stored sidecars.
- The extension's own dependencies resolve before it is active and are not verified.
- Every download is judged, build tooling and POMs included. With `rules`, an artifact no rule
  matches is `NOT_CONFIGURED`, which fails by default, so a policy has to cover the build's
  plugins too.
- Each artifact costs one extra request per configured signature format, in the same parallel
  batch.
- A repository that answers a missing sidecar with an error other than not-found fails the
  artifact.
- Maven 3.9 and older are not supported, and will not be.
