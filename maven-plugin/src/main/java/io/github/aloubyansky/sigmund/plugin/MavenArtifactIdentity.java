package io.github.aloubyansky.sigmund.plugin;

import io.github.aloubyansky.sigmund.core.ArtifactIdentity;

/**
 * Maven-specific implementation of {@link ArtifactIdentity}.
 *
 * @param namespace the groupId
 * @param name the artifactId
 * @param version the version
 */
record MavenArtifactIdentity(String namespace, String name, String version)
        implements
            ArtifactIdentity {

    static MavenArtifactIdentity from(ArtifactCoords coords) {
        return new MavenArtifactIdentity(coords.groupId(), coords.artifactId(), coords.version());
    }
}
