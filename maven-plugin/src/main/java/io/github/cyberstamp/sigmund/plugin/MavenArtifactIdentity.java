package io.github.cyberstamp.sigmund.plugin;

import io.github.cyberstamp.sigmund.core.ArtifactIdentity;

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
