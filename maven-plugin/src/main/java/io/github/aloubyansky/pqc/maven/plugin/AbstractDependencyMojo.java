package io.github.aloubyansky.pqc.maven.plugin;

import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import javax.inject.Inject;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResolutionException;
import org.eclipse.aether.resolution.ArtifactResult;

/**
 * Base class for Mojos that iterate over project dependencies and inspect their signatures.
 */
abstract class AbstractDependencyMojo extends AbstractMojo {

    static final Comparator<Artifact> ARTIFACT_ORDER = Comparator
            .comparing(Artifact::getGroupId)
            .thenComparing(Artifact::getArtifactId)
            .thenComparing(Artifact::getVersion);

    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    protected MavenProject project;

    @Inject
    protected RepositorySystem repoSystem;

    @Parameter(defaultValue = "${repositorySystemSession}", readonly = true)
    protected RepositorySystemSession repoSession;

    @Parameter(defaultValue = "${project.remoteProjectRepositories}", readonly = true)
    protected List<RemoteRepository> remoteRepos;

    @Parameter(property = "pqc.includeTestDependencies", defaultValue = "false")
    protected boolean includeTestDependencies;

    @Parameter(property = "pqc.skip", defaultValue = "false")
    protected boolean skip;

    Set<Artifact> resolveDependencies() {
        Set<Artifact> artifacts = project.getArtifacts();
        if (!includeTestDependencies) {
            artifacts = artifacts.stream()
                    .filter(a -> !Artifact.SCOPE_TEST.equals(a.getScope()))
                    .collect(Collectors.toCollection(() -> new TreeSet<>(ARTIFACT_ORDER)));
        } else {
            TreeSet<Artifact> sorted = new TreeSet<>(ARTIFACT_ORDER);
            sorted.addAll(artifacts);
            artifacts = sorted;
        }
        return artifacts;
    }

    /**
     * Downloads the .asc signature file for the given artifact from the specified repositories.
     *
     * @return the resolved artifact result, or null if no signature was found
     */
    protected ArtifactResult resolveSignature(Artifact artifact, List<RemoteRepository> repos) {
        try {
            org.eclipse.aether.artifact.Artifact aetherArtifact = new DefaultArtifact(
                    artifact.getGroupId(),
                    artifact.getArtifactId(),
                    artifact.getClassifier(),
                    artifact.getType() + ".asc",
                    artifact.getVersion());
            ArtifactRequest request = new ArtifactRequest(aetherArtifact, repos, null);
            return repoSystem.resolveArtifact(repoSession, request);
        } catch (ArtifactResolutionException e) {
            getLog().debug("No .asc signature found for " + artifact);
            return null;
        }
    }

    Path downloadSignature(Artifact artifact) {
        ArtifactResult result = resolveSignature(artifact, remoteRepos);
        return result != null ? result.getArtifact().getFile().toPath() : null;
    }
}
