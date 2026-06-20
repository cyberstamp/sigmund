package io.github.aloubyansky.sigmund.plugin;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.inject.Inject;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.collection.CollectRequest;
import org.eclipse.aether.graph.Dependency;
import org.eclipse.aether.graph.DependencyNode;
import org.eclipse.aether.graph.Exclusion;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.resolution.DependencyRequest;
import org.eclipse.aether.resolution.DependencyResolutionException;

/**
 * Base class for Mojos that iterate over project dependencies and inspect their signatures.
 */
abstract class AbstractDependencyMojo extends AbstractMojo {

    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    protected MavenProject project;

    @Inject
    protected RepositorySystem repoSystem;

    @Parameter(defaultValue = "${repositorySystemSession}", readonly = true)
    protected RepositorySystemSession repoSession;

    @Parameter(defaultValue = "${project.remoteProjectRepositories}", readonly = true)
    protected List<RemoteRepository> remoteRepos;

    @Parameter(property = "sigmund.trustConfig", defaultValue = "${project.basedir}/trust-config.yaml")
    protected File trustConfigFile;

    @Parameter(property = "sigmund.fetchSignerInfo")
    protected Boolean fetchSignerInfo;

    @Parameter(property = "sigmund.keyservers", defaultValue = "hkps://keyserver.ubuntu.com,hkps://keys.openpgp.org")
    protected String keyservers;

    @Parameter(property = "sigmund.sqHome")
    protected File sqHome;

    @Parameter(property = "sigmund.includeTestDependencies", defaultValue = "false")
    protected boolean includeTestDependencies;

    @Parameter(property = "sigmund.skip", defaultValue = "false")
    protected boolean skip;

    List<ArtifactCoords> resolveDependencies() throws MojoExecutionException {
        CollectRequest collectRequest = new CollectRequest();
        collectRequest.setRepositories(remoteRepos);
        collectRequest.setRootArtifact(new DefaultArtifact(
                project.getGroupId(), project.getArtifactId(), null, "pom", project.getVersion()));

        for (org.apache.maven.model.Dependency dep : project.getDependencies()) {
            if (!includeTestDependencies && Artifact.SCOPE_TEST.equals(dep.getScope())) {
                continue;
            }
            collectRequest.addDependency(toAetherDependency(dep));
        }

        if (project.getDependencyManagement() != null) {
            for (org.apache.maven.model.Dependency dep : project.getDependencyManagement().getDependencies()) {
                collectRequest.addManagedDependency(toAetherDependency(dep));
            }
        }

        DependencyRequest request = new DependencyRequest(collectRequest, null);
        DependencyNode root;
        try {
            root = repoSystem.resolveDependencies(repoSession, request).getRoot();
        } catch (DependencyResolutionException e) {
            throw new MojoExecutionException("Failed to resolve dependencies", e);
        }

        List<ArtifactCoords> artifacts = new ArrayList<>();
        collectArtifacts(root, artifacts);
        return artifacts;
    }

    private void collectArtifacts(DependencyNode node, List<ArtifactCoords> artifacts) {
        if (node.getDependency() != null) {
            org.eclipse.aether.artifact.Artifact a = node.getArtifact();
            if (a != null && a.getFile() != null) {
                artifacts.add(new ArtifactCoords(
                        a.getGroupId(), a.getArtifactId(),
                        a.getClassifier() != null ? a.getClassifier() : "",
                        a.getExtension(), a.getVersion()));
            }
        }
        for (DependencyNode child : node.getChildren()) {
            collectArtifacts(child, artifacts);
        }
    }

    private Dependency toAetherDependency(org.apache.maven.model.Dependency dep) {
        DefaultArtifact artifact = new DefaultArtifact(
                dep.getGroupId(), dep.getArtifactId(),
                dep.getClassifier() != null ? dep.getClassifier() : "",
                dep.getType() != null ? dep.getType() : "jar",
                dep.getVersion());
        List<Exclusion> exclusions = new ArrayList<>();
        if (dep.getExclusions() != null) {
            for (org.apache.maven.model.Exclusion e : dep.getExclusions()) {
                exclusions.add(new Exclusion(
                        e.getGroupId() != null ? e.getGroupId() : "*",
                        e.getArtifactId() != null ? e.getArtifactId() : "*",
                        "*", "*"));
            }
        }
        return new Dependency(artifact, dep.getScope(), "true".equals(dep.getOptional()), exclusions);
    }

    /**
     * Loads and parses the trust configuration file. Returns {@code null} if the
     * file does not exist.
     */
    protected TrustConfig loadTrustConfig() throws MojoExecutionException {
        if (trustConfigFile == null || !trustConfigFile.exists()) {
            return null;
        }
        try {
            return TrustConfigParser.parse(trustConfigFile.toPath());
        } catch (IOException e) {
            throw new MojoExecutionException("Failed to parse trust configuration", e);
        } catch (IllegalArgumentException e) {
            throw new MojoExecutionException(e.getMessage(), e);
        }
    }

    /**
     * Merges the Mojo {@code fetchSignerInfo} and {@code keyservers} parameters with
     * settings from the trust config file. If {@code fetchSignerInfo} is not explicitly
     * set, the config file value (or default {@code true}) is used. When fetching is
     * enabled but the config provides no keyservers, the Mojo default keyservers are used.
     */
    protected TrustConfig.Settings resolveSettings(TrustConfig.Settings fileSettings) {
        boolean effectiveFetch = fetchSignerInfo != null
                ? fetchSignerInfo
                : fileSettings.fetchSignerInfo();
        List<String> effectiveKeyservers = fileSettings.keyservers();
        if (effectiveFetch && effectiveKeyservers.isEmpty()) {
            effectiveKeyservers = SignatureInspector.parseKeyservers(keyservers);
        }
        return new TrustConfig.Settings(
                effectiveKeyservers, fileSettings.onUntrusted(),
                fileSettings.verifyAllSignatures(), effectiveFetch);
    }

    /**
     * Builds a {@link SignatureInspector} configured with keyservers according to the
     * given settings.
     */
    protected SignatureInspector buildInspector(TrustConfig.Settings settings)
            throws MojoExecutionException {
        var builder = SignatureInspector.builder()
                .log(getLog())
                .repoSystem(repoSystem).repoSession(repoSession).remoteRepos(remoteRepos)
                .sqHome(sqHome);
        if (settings.fetchSignerInfo()) {
            for (String server : settings.keyservers()) {
                builder.addKeyServer(server);
            }
        }
        return builder.build();
    }
}
