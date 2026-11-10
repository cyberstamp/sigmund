package dev.cyberstamp.sigmund.plugin;

import dev.cyberstamp.sigmund.core.ArtifactCoords;
import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.ToolsConfig;
import dev.cyberstamp.sigmund.core.VerificationConfig;
import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import javax.inject.Inject;
import org.apache.maven.artifact.Artifact;
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
abstract class AbstractDependencyMojo extends AbstractSigmundMojo {

    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    protected MavenProject project;

    @Inject
    protected RepositorySystem repoSystem;

    @Parameter(defaultValue = "${repositorySystemSession}", readonly = true)
    protected RepositorySystemSession repoSession;

    @Parameter(defaultValue = "${project.remoteProjectRepositories}", readonly = true)
    protected List<RemoteRepository> remoteRepos;

    @Parameter(property = "sigmund.trustConfig", defaultValue = "${project.basedir}/sigmund.yaml")
    protected File trustConfigFile;

    @Parameter(property = "sigmund.resolveSigners")
    protected Boolean resolveSigners;

    @Parameter(property = "sigmund.keyservers")
    protected String keyservers;

    @Parameter(property = "sigmund.includeTestDependencies", defaultValue = "false")
    protected boolean includeTestDependencies;

    @Parameter(property = "sigmund.importToKeyring")
    protected Boolean importToKeyring;

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
     * Loads the project's policy file: the file {@link #trustConfigFile} names, or
     * {@code sigmund.yaml} in the project directory.
     *
     * <p>
     * A missing file at the default location means the project has not written one. A missing
     * file at a location given explicitly is an error instead: a mistyped path must not quietly
     * run the goal as if the project had no configuration.
     *
     * @return the configuration, or {@code null} when there is no file at the default location
     * @throws MojoExecutionException when an explicitly given file does not exist or does not
     *         parse
     */
    @Override
    protected SigmundConfig loadConfig() throws MojoExecutionException {
        if (trustConfigFile == null || !trustConfigFile.exists()) {
            if (!isDefaultConfigLocation()) {
                throw new MojoExecutionException("Config file not found at "
                        + Path.of("").toAbsolutePath()
                                .relativize(trustConfigFile.toPath().toAbsolutePath()));
            }
            return null;
        }
        try {
            return SigmundConfig.parse(trustConfigFile.toPath());
        } catch (Exception e) {
            throw new MojoExecutionException("Failed to parse config: " + trustConfigFile, e);
        }
    }

    private boolean isDefaultConfigLocation() {
        if (trustConfigFile == null || project == null || project.getBasedir() == null) {
            return true;
        }
        File defaultLocation = new File(project.getBasedir(), "sigmund.yaml");
        return trustConfigFile.getAbsoluteFile().equals(defaultLocation.getAbsoluteFile());
    }

    /**
     * Resolves the verification config using field-level overrides from the mojo parameters.
     *
     * @param fileConfig the base verification configuration from the config file
     * @return the resolved verification configuration
     */
    protected VerificationConfig resolveVerificationConfig(VerificationConfig fileConfig) {
        return resolveVerificationConfig(fileConfig, resolveSigners, keyservers, importToKeyring);
    }

    /**
     * Builds a {@link SignatureInspector} with the given verification and tools configurations.
     *
     * @param verificationConfig the resolved verification configuration
     * @param toolsConfig the resolved tools configuration
     * @return the configured signature inspector
     * @throws MojoExecutionException if construction fails
     */
    protected SignatureInspector buildInspector(VerificationConfig verificationConfig, ToolsConfig toolsConfig)
            throws MojoExecutionException {
        Sigmund sigmund = buildSigmund(verificationConfig, toolsConfig);
        return SignatureInspector.builder()
                .log(getLog())
                .sigmund(sigmund)
                .repoSystem(repoSystem).repoSession(repoSession).remoteRepos(remoteRepos)
                .sqHome(sqHome)
                .build();
    }
}
