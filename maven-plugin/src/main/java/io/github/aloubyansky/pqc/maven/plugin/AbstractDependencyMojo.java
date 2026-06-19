package io.github.aloubyansky.pqc.maven.plugin;

import java.io.File;
import java.io.IOException;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import javax.inject.Inject;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.repository.RemoteRepository;

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

    @Parameter(property = "pqc.trustConfig", defaultValue = "${project.basedir}/trust-config.yaml")
    protected File trustConfigFile;

    @Parameter(property = "pqc.fetchSignerInfo")
    protected Boolean fetchSignerInfo;

    @Parameter(property = "pqc.keyservers", defaultValue = "hkps://keyserver.ubuntu.com,hkps://keys.openpgp.org")
    protected String keyservers;

    @Parameter(property = "pqc.sqHome")
    protected File sqHome;

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
