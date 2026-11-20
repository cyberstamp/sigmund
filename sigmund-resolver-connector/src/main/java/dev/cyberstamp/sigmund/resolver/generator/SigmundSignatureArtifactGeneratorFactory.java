package dev.cyberstamp.sigmund.resolver.generator;

import dev.cyberstamp.sigmund.core.ConfigLoader;
import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.Signer;
import dev.cyberstamp.sigmund.resolver.SessionConfig;
import dev.cyberstamp.sigmund.resolver.SigmundConfigurationKeys;
import java.nio.file.Path;
import java.util.function.Supplier;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;
import org.apache.maven.execution.MavenSession;
import org.eclipse.aether.ConfigurationProperties;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.deployment.DeployRequest;
import org.eclipse.aether.installation.InstallRequest;
import org.eclipse.aether.spi.artifact.ArtifactPredicateFactory;
import org.eclipse.aether.spi.artifact.generator.ArtifactGenerator;
import org.eclipse.aether.spi.artifact.generator.ArtifactGeneratorFactory;
import org.eclipse.aether.util.ConfigUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Signs deployed artifacts with Sigmund when {@link SigmundConfigurationKeys#CONFIG_PROP_SIGN_ENABLED} is set.
 *
 * <p>
 * The signing tools and keys come from the {@code signing} and {@code tools} sections of the extension's
 * {@code sigmund.yaml}, located as for verification; without a file, Sigmund's default signing tools sign, such as
 * a Bouncy Castle key from {@code SIGMUND_BC_SIGNING_KEY}. The policy is never compiled for signing.
 */
@Singleton
@Named(SigmundSignatureArtifactGeneratorFactory.NAME)
public final class SigmundSignatureArtifactGeneratorFactory implements ArtifactGeneratorFactory {
    private static final Logger LOGGER = LoggerFactory.getLogger(SigmundSignatureArtifactGeneratorFactory.class);

    public static final String NAME = "sigmund";

    private final ArtifactPredicateFactory artifactPredicateFactory;
    private final Supplier<Path> rootDirectory;

    /**
     * Creates the factory.
     *
     * @param artifactPredicateFactory tells which artifacts get checksums, and so signatures
     * @param mavenSession the Maven session, whose root directory holds the project's {@code sigmund.yaml}
     */
    @Inject
    public SigmundSignatureArtifactGeneratorFactory(
            ArtifactPredicateFactory artifactPredicateFactory, Provider<MavenSession> mavenSession) {
        this(artifactPredicateFactory, () -> SessionConfig.rootDirectory(mavenSession.get()));
    }

    SigmundSignatureArtifactGeneratorFactory(
            ArtifactPredicateFactory artifactPredicateFactory, Supplier<Path> rootDirectory) {
        this.artifactPredicateFactory = artifactPredicateFactory;
        this.rootDirectory = rootDirectory;
    }

    /**
     * Signatures are not generated on install, only on deploy.
     */
    @Override
    public ArtifactGenerator newInstance(RepositorySystemSession session, InstallRequest request) {
        return null;
    }

    @Override
    public ArtifactGenerator newInstance(RepositorySystemSession session, DeployRequest request) {
        boolean enabled = ConfigUtils.getBoolean(
                session, SigmundConfigurationKeys.DEFAULT_SIGN_ENABLED, SigmundConfigurationKeys.CONFIG_PROP_SIGN_ENABLED);
        if (!enabled) {
            return null;
        }
        Sigmund sigmund = signingSigmund(session);
        try {
            return new SigmundSignatureArtifactGenerator(
                    request.getArtifacts(),
                    artifactPredicateFactory.newInstance(session)::hasChecksums,
                    sigmund,
                    signer(session, sigmund));
        } catch (RuntimeException e) {
            sigmund.close();
            throw e;
        }
    }

    private static Signer signer(RepositorySystemSession session, Sigmund sigmund) {
        String profile = ConfigUtils.getString(session, null, SigmundConfigurationKeys.CONFIG_PROP_SIGN_PROFILE);
        if (profile == null) {
            return sigmund.signer();
        }
        LOGGER.info("Sigmund signs with profile {}", profile);
        return sigmund.signer(profile);
    }

    private Sigmund signingSigmund(RepositorySystemSession session) {
        Path located = SessionConfig.locate(session, rootDirectory.get());
        SigmundConfig config = located == null ? SigmundConfig.EMPTY : ConfigLoader.load(located);
        LOGGER.info("Sigmund signs artifacts with {}", located == null ? "its default signing tools" : located);
        return Sigmund.builder()
                .config(config)
                .interactive(ConfigUtils.getBoolean(
                        session, ConfigurationProperties.DEFAULT_INTERACTIVE, ConfigurationProperties.INTERACTIVE))
                .addSigningTools(name -> LOGGER.debug("Signing tool '{}' not available, skipping", name))
                .build();
    }

    /**
     * Generators run highest priority first, so 20000 runs this one before Resolver's GnuPG (100) and Sigstore (150)
     * generators, which back off when they find its signatures.
     */
    private float priority = 20000;

    @Override
    public float getPriority() {
        return priority;
    }

    public SigmundSignatureArtifactGeneratorFactory setPriority(float priority) {
        this.priority = priority;
        return this;
    }
}
