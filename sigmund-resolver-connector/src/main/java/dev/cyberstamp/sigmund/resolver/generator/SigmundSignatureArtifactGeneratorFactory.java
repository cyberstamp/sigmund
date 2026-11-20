package dev.cyberstamp.sigmund.resolver.generator;

import dev.cyberstamp.sigmund.resolver.SigmundConfigurationKeys;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.deployment.DeployRequest;
import org.eclipse.aether.installation.InstallRequest;
import org.eclipse.aether.spi.artifact.ArtifactPredicateFactory;
import org.eclipse.aether.spi.artifact.generator.ArtifactGenerator;
import org.eclipse.aether.spi.artifact.generator.ArtifactGeneratorFactory;
import org.eclipse.aether.util.ConfigUtils;

@Singleton
@Named(SigmundSignatureArtifactGeneratorFactory.NAME)
public final class SigmundSignatureArtifactGeneratorFactory implements ArtifactGeneratorFactory {

    public static final String NAME = "sigmund";

    private final ArtifactPredicateFactory artifactPredicateFactory;

    @Inject
    public SigmundSignatureArtifactGeneratorFactory(ArtifactPredicateFactory artifactPredicateFactory) {
        this.artifactPredicateFactory = artifactPredicateFactory;
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
        final boolean enabled = ConfigUtils.getBoolean(
                session, SigmundConfigurationKeys.DEFAULT_SIGN_ENABLED, SigmundConfigurationKeys.CONFIG_PROP_SIGN_ENABLED);
        if (!enabled) {
            return null;
        }

        return new SigmundSignatureArtifactGenerator(
                request.getArtifacts(), artifactPredicateFactory.newInstance(session)::hasChecksums);
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
