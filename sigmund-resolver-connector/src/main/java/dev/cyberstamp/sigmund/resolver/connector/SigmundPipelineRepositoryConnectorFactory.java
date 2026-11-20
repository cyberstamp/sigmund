package dev.cyberstamp.sigmund.resolver.connector;

import dev.cyberstamp.sigmund.resolver.SigmundSessionVerifier;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;
import org.apache.maven.execution.MavenSession;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.spi.connector.PipelineRepositoryConnectorFactory;
import org.eclipse.aether.spi.connector.RepositoryConnector;

@Singleton
@Named(SigmundPipelineRepositoryConnectorFactory.NAME)
public final class SigmundPipelineRepositoryConnectorFactory implements PipelineRepositoryConnectorFactory {
    public static final String NAME = "sigmund";

    /**
     * This connector should be usually the right-most in pipeline.
     */
    private float priority = 20000;

    private final Provider<MavenSession> mavenSession;

    /**
     * Creates the factory.
     *
     * @param mavenSession the Maven session, whose root directory holds the project's {@code sigmund.yaml}
     */
    @Inject
    public SigmundPipelineRepositoryConnectorFactory(Provider<MavenSession> mavenSession) {
        this.mavenSession = mavenSession;
    }

    @Override
    public RepositoryConnector newInstance(
            RepositorySystemSession session, RemoteRepository repository, RepositoryConnector delegate) {
        if (SigmundSessionVerifier.isEnabled(session)) {
            return new SigmundRepositoryConnector(
                    session, repository, delegate,
                    SigmundSessionVerifier.get(session, () -> SigmundSessionVerifier.rootDirectory(mavenSession.get())));
        } else {
            return delegate;
        }
    }

    @Override
    public float getPriority() {
        return priority;
    }

    public SigmundPipelineRepositoryConnectorFactory setPriority(float priority) {
        this.priority = priority;
        return this;
    }
}
