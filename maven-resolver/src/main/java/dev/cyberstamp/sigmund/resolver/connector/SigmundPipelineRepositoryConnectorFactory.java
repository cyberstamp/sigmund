package dev.cyberstamp.sigmund.resolver.connector;

import dev.cyberstamp.sigmund.resolver.SigmundConfigurationKeys;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.spi.connector.PipelineRepositoryConnectorFactory;
import org.eclipse.aether.spi.connector.RepositoryConnector;
import org.eclipse.aether.util.ConfigUtils;

@Singleton
@Named(SigmundPipelineRepositoryConnectorFactory.NAME)
public final class SigmundPipelineRepositoryConnectorFactory implements PipelineRepositoryConnectorFactory {
    public static final String NAME = "sigmund";

    /**
     * This connector should be usually the right-most in pipeline.
     */
    private float priority = 20000;

    @Inject
    public SigmundPipelineRepositoryConnectorFactory() {
    }

    @Override
    public RepositoryConnector newInstance(
            RepositorySystemSession session, RemoteRepository repository, RepositoryConnector delegate) {
        final boolean enabled = ConfigUtils.getBoolean(
                session, SigmundConfigurationKeys.DEFAULT_VERIFY_ENABLED,
                SigmundConfigurationKeys.CONFIG_PROP_VERIFY_ENABLED);
        if (enabled) {
            return new SigmundRepositoryConnector(session, repository, delegate);
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
