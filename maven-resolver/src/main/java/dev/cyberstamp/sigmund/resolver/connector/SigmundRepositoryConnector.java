package dev.cyberstamp.sigmund.resolver.connector;

import static java.util.Objects.requireNonNull;

import java.util.Collection;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.spi.connector.ArtifactDownload;
import org.eclipse.aether.spi.connector.ArtifactUpload;
import org.eclipse.aether.spi.connector.MetadataDownload;
import org.eclipse.aether.spi.connector.MetadataUpload;
import org.eclipse.aether.spi.connector.RepositoryConnector;

public final class SigmundRepositoryConnector implements RepositoryConnector {
    private final RepositorySystemSession session;
    private final RemoteRepository remoteRepository;
    private final RepositoryConnector delegate;

    public SigmundRepositoryConnector(
            RepositorySystemSession session, RemoteRepository remoteRepository, RepositoryConnector delegate) {
        this.session = requireNonNull(session);
        this.remoteRepository = requireNonNull(remoteRepository);
        this.delegate = requireNonNull(delegate);
    }

    @Override
    public void close() {
        delegate.close();
    }

    @Override
    public void get(
            Collection<? extends ArtifactDownload> artifactDownloads,
            Collection<? extends MetadataDownload> metadataDownloads) {
        delegate.get(artifactDownloads, metadataDownloads);
    }

    @Override
    public void put(
            Collection<? extends ArtifactUpload> artifactUploads,
            Collection<? extends MetadataUpload> metadataUploads) {
        delegate.put(artifactUploads, metadataUploads);
    }

    @Override
    public String toString() {
        return SigmundPipelineRepositoryConnectorFactory.NAME + "( " + delegate.toString() + " )";
    }
}
