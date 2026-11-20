package dev.cyberstamp.sigmund.resolver.connector;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.spi.connector.ArtifactDownload;
import org.eclipse.aether.spi.connector.ArtifactUpload;
import org.eclipse.aether.spi.connector.MetadataDownload;
import org.eclipse.aether.spi.connector.MetadataUpload;
import org.eclipse.aether.spi.connector.RepositoryConnector;
import org.eclipse.aether.transfer.ArtifactNotFoundException;
import org.eclipse.aether.transfer.ArtifactTransferException;

/**
 * A delegate connector serving artifacts from local files, keyed by {@code Artifact.toString()}, recording every
 * download it is asked for.
 */
class FakeConnector implements RepositoryConnector {

    final List<ArtifactDownload> seen = new ArrayList<>();

    private final Map<String, Path> files;
    private final Map<String, ArtifactTransferException> failures;

    FakeConnector(Map<String, Path> files) {
        this(files, Map.of());
    }

    FakeConnector(Map<String, Path> files, Map<String, ArtifactTransferException> failures) {
        this.files = Map.copyOf(files);
        this.failures = Map.copyOf(failures);
    }

    @Override
    public void get(
            Collection<? extends ArtifactDownload> artifactDownloads,
            Collection<? extends MetadataDownload> metadataDownloads) {
        for (ArtifactDownload download : artifactDownloads) {
            seen.add(download);
            serve(download);
        }
    }

    private void serve(ArtifactDownload download) {
        String key = download.getArtifact().toString();
        if (failures.containsKey(key)) {
            download.setException(failures.get(key));
        } else if (!files.containsKey(key)) {
            download.setException(new ArtifactNotFoundException(download.getArtifact(), (RemoteRepository) null));
        } else if (!download.isExistenceCheck()) {
            copy(files.get(key), download.getPath());
        }
    }

    private static void copy(Path source, Path target) {
        try {
            Files.createDirectories(target.getParent());
            Files.copy(source, target, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public void put(
            Collection<? extends ArtifactUpload> artifactUploads,
            Collection<? extends MetadataUpload> metadataUploads) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void close() {
    }
}
