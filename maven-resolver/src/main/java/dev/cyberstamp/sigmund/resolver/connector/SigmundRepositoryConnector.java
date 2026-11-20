package dev.cyberstamp.sigmund.resolver.connector;

import static java.util.Objects.requireNonNull;

import dev.cyberstamp.sigmund.core.ArtifactOutcome;
import dev.cyberstamp.sigmund.resolver.SigmundSessionVerifier;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.repository.RepositoryPolicy;
import org.eclipse.aether.spi.connector.ArtifactDownload;
import org.eclipse.aether.spi.connector.ArtifactUpload;
import org.eclipse.aether.spi.connector.MetadataDownload;
import org.eclipse.aether.spi.connector.MetadataUpload;
import org.eclipse.aether.spi.connector.RepositoryConnector;
import org.eclipse.aether.transfer.ArtifactNotFoundException;
import org.eclipse.aether.transfer.ArtifactTransferException;
import org.eclipse.aether.util.artifact.SubArtifact;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifies every artifact downloaded from a remote repository against the Sigmund trust policy before resolution
 * hands it on.
 *
 * <p>
 * Each artifact download is accompanied by downloads of its signature sidecars ({@code <artifact>.asc}, …) into a
 * temporary directory, all in one call to the delegate. A missing sidecar is no claim, which the policy judges; any
 * other sidecar transfer failure fails the artifact, so a network fault cannot downgrade a required signature to
 * "unsigned". An artifact whose outcome blocks gets a {@link SigmundVerificationException} and its file is deleted.
 * Existence checks and explicit requests for a signature file pass through untouched. Uploads pass through.
 */
public final class SigmundRepositoryConnector implements RepositoryConnector {
    private static final Logger LOGGER = LoggerFactory.getLogger(SigmundRepositoryConnector.class);

    private final RemoteRepository remoteRepository;
    private final RepositoryConnector delegate;
    private final SigmundSessionVerifier verifier;

    /**
     * Creates the connector.
     *
     * @param remoteRepository the repository the delegate downloads from
     * @param delegate the connector doing the transfers
     * @param verifier the session's verifier
     */
    public SigmundRepositoryConnector(
            RemoteRepository remoteRepository, RepositoryConnector delegate, SigmundSessionVerifier verifier) {
        this.remoteRepository = requireNonNull(remoteRepository);
        this.delegate = requireNonNull(delegate);
        this.verifier = requireNonNull(verifier);
    }

    @Override
    public void close() {
        delegate.close();
    }

    @Override
    public void get(
            Collection<? extends ArtifactDownload> artifactDownloads,
            Collection<? extends MetadataDownload> metadataDownloads) {
        if (artifactDownloads == null || artifactDownloads.isEmpty()) {
            delegate.get(artifactDownloads, metadataDownloads);
            return;
        }
        Set<String> extensions = verifier.signatureExtensions();
        Path tmp = createTempDir();
        try {
            Map<ArtifactDownload, List<ArtifactDownload>> companions = companions(artifactDownloads, extensions, tmp);
            List<ArtifactDownload> all = new ArrayList<>(artifactDownloads);
            companions.values().forEach(all::addAll);
            delegate.get(all, metadataDownloads);
            companions.forEach(this::verify);
        } finally {
            deleteRecursively(tmp);
        }
    }

    private static Map<ArtifactDownload, List<ArtifactDownload>> companions(
            Collection<? extends ArtifactDownload> downloads, Set<String> extensions, Path tmp) {
        Map<ArtifactDownload, List<ArtifactDownload>> companions = new LinkedHashMap<>();
        int index = 0;
        for (ArtifactDownload download : downloads) {
            if (!isVerifiable(download, extensions)) {
                continue;
            }
            List<ArtifactDownload> sidecars = new ArrayList<>(extensions.size());
            for (String extension : extensions) {
                sidecars.add(new ArtifactDownload(
                        new SubArtifact(download.getArtifact(), "*", "*" + extension),
                        download.getRequestContext(),
                        tmp.resolve(index++ + extension),
                        RepositoryPolicy.CHECKSUM_POLICY_IGNORE)
                        .setTrace(download.getTrace()));
            }
            companions.put(download, sidecars);
        }
        return companions;
    }

    private static boolean isVerifiable(ArtifactDownload download, Set<String> extensions) {
        String extension = "." + download.getArtifact().getExtension();
        return !download.isExistenceCheck() && extensions.stream().noneMatch(extension::endsWith);
    }

    private void verify(ArtifactDownload download, List<ArtifactDownload> sidecars) {
        if (download.getException() != null) {
            return;
        }
        List<Path> evidence = new ArrayList<>(sidecars.size());
        for (ArtifactDownload sidecar : sidecars) {
            ArtifactTransferException failure = sidecar.getException();
            if (failure == null) {
                evidence.add(sidecar.getPath());
            } else if (!(failure instanceof ArtifactNotFoundException)) {
                fail(download, "Could not fetch signature " + sidecar.getArtifact() + " to verify it", failure);
                return;
            }
        }
        SigmundSessionVerifier.Verdict verdict = verifier.verify(download.getArtifact(), download.getPath(), evidence);
        if (verdict.blocks()) {
            fail(download, verdict.message(), null);
        } else if (verdict.outcome() != ArtifactOutcome.SATISFIED
                && verdict.outcome() != ArtifactOutcome.NOT_CONFIGURED) {
            LOGGER.warn(verdict.message());
        }
    }

    private void fail(ArtifactDownload download, String message, Throwable cause) {
        download.setException(
                new SigmundVerificationException(download.getArtifact(), remoteRepository, message, cause));
        try {
            Files.deleteIfExists(download.getPath());
        } catch (IOException e) {
            throw new UncheckedIOException("Could not delete blocked artifact " + download.getPath(), e);
        }
    }

    private static Path createTempDir() {
        try {
            return Files.createTempDirectory("sigmund-");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static void deleteRecursively(Path dir) {
        try (Stream<Path> paths = Files.walk(dir)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        } catch (IOException e) {
            LOGGER.warn("Could not delete temporary directory {}", dir, e);
        }
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
