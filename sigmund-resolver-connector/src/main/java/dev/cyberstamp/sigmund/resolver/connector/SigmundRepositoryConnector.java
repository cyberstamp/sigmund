package dev.cyberstamp.sigmund.resolver.connector;

import static java.util.Objects.requireNonNull;

import dev.cyberstamp.sigmund.resolver.Sidecar;
import dev.cyberstamp.sigmund.resolver.SigmundSessionVerifier;
import dev.cyberstamp.sigmund.resolver.SigmundVerificationException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.repository.LocalArtifactRegistration;
import org.eclipse.aether.repository.LocalRepositoryManager;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.repository.RepositoryPolicy;
import org.eclipse.aether.spi.connector.ArtifactDownload;
import org.eclipse.aether.spi.connector.ArtifactUpload;
import org.eclipse.aether.spi.connector.MetadataDownload;
import org.eclipse.aether.spi.connector.MetadataUpload;
import org.eclipse.aether.spi.connector.RepositoryConnector;
import org.eclipse.aether.transfer.ArtifactNotFoundException;
import org.eclipse.aether.transfer.ArtifactTransferException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifies every artifact downloaded from a remote repository against the Sigmund trust policy before resolution
 * hands it on.
 *
 * <p>
 * Each artifact download is accompanied by downloads of its signature sidecars ({@code <artifact>.asc}, …) to their
 * place next to the artifact in the local repository, all in one call to the delegate. A missing sidecar is no
 * claim, which the policy judges; any other sidecar transfer failure fails the artifact, so a network fault cannot
 * downgrade a required signature to "unsigned". An artifact that passes keeps its sidecars, registered with the
 * local repository manager. An artifact whose outcome blocks, or that could not be verified, gets a
 * {@link SigmundVerificationException}, and its file and sidecars are deleted; so are they when the delegate fails,
 * so no unverified file is left behind. Existence checks and explicit requests for a signature file pass through
 * untouched. Uploads pass through.
 */
public final class SigmundRepositoryConnector implements RepositoryConnector {
    private static final Logger LOGGER = LoggerFactory.getLogger(SigmundRepositoryConnector.class);

    private final RepositorySystemSession session;
    private final RemoteRepository remoteRepository;
    private final RepositoryConnector delegate;
    private final SigmundSessionVerifier verifier;

    /**
     * Creates the connector.
     *
     * @param session the session, whose local repository manager places and registers the sidecars
     * @param remoteRepository the repository the delegate downloads from
     * @param delegate the connector doing the transfers
     * @param verifier the session's verifier
     */
    public SigmundRepositoryConnector(
            RepositorySystemSession session,
            RemoteRepository remoteRepository,
            RepositoryConnector delegate,
            SigmundSessionVerifier verifier) {
        this.session = requireNonNull(session);
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
        Map<ArtifactDownload, List<ArtifactDownload>> companions = companions(artifactDownloads);
        if (companions.isEmpty()) {
            delegate.get(artifactDownloads, metadataDownloads);
            return;
        }
        List<ArtifactDownload> all = new ArrayList<>(artifactDownloads);
        companions.values().forEach(all::addAll);
        Set<ArtifactDownload> judged = new HashSet<>();
        try {
            delegate.get(all, metadataDownloads);
            companions.forEach((download, sidecars) -> {
                judge(download, sidecars);
                judged.add(download);
            });
        } finally {
            companions.forEach((download, sidecars) -> {
                if (!judged.contains(download)) {
                    discard(download, sidecars);
                }
            });
        }
    }

    private Map<ArtifactDownload, List<ArtifactDownload>> companions(
            Collection<? extends ArtifactDownload> downloads) {
        if (downloads == null) {
            return Map.of();
        }
        Map<ArtifactDownload, List<ArtifactDownload>> companions = new LinkedHashMap<>();
        for (ArtifactDownload download : downloads) {
            if (!download.isExistenceCheck() && !verifier.isSignature(download.getArtifact())) {
                companions.put(download, sidecars(download));
            }
        }
        return companions;
    }

    private List<ArtifactDownload> sidecars(ArtifactDownload download) {
        LocalRepositoryManager localRepository = session.getLocalRepositoryManager();
        List<ArtifactDownload> sidecars = new ArrayList<>();
        for (Artifact signature : verifier.signaturesOf(download.getArtifact())) {
            Path path = localRepository.getAbsolutePathForRemoteArtifact(
                    signature, remoteRepository, download.getRequestContext());
            sidecars.add(new ArtifactDownload(
                    signature, download.getRequestContext(), path, RepositoryPolicy.CHECKSUM_POLICY_IGNORE)
                    .setRepositories(download.getRepositories())
                    .setSupportedContexts(download.getSupportedContexts())
                    .setTrace(download.getTrace()));
        }
        return sidecars;
    }

    private void judge(ArtifactDownload download, List<ArtifactDownload> sidecars) {
        if (download.getException() != null) {
            sidecars.forEach(sidecar -> delete(sidecar.getPath()));
            return;
        }
        SigmundVerificationException refused = verifier.check(download.getArtifact(), download.getPath(), outcomes(sidecars),
                remoteRepository);
        if (refused != null) {
            download.setException(refused);
            discard(download, sidecars);
            return;
        }
        register(sidecars);
    }

    private static List<Sidecar> outcomes(List<ArtifactDownload> sidecars) {
        List<Sidecar> outcomes = new ArrayList<>(sidecars.size());
        for (ArtifactDownload sidecar : sidecars) {
            ArtifactTransferException failure = sidecar.getException();
            if (failure == null) {
                outcomes.add(Sidecar.found(sidecar.getArtifact(), sidecar.getPath()));
            } else if (failure instanceof ArtifactNotFoundException) {
                outcomes.add(Sidecar.missing(sidecar.getArtifact()));
            } else {
                outcomes.add(Sidecar.failed(sidecar.getArtifact(), failure));
            }
        }
        return outcomes;
    }

    private void register(List<ArtifactDownload> sidecars) {
        LocalRepositoryManager localRepository = session.getLocalRepositoryManager();
        for (ArtifactDownload sidecar : sidecars) {
            if (sidecar.getException() == null) {
                localRepository.add(
                        session,
                        new LocalArtifactRegistration(
                                sidecar.getArtifact(), remoteRepository, sidecar.getSupportedContexts()));
            }
        }
    }

    private static void discard(ArtifactDownload download, List<ArtifactDownload> sidecars) {
        delete(download.getPath());
        sidecars.forEach(sidecar -> delete(sidecar.getPath()));
    }

    private static void delete(Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (IOException e) {
            LOGGER.warn("Could not delete unverified file {}", path, e);
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
