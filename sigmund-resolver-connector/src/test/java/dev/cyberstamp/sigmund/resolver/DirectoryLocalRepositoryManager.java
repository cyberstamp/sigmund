package dev.cyberstamp.sigmund.resolver;

import java.nio.file.Files;
import java.nio.file.Path;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.internal.test.util.TestLocalRepositoryManager;
import org.eclipse.aether.repository.LocalArtifactRequest;
import org.eclipse.aether.repository.LocalArtifactResult;
import org.eclipse.aether.repository.LocalRepository;

/**
 * Resolver's test local repository manager, rooted in a given directory: it records registrations, and finds an
 * artifact when its file exists.
 */
public final class DirectoryLocalRepositoryManager extends TestLocalRepositoryManager {

    private final LocalRepository repository;

    /**
     * Creates the manager.
     *
     * @param basedir the local repository's directory
     */
    public DirectoryLocalRepositoryManager(Path basedir) {
        this.repository = new LocalRepository(basedir);
    }

    @Override
    public LocalRepository getRepository() {
        return repository;
    }

    @Override
    public LocalArtifactResult find(RepositorySystemSession session, LocalArtifactRequest request) {
        Path path = getAbsolutePathForLocalArtifact(request.getArtifact());
        boolean exists = Files.isRegularFile(path);
        return new LocalArtifactResult(request).setPath(exists ? path : null).setAvailable(exists);
    }
}
