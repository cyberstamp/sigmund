package io.github.aloubyansky.sigmund.plugin;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.apache.maven.plugin.logging.Log;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.repository.ArtifactRepository;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResolutionException;
import org.eclipse.aether.resolution.ArtifactResult;

class ArtifactFileResolver {

    private final Log log;
    private final RepositorySystem repoSystem;
    private final RepositorySystemSession repoSession;
    private final List<RemoteRepository> remoteRepos;

    ArtifactFileResolver(RepositorySystem repoSystem, RepositorySystemSession repoSession,
            List<RemoteRepository> remoteRepos, Log log) {
        this.repoSystem = repoSystem;
        this.repoSession = repoSession;
        this.remoteRepos = remoteRepos;
        this.log = log;
    }

    record ResolvedFiles(Path artifactFile, List<Path> evidenceFiles) {
    }

    record ResolvedArtifact(Path artifactFile, RemoteRepository sourceRepo) {
    }

    record ResolvedSignature(Path signatureFile, String repoId) {
    }

    ResolvedFiles resolve(ArtifactCoords coords) {
        ResolvedArtifact resolved = resolveArtifact(coords);
        if (resolved == null) {
            return null;
        }

        List<RemoteRepository> sigRepos = signatureRepos(resolved.sourceRepo());

        List<Path> evidenceFiles = new ArrayList<>();
        ResolvedSignature sig = resolveSignature(coords, ".asc", sigRepos);
        if (sig != null) {
            evidenceFiles.add(sig.signatureFile());
        }

        return new ResolvedFiles(resolved.artifactFile(), evidenceFiles);
    }

    ResolvedArtifact resolveArtifact(ArtifactCoords coords) {
        try {
            org.eclipse.aether.artifact.Artifact aetherArtifact = new DefaultArtifact(
                    coords.groupId(), coords.artifactId(),
                    coords.classifier(), coords.type(), coords.version());
            ArtifactRequest request = new ArtifactRequest(aetherArtifact, remoteRepos, null);
            ArtifactResult result = repoSystem.resolveArtifact(repoSession, request);
            Path file = result.getArtifact().getFile().toPath();
            RemoteRepository sourceRepo = extractSourceRepo(result);
            return new ResolvedArtifact(file, sourceRepo);
        } catch (ArtifactResolutionException e) {
            log.debug("Could not resolve " + coords);
            return null;
        }
    }

    ResolvedSignature resolveSignature(ArtifactCoords coords, String extension,
            List<RemoteRepository> repos) {
        try {
            org.eclipse.aether.artifact.Artifact aetherArtifact = new DefaultArtifact(
                    coords.groupId(), coords.artifactId(),
                    coords.classifier(), coords.type() + extension,
                    coords.version());
            ArtifactRequest request = new ArtifactRequest(aetherArtifact, repos, null);
            ArtifactResult result = repoSystem.resolveArtifact(repoSession, request);
            Path file = result.getArtifact().getFile().toPath();
            String repoId = resolveRepoId(result);
            return new ResolvedSignature(file, repoId);
        } catch (ArtifactResolutionException e) {
            log.debug("No " + extension + " found for " + coords);
            return null;
        }
    }

    List<RemoteRepository> signatureRepos(RemoteRepository sourceRepo) {
        return sourceRepo != null ? List.of(sourceRepo) : remoteRepos;
    }

    private String resolveRepoId(ArtifactResult result) {
        if (result.getLocalArtifactResult() != null
                && result.getLocalArtifactResult().getRepository() != null) {
            return result.getLocalArtifactResult().getRepository().getId();
        }
        ArtifactRepository repo = result.getRepository();
        return repo != null ? repo.getId() : null;
    }

    private RemoteRepository extractSourceRepo(ArtifactResult result) {
        if (result.getLocalArtifactResult() != null
                && result.getLocalArtifactResult().getRepository() != null) {
            return findMatchingRepo(result.getLocalArtifactResult().getRepository().getId());
        }
        ArtifactRepository repo = result.getRepository();
        if (repo instanceof RemoteRepository) {
            return (RemoteRepository) repo;
        }
        if (repo != null) {
            return findMatchingRepo(repo.getId());
        }
        return null;
    }

    private RemoteRepository findMatchingRepo(String repoId) {
        if (repoId == null) {
            return null;
        }
        for (RemoteRepository repo : remoteRepos) {
            if (repoId.equals(repo.getId())) {
                return repo;
            }
        }
        return null;
    }
}
