package dev.cyberstamp.sigmund.resolver.processor;

import dev.cyberstamp.sigmund.resolver.Sidecar;
import dev.cyberstamp.sigmund.resolver.SigmundSessionVerifier;
import dev.cyberstamp.sigmund.resolver.SigmundVerificationException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;
import org.apache.maven.execution.MavenSession;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.repository.ArtifactRepository;
import org.eclipse.aether.repository.LocalArtifactRequest;
import org.eclipse.aether.repository.LocalArtifactResult;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.repository.WorkspaceRepository;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResult;
import org.eclipse.aether.spi.resolution.ArtifactResolverPostProcessor;

/**
 * Verifies every artifact resolution returns — local repository hits included — against the Sigmund trust policy,
 * so an artifact cached before verification was enabled, or altered in the local repository since, is checked too.
 *
 * <p>
 * The signature files are looked up in the local repository only, where the repository connector stores them when
 * it downloads an artifact; a signature that is not there is no claim, which the policy judges. Resolving them from
 * here would re-enter the resolver while it holds the artifacts' locks. A file the connector already verified in
 * the session is not verified again. A refused artifact is made unresolved, with a
 * {@link SigmundVerificationException}; its file stays in the local repository. Artifacts from the workspace — the
 * build's own modules — and signature files themselves are not verified.
 */
@Singleton
@Named(SigmundArtifactResolverPostProcessor.NAME)
public final class SigmundArtifactResolverPostProcessor implements ArtifactResolverPostProcessor {
    public static final String NAME = "sigmund";

    private final Supplier<Path> rootDirectory;

    /**
     * Creates the post-processor.
     *
     * @param mavenSession the Maven session, whose root directory holds the project's {@code sigmund.yaml}
     */
    @Inject
    public SigmundArtifactResolverPostProcessor(Provider<MavenSession> mavenSession) {
        this(() -> SigmundSessionVerifier.rootDirectory(mavenSession.get()));
    }

    SigmundArtifactResolverPostProcessor(Supplier<Path> rootDirectory) {
        this.rootDirectory = rootDirectory;
    }

    @Override
    public void postProcess(RepositorySystemSession session, List<ArtifactResult> artifactResults) {
        if (!SigmundSessionVerifier.isEnabled(session)) {
            return;
        }
        SigmundSessionVerifier verifier = SigmundSessionVerifier.get(session, rootDirectory);
        for (ArtifactResult result : artifactResults) {
            if (isVerifiable(result, verifier)) {
                verify(session, result, verifier);
            }
        }
    }

    private static boolean isVerifiable(ArtifactResult result, SigmundSessionVerifier verifier) {
        return result.isResolved()
                && !(result.getRepository() instanceof WorkspaceRepository)
                && !verifier.isSignature(result.getArtifact())
                && !verifier.hasPassed(result.getArtifact().getPath());
    }

    private static void verify(RepositorySystemSession session, ArtifactResult result, SigmundSessionVerifier verifier) {
        Artifact artifact = result.getArtifact();
        ArtifactRepository repository = result.getRepository();
        SigmundVerificationException refused = verifier.check(
                artifact,
                artifact.getPath(),
                storedSignatures(session, result.getRequest(), verifier.signaturesOf(artifact)),
                repository instanceof RemoteRepository remote ? remote : null);
        if (refused != null) {
            result.setArtifact(artifact.setPath(null));
            result.addException(repository, refused);
        }
    }

    private static List<Sidecar> storedSignatures(
            RepositorySystemSession session, ArtifactRequest request, List<Artifact> signatures) {
        List<Sidecar> sidecars = new ArrayList<>(signatures.size());
        for (Artifact signature : signatures) {
            LocalArtifactResult stored = session.getLocalRepositoryManager()
                    .find(session, new LocalArtifactRequest(
                            signature, request.getRepositories(), request.getRequestContext()));
            sidecars.add(stored.getPath() != null
                    ? Sidecar.found(signature, stored.getPath())
                    : Sidecar.missing(signature));
        }
        return sidecars;
    }
}
