package dev.cyberstamp.sigmund.resolver.processor;

import static org.assertj.core.api.Assertions.assertThat;

import dev.cyberstamp.sigmund.resolver.DirectoryLocalRepositoryManager;
import dev.cyberstamp.sigmund.resolver.SigmundConfigurationKeys;
import dev.cyberstamp.sigmund.resolver.SigmundVerificationException;
import dev.cyberstamp.sigmund.resolver.TestKeys;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.repository.ArtifactRepository;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.repository.WorkspaceRepository;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SigmundArtifactResolverPostProcessorTest {

    private static final RemoteRepository REPO = new RemoteRepository.Builder("test", "default", "https://example.invalid/")
            .build();
    private static final Artifact JAR = new DefaultArtifact("org.example:lib:jar:1.0");
    private static final Artifact ASC = new DefaultArtifact("org.example:lib:jar.asc:1.0");

    @TempDir
    Path dir;

    private TestKeys.Fixture fixture;
    private DirectoryLocalRepositoryManager localRepository;
    private DefaultRepositorySystemSession session;
    private final List<Runnable> sessionEndedHandlers = new ArrayList<>();
    private SigmundArtifactResolverPostProcessor processor;

    @BeforeEach
    void setUp() {
        fixture = TestKeys.create(dir.resolve("fixture"));
        localRepository = new DirectoryLocalRepositoryManager(dir.resolve("local"));
        session = new DefaultRepositorySystemSession(sessionEndedHandlers::add);
        session.setLocalRepositoryManager(localRepository);
        session.setConfigProperty(SigmundConfigurationKeys.CONFIG_PROP_VERIFY_ENABLED, "true");
        processor = new SigmundArtifactResolverPostProcessor(() -> fixture.configFile().getParent());
    }

    @AfterEach
    void tearDown() {
        sessionEndedHandlers.forEach(Runnable::run);
    }

    @Test
    void aCachedArtifactWithItsStoredSignatureStaysResolved() throws IOException {
        ArtifactResult result = cached(JAR, fixture.artifact(), REPO);
        store(ASC, fixture.signature());

        processor.postProcess(session, List.of(result));

        assertThat(result.isResolved()).isTrue();
        assertThat(result.getExceptions()).isEmpty();
    }

    @Test
    void aTamperedCachedArtifactIsUnresolvedButNotDeleted() throws IOException {
        ArtifactResult result = cached(JAR, tampered(), REPO);
        store(ASC, fixture.signature());

        processor.postProcess(session, List.of(result));

        assertThat(result.isResolved()).isFalse();
        assertThat(result.getExceptions()).singleElement()
                .isInstanceOf(SigmundVerificationException.class)
                .satisfies(e -> assertThat(e.getMessage()).contains("FAILED"));
        assertThat(localPath(JAR)).exists();
    }

    @Test
    void aCachedArtifactWithoutAStoredSignatureIsNoClaim() throws IOException {
        ArtifactResult result = cached(JAR, fixture.artifact(), REPO);

        processor.postProcess(session, List.of(result));

        assertThat(result.isResolved()).isFalse();
        assertThat(result.getExceptions()).singleElement()
                .satisfies(e -> assertThat(e.getMessage()).contains("NO_CLAIM"));
    }

    @Test
    void aWorkspaceArtifactIsNotVerified() throws IOException {
        ArtifactResult result = cached(JAR, tampered(), new WorkspaceRepository());

        processor.postProcess(session, List.of(result));

        assertThat(result.isResolved()).isTrue();
    }

    @Test
    void aSignatureIsNotVerifiedAsAnArtifact() throws IOException {
        ArtifactResult result = cached(ASC, fixture.signature(), REPO);

        processor.postProcess(session, List.of(result));

        assertThat(result.isResolved()).isTrue();
    }

    @Test
    void anUnresolvedResultIsLeftAlone() {
        ArtifactResult result = new ArtifactResult(new ArtifactRequest(JAR, List.of(REPO), ""));

        processor.postProcess(session, List.of(result));

        assertThat(result.getExceptions()).isEmpty();
    }

    @Test
    void nothingIsVerifiedWhenVerificationIsDisabled() throws IOException {
        session.setConfigProperty(SigmundConfigurationKeys.CONFIG_PROP_VERIFY_ENABLED, "false");
        ArtifactResult result = cached(JAR, tampered(), REPO);
        store(ASC, fixture.signature());

        processor.postProcess(session, List.of(result));

        assertThat(result.isResolved()).isTrue();
    }

    private ArtifactResult cached(Artifact artifact, Path content, ArtifactRepository repository)
            throws IOException {
        Path path = store(artifact, content);
        ArtifactResult result = new ArtifactResult(new ArtifactRequest(artifact, List.of(REPO), ""));
        result.setArtifact(artifact.setPath(path));
        result.setRepository(repository);
        return result;
    }

    private Path store(Artifact artifact, Path content) throws IOException {
        Path path = localPath(artifact);
        Files.createDirectories(path.getParent());
        return Files.copy(content, path);
    }

    private Path localPath(Artifact artifact) {
        return localRepository.getAbsolutePathForLocalArtifact(artifact);
    }

    private Path tampered() throws IOException {
        Path tampered = Files.copy(fixture.artifact(), dir.resolve("tampered.jar"));
        Files.write(tampered, new byte[] { 1 }, StandardOpenOption.APPEND);
        return tampered;
    }
}
