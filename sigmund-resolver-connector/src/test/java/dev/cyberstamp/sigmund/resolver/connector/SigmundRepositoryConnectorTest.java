package dev.cyberstamp.sigmund.resolver.connector;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.cyberstamp.sigmund.resolver.SigmundSessionVerifier;
import dev.cyberstamp.sigmund.resolver.TestKeys;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.internal.test.util.TestLocalRepositoryManager;
import org.eclipse.aether.repository.LocalRepository;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.repository.RepositoryPolicy;
import org.eclipse.aether.spi.connector.ArtifactDownload;
import org.eclipse.aether.spi.connector.MetadataDownload;
import org.eclipse.aether.transfer.ArtifactTransferException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SigmundRepositoryConnectorTest {

    private static final RemoteRepository REPO = new RemoteRepository.Builder("test", "default", "https://example.invalid/")
            .build();
    private static final Artifact JAR = new DefaultArtifact("org.example:lib:jar:1.0");
    private static final Artifact ASC = new DefaultArtifact("org.example:lib:jar.asc:1.0");

    @TempDir
    Path dir;

    private TestKeys.Fixture fixture;
    private SigmundSessionVerifier verifier;
    private TestLocalRepositoryManager localRepository;
    private DefaultRepositorySystemSession session;

    @BeforeEach
    void setUp() {
        fixture = TestKeys.create(dir.resolve("fixture"));
        verifier = SigmundSessionVerifier.create(fixture.configFile());
        LocalRepository local = new LocalRepository(dir.resolve("local"));
        localRepository = new TestLocalRepositoryManager() {
            @Override
            public LocalRepository getRepository() {
                return local;
            }
        };
        session = new DefaultRepositorySystemSession(h -> false);
        session.setLocalRepositoryManager(localRepository);
    }

    @AfterEach
    void tearDown() {
        verifier.close();
    }

    @Test
    void signedArtifactPassesAndKeepsItsSignatureRegisteredNextToIt() {
        FakeConnector fake = new FakeConnector(signedFiles(fixture.artifact()));
        ArtifactDownload download = download(JAR);

        get(fake, download);

        assertThat(download.getException()).isNull();
        assertThat(download.getPath()).exists();
        assertThat(localPath(ASC)).hasSameTextualContentAs(fixture.signature());
        assertThat(localPath(ASC).getParent()).isEqualTo(download.getPath().getParent());
        assertThat(registered()).contains(ASC.toString());
        assertThat(fake.seen).hasSize(2);
    }

    @Test
    void tamperedArtifactIsBlockedAndItsFilesDeleted() throws IOException {
        FakeConnector fake = new FakeConnector(signedFiles(tampered()));
        ArtifactDownload download = download(JAR);

        get(fake, download);

        assertThat(download.getException()).isInstanceOf(SigmundVerificationException.class);
        assertThat(download.getException().getMessage()).contains("FAILED");
        assertThat(download.getPath()).doesNotExist();
        assertThat(localPath(ASC)).doesNotExist();
        assertThat(registered()).doesNotContain(ASC.toString());
    }

    @Test
    void missingSignatureIsNoClaimWhichTheDefaultPolicyBlocks() {
        FakeConnector fake = new FakeConnector(Map.of(JAR.toString(), fixture.artifact()));
        ArtifactDownload download = download(JAR);

        get(fake, download);

        assertThat(download.getException()).isInstanceOf(SigmundVerificationException.class);
        assertThat(download.getException().getCause()).isNull();
        assertThat(download.getException().getMessage()).contains("NO_CLAIM");
        assertThat(download.getPath()).doesNotExist();
    }

    @Test
    void missingSignatureIsNotATransferErrorUnderAWarnPolicy() {
        TestKeys.Fixture warning = TestKeys.create(dir.resolve("warn"), "defaults:\n  on-no-claim: warn\n");
        try (SigmundSessionVerifier warnVerifier = SigmundSessionVerifier.create(warning.configFile())) {
            FakeConnector fake = new FakeConnector(Map.of(JAR.toString(), warning.artifact()));
            ArtifactDownload download = download(JAR);

            new SigmundRepositoryConnector(session, REPO, fake, warnVerifier).get(List.of(download), List.of());

            assertThat(download.getException()).isNull();
            assertThat(download.getPath()).exists();
        }
    }

    @Test
    void signatureTransferErrorFailsArtifact() {
        ArtifactTransferException timeout = new ArtifactTransferException(ASC, REPO, "timeout");
        FakeConnector fake = new FakeConnector(Map.of(JAR.toString(), fixture.artifact()), Map.of(ASC.toString(), timeout));
        ArtifactDownload download = download(JAR);

        get(fake, download);

        assertThat(download.getException()).isInstanceOf(SigmundVerificationException.class);
        assertThat(download.getException().getCause()).isSameAs(timeout);
        assertThat(download.getPath()).doesNotExist();
    }

    @Test
    void verificationErrorFailsTheArtifactClosed() throws IOException {
        Path unreadable = Files.createDirectories(dir.resolve("unreadable.jar"));
        FakeConnector fake = new FakeConnector(signedFiles(unreadable));
        ArtifactDownload download = download(JAR);

        get(fake, download);

        assertThat(download.getException()).isInstanceOf(SigmundVerificationException.class);
        assertThat(download.getException().getCause()).isNotNull();
        assertThat(download.getPath()).doesNotExist();
        assertThat(localPath(ASC)).doesNotExist();
    }

    @Test
    void delegateFailingAfterWritingLeavesNoUnverifiedFile() {
        FakeConnector failing = new FakeConnector(signedFiles(fixture.artifact())) {
            @Override
            public void get(
                    Collection<? extends ArtifactDownload> artifactDownloads,
                    Collection<? extends MetadataDownload> metadataDownloads) {
                super.get(artifactDownloads, metadataDownloads);
                throw new IllegalStateException("delegate broke");
            }
        };
        ArtifactDownload download = download(JAR);

        assertThatThrownBy(() -> get(failing, download)).isInstanceOf(IllegalStateException.class);

        assertThat(download.getPath()).doesNotExist();
        assertThat(localPath(ASC)).doesNotExist();
    }

    @Test
    void explicitSignatureRequestPassesThrough() {
        FakeConnector fake = new FakeConnector(signedFiles(fixture.artifact()));
        ArtifactDownload download = download(ASC);

        get(fake, download);

        assertThat(fake.seen).containsExactly(download);
        assertThat(download.getException()).isNull();
        assertThat(download.getPath()).exists();
    }

    @Test
    void existenceCheckPassesThrough() {
        FakeConnector fake = new FakeConnector(signedFiles(fixture.artifact()));
        ArtifactDownload download = download(JAR).setExistenceCheck(true);

        get(fake, download);

        assertThat(fake.seen).containsExactly(download);
        assertThat(download.getException()).isNull();
    }

    private void get(FakeConnector fake, ArtifactDownload download) {
        new SigmundRepositoryConnector(session, REPO, fake, verifier).get(List.of(download), List.of());
    }

    private ArtifactDownload download(Artifact artifact) {
        return new ArtifactDownload(artifact, "", localPath(artifact), RepositoryPolicy.CHECKSUM_POLICY_FAIL);
    }

    private Path localPath(Artifact artifact) {
        return localRepository.getAbsolutePathForRemoteArtifact(artifact, REPO, "");
    }

    private List<String> registered() {
        return localRepository.getArtifactRegistration().stream()
                .map(Artifact::toString)
                .toList();
    }

    private Map<String, Path> signedFiles(Path artifactFile) {
        return Map.of(JAR.toString(), artifactFile, ASC.toString(), fixture.signature());
    }

    private Path tampered() throws IOException {
        Path tampered = Files.copy(fixture.artifact(), dir.resolve("tampered.jar"));
        Files.write(tampered, new byte[] { 1 }, StandardOpenOption.APPEND);
        return tampered;
    }
}
