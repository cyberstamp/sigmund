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
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
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

    @BeforeEach
    void setUp() {
        fixture = TestKeys.create(dir.resolve("fixture"));
        verifier = SigmundSessionVerifier.create(fixture.configFile());
    }

    @AfterEach
    void tearDown() {
        verifier.close();
    }

    @Test
    void signedArtifactPasses() {
        FakeConnector fake = new FakeConnector(signedFiles(fixture.artifact()));
        ArtifactDownload download = download(JAR);

        get(fake, download);

        assertThat(download.getException()).isNull();
        assertThat(download.getPath()).exists();
        assertThat(fake.seen).hasSize(2);
    }

    @Test
    void tamperedArtifactIsBlockedAndDeleted() throws IOException {
        FakeConnector fake = new FakeConnector(signedFiles(tampered()));
        ArtifactDownload download = download(JAR);

        get(fake, download);

        assertThat(download.getException()).isInstanceOf(SigmundVerificationException.class);
        assertThat(download.getPath()).doesNotExist();
    }

    @Test
    void missingSignatureIsNoClaimNotTransferError() {
        FakeConnector fake = new FakeConnector(Map.of(JAR.toString(), fixture.artifact()));
        ArtifactDownload download = download(JAR);

        get(fake, download);

        assertThat(download.getException())
                .as("on-no-claim defaults to fail with a policy")
                .isInstanceOf(SigmundVerificationException.class);
        assertThat(download.getPath()).doesNotExist();
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

    @Test
    void tempDirCleanedUp() throws IOException {
        Set<Path> before = sigmundTempDirs();

        get(new FakeConnector(signedFiles(fixture.artifact())), download(JAR));
        get(new FakeConnector(signedFiles(tampered())), download(JAR));

        assertThat(sigmundTempDirs()).isEqualTo(before);
    }

    @Test
    void tempDirCleanedUpWhenDelegateThrows() throws IOException {
        Set<Path> before = sigmundTempDirs();
        FakeConnector throwing = new FakeConnector(Map.of()) {
            @Override
            public void get(
                    Collection<? extends ArtifactDownload> artifactDownloads,
                    Collection<? extends MetadataDownload> md) {
                throw new IllegalStateException("delegate broke");
            }
        };

        assertThatThrownBy(() -> get(throwing, download(JAR))).isInstanceOf(IllegalStateException.class);

        assertThat(sigmundTempDirs()).isEqualTo(before);
    }

    private void get(FakeConnector fake, ArtifactDownload download) {
        new SigmundRepositoryConnector(REPO, fake, verifier).get(List.of(download), List.of());
    }

    private ArtifactDownload download(Artifact artifact) {
        Path path = dir.resolve("local").resolve(artifact.getArtifactId() + "-" + artifact.getVersion() + "."
                + artifact.getExtension());
        return new ArtifactDownload(artifact, "", path, RepositoryPolicy.CHECKSUM_POLICY_FAIL);
    }

    private Map<String, Path> signedFiles(Path artifactFile) {
        return Map.of(JAR.toString(), artifactFile, ASC.toString(), fixture.signature());
    }

    private Path tampered() throws IOException {
        Path tampered = Files.copy(fixture.artifact(), dir.resolve("tampered.jar"));
        Files.write(tampered, new byte[] { 1 }, StandardOpenOption.APPEND);
        return tampered;
    }

    private static Set<Path> sigmundTempDirs() throws IOException {
        try (Stream<Path> entries = Files.list(Path.of(System.getProperty("java.io.tmpdir")))) {
            return entries.filter(p -> p.getFileName().toString().startsWith("sigmund-"))
                    .collect(Collectors.toSet());
        }
    }
}
