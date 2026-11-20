package dev.cyberstamp.sigmund.resolver.generator;

import static org.assertj.core.api.Assertions.assertThat;

import dev.cyberstamp.sigmund.core.ArtifactOutcome;
import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.resolver.SigmundConfigurationKeys;
import dev.cyberstamp.sigmund.resolver.SigmundSessionVerifier;
import dev.cyberstamp.sigmund.resolver.TestKeys;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.deployment.DeployRequest;
import org.eclipse.aether.installation.InstallRequest;
import org.eclipse.aether.spi.artifact.ArtifactPredicate;
import org.eclipse.aether.spi.artifact.generator.ArtifactGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SigmundSignatureArtifactGeneratorTest {

    private static final ArtifactPredicate SIGNABLE = new ArtifactPredicate() {
        @Override
        public boolean isWithoutChecksum(Artifact artifact) {
            return artifact.getExtension().endsWith(".asc");
        }

        @Override
        public boolean isChecksum(Artifact artifact) {
            return artifact.getExtension().endsWith(".sha1");
        }
    };

    @TempDir
    Path dir;

    private TestKeys.Fixture fixture;
    private Artifact jar;
    private Artifact pom;

    @BeforeEach
    void setUp() throws IOException {
        fixture = TestKeys.create(dir.resolve("keys"));
        jar = new DefaultArtifact("org.example:lib:jar:1.0").setPath(fixture.artifact());
        pom = new DefaultArtifact("org.example:lib:pom:1.0")
                .setPath(Files.writeString(dir.resolve("lib-1.0.pom"), "<project/>"));
    }

    @Nested
    class Generating {

        @Test
        void eachArtifactGetsASignatureThatVerifies() {
            try (ArtifactGenerator generator = generator(List.of(jar, pom));
                    SigmundSessionVerifier verifier = SigmundSessionVerifier.create(fixture.configFile())) {
                List<Artifact> signatures = new ArrayList<>(generator.generate(List.of()));

                assertThat(signatures).extracting(Artifact::getExtension).containsExactly("jar.asc", "pom.asc");
                assertThat(signatures).allSatisfy(s -> assertThat(s.getPath()).isRegularFile());
                assertThat(verifier.verify(jar, jar.getPath(), List.of(signatures.get(0).getPath())).outcome())
                        .isEqualTo(ArtifactOutcome.SATISFIED);
            }
        }

        @Test
        void artifactsThePredicateRejectsAreNotSigned() {
            Artifact checksum = new DefaultArtifact("org.example:lib:jar.sha1:1.0").setPath(fixture.signature());
            try (ArtifactGenerator generator = generator(List.of(jar, checksum))) {
                assertThat(generator.generate(List.of())).extracting(Artifact::getExtension).containsExactly("jar.asc");
            }
        }

        @Test
        void itBacksOffWhenTheBuildAttachedSignatures() {
            Artifact attached = new DefaultArtifact("org.example:lib:jar.asc:1.0").setPath(fixture.signature());
            try (ArtifactGenerator generator = generator(List.of(jar, attached))) {
                assertThat(generator.generate(List.of())).isEmpty();
            }
        }

        @Test
        void closingDeletesTheSignatures() {
            Collection<? extends Artifact> signatures;
            try (ArtifactGenerator generator = generator(List.of(jar))) {
                signatures = generator.generate(List.of());
            }

            assertThat(signatures).allSatisfy(s -> assertThat(s.getPath()).doesNotExist());
        }
    }

    @Nested
    class Factory {

        private final DefaultRepositorySystemSession session = new DefaultRepositorySystemSession(h -> false);
        private final SigmundSignatureArtifactGeneratorFactory factory = new SigmundSignatureArtifactGeneratorFactory(
                s -> SIGNABLE, () -> dir.resolve("no-root"));

        @Test
        void signingIsOffByDefault() {
            assertThat(factory.newInstance(session, new DeployRequest().setArtifacts(List.of(jar)))).isNull();
        }

        @Test
        void installsAreNotSigned() {
            session.setConfigProperty(SigmundConfigurationKeys.CONFIG_PROP_SIGN_ENABLED, "true");

            assertThat(factory.newInstance(session, new InstallRequest().setArtifacts(List.of(jar)))).isNull();
        }

        @Test
        void deploysAreSignedWithTheConfiguredKey() throws IOException {
            Path config = Files.writeString(dir.resolve("signing.yaml"), """
                    signing:
                      toolchain: [bc]
                    tools:
                      bc:
                        cert-d-home: "%s"
                        bc-private-home: "%s"
                        gnupg-home: "%s"
                        signing-fingerprint: "%s"
                    """.formatted(dir.resolve("keys/cert-d"), dir.resolve("keys/bc-private"),
                    dir.resolve("keys/gnupg"), fixture.fingerprint()));
            session.setConfigProperty(SigmundConfigurationKeys.CONFIG_PROP_SIGN_ENABLED, "true");
            session.setConfigProperty(SigmundConfigurationKeys.CONFIG_PROP_CONFIG, config.toString());

            try (ArtifactGenerator generator = factory.newInstance(session, new DeployRequest().setArtifacts(List.of(jar)))) {
                assertThat(generator.generate(List.of())).extracting(Artifact::getExtension).containsExactly("jar.asc");
            }
        }
    }

    private ArtifactGenerator generator(List<Artifact> artifacts) {
        Sigmund sigmund = Sigmund.builder()
                .addSigningTool("bc", Map.of(
                        "cert-d-home", dir.resolve("keys/cert-d").toString(),
                        "bc-private-home", dir.resolve("keys/bc-private").toString(),
                        "gnupg-home", dir.resolve("keys/gnupg").toString(),
                        "signing-fingerprint", fixture.fingerprint()))
                .build();
        return new SigmundSignatureArtifactGenerator(artifacts, SIGNABLE::hasChecksums, sigmund);
    }
}
