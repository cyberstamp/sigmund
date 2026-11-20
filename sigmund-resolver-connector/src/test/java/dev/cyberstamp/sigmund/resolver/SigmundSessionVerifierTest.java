package dev.cyberstamp.sigmund.resolver;

import static org.assertj.core.api.Assertions.assertThat;

import dev.cyberstamp.sigmund.core.ArtifactOutcome;
import dev.cyberstamp.sigmund.core.EnforcementAction;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SigmundSessionVerifierTest {

    private static final Artifact LIB = new DefaultArtifact("org.example:lib:jar:1.0");

    @TempDir
    Path dir;

    private TestKeys.Fixture fixture;
    private SigmundSessionVerifier verifier;

    @BeforeEach
    void setUp() {
        fixture = TestKeys.create(dir);
        verifier = SigmundSessionVerifier.create(fixture.configFile());
    }

    @AfterEach
    void tearDown() {
        verifier.close();
    }

    @Test
    void signedArtifactIsSatisfied() {
        SigmundSessionVerifier.Verdict verdict = verifier.verify(LIB, fixture.artifact(), List.of(fixture.signature()));

        assertThat(verdict.outcome()).isEqualTo(ArtifactOutcome.SATISFIED);
        assertThat(verdict.blocks()).isFalse();
    }

    @Test
    void tamperedArtifactFailsAndBlocks() throws IOException {
        Path tampered = Files.copy(fixture.artifact(), dir.resolve("tampered.jar"));
        Files.write(tampered, new byte[] { 1 }, StandardOpenOption.APPEND);

        SigmundSessionVerifier.Verdict verdict = verifier.verify(LIB, tampered, List.of(fixture.signature()));

        assertThat(verdict.outcome()).isEqualTo(ArtifactOutcome.FAILED);
        assertThat(verdict.action()).isEqualTo(EnforcementAction.FAIL);
        assertThat(verdict.blocks()).isTrue();
    }

    @Test
    void messageSaysWhatHappenedAndWhichRuleDecided() throws IOException {
        Path tampered = Files.copy(fixture.artifact(), dir.resolve("tampered.jar"));
        Files.write(tampered, new byte[] { 1 }, StandardOpenOption.APPEND);

        String message = verifier.verify(LIB, tampered, List.of(fixture.signature())).message();

        assertThat(message).contains("org.example:lib", "FAILED", "FAIL", "org.example:*", "evidence ");
    }

    @Test
    void noClaimUnderAWarnPolicyWarnsWithoutBlocking() {
        TestKeys.Fixture warning = TestKeys.create(dir.resolve("warn"), "defaults:\n  on-no-claim: warn\n");
        try (SigmundSessionVerifier warnVerifier = SigmundSessionVerifier.create(warning.configFile())) {
            SigmundSessionVerifier.Verdict verdict = warnVerifier.verify(LIB, warning.artifact(), List.of());

            assertThat(verdict.outcome()).isEqualTo(ArtifactOutcome.NO_CLAIM);
            assertThat(verdict.action()).isEqualTo(EnforcementAction.WARN);
            assertThat(verdict.blocks()).isFalse();
        }
    }

    @Test
    void unsignedArtifactIsNoClaimAndBlocksByDefault() {
        SigmundSessionVerifier.Verdict verdict = verifier.verify(LIB, fixture.artifact(), List.of());

        assertThat(verdict.outcome()).isEqualTo(ArtifactOutcome.NO_CLAIM);
        assertThat(verdict.blocks()).isTrue();
    }

    @Test
    void unmatchedCoordinateIsNotConfiguredAndBlocksByDefault() {
        SigmundSessionVerifier.Verdict verdict = verifier.verify(
                new DefaultArtifact("com.other:x:jar:1"), fixture.artifact(), List.of(fixture.signature()));

        assertThat(verdict.outcome()).isEqualTo(ArtifactOutcome.NOT_CONFIGURED);
        assertThat(verdict.blocks()).isTrue();
    }

    @Test
    void signatureExtensionsContainAsc() {
        assertThat(verifier.signatureExtensions()).contains(".asc");
    }

    @Test
    void getReturnsOneVerifierPerSessionFromTheConfiguredFile() {
        List<Runnable> sessionEndedHandlers = new ArrayList<>();
        DefaultRepositorySystemSession session = new DefaultRepositorySystemSession(sessionEndedHandlers::add);
        session.setConfigProperty(SigmundConfigurationKeys.CONFIG_PROP_CONFIG, fixture.configFile().toString());

        Path elsewhere = dir.resolve("elsewhere");
        SigmundSessionVerifier first = SigmundSessionVerifier.get(session, elsewhere);
        try {
            assertThat(SigmundSessionVerifier.get(session, elsewhere)).isSameAs(first);
            assertThat(first.verify(LIB, fixture.artifact(), List.of(fixture.signature())).outcome())
                    .isEqualTo(ArtifactOutcome.SATISFIED);
            assertThat(sessionEndedHandlers).hasSize(1);
        } finally {
            sessionEndedHandlers.forEach(Runnable::run);
        }
    }

    @Test
    void getLocatesTheConfigInTheRootDirectory() {
        List<Runnable> sessionEndedHandlers = new ArrayList<>();
        DefaultRepositorySystemSession session = new DefaultRepositorySystemSession(sessionEndedHandlers::add);

        SigmundSessionVerifier located = SigmundSessionVerifier.get(session, fixture.configFile().getParent());
        try {
            assertThat(located.verify(LIB, fixture.artifact(), List.of()).outcome())
                    .as("the policy in the root directory applies")
                    .isEqualTo(ArtifactOutcome.NO_CLAIM);
            assertThat(located.verify(LIB, fixture.artifact(), List.of()).blocks()).isTrue();
        } finally {
            sessionEndedHandlers.forEach(Runnable::run);
        }
    }
}
