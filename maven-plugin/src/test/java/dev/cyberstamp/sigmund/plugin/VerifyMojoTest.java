package dev.cyberstamp.sigmund.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.cyberstamp.sigmund.core.ArtifactCoords;
import dev.cyberstamp.sigmund.core.ArtifactOutcome;
import dev.cyberstamp.sigmund.core.ArtifactResult;
import dev.cyberstamp.sigmund.core.ArtifactSubject;
import dev.cyberstamp.sigmund.core.ClaimOutcome;
import dev.cyberstamp.sigmund.core.ClaimResult;
import dev.cyberstamp.sigmund.core.ClaimSetMode;
import dev.cyberstamp.sigmund.core.ClaimTimeSource;
import dev.cyberstamp.sigmund.core.Credential;
import dev.cyberstamp.sigmund.core.DigestSet;
import dev.cyberstamp.sigmund.core.EnforcementAction;
import dev.cyberstamp.sigmund.core.Evidence;
import dev.cyberstamp.sigmund.core.EvidenceRef;
import dev.cyberstamp.sigmund.core.KeyCredential;
import dev.cyberstamp.sigmund.core.MatchedRule;
import dev.cyberstamp.sigmund.core.Rule;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.TrustPolicy;
import dev.cyberstamp.sigmund.core.TrustRootRef;
import dev.cyberstamp.sigmund.core.VerificationReport;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class VerifyMojoTest {

    @Nested
    class ConfigLoading {

        @TempDir
        Path basedir;

        private final RecordingLog log = new RecordingLog();

        private VerifyMojo mojoWithConfigAt(Path config) {
            VerifyMojo mojo = new VerifyMojo();
            mojo.setLog(log);
            MavenProject project = new MavenProject();
            project.setFile(basedir.resolve("pom.xml").toFile());
            mojo.project = project;
            mojo.trustConfigFile = config.toFile();
            return mojo;
        }

        @Test
        void missingConfigAtTheDefaultLocationIsZeroConfig() throws Exception {
            VerifyMojo mojo = mojoWithConfigAt(basedir.resolve("sigmund.yaml"));

            SigmundConfig config = mojo.loadAndValidateConfig();

            assertThat(config.trustPolicySpec().declared()).isFalse();
            assertThat(log.lines).anyMatch(line -> line.contains("observing only"));
        }

        @Test
        void missingConfigAtAnExplicitLocationIsError() {
            VerifyMojo mojo = mojoWithConfigAt(basedir.resolve("policies/strict.yaml"));

            assertThatThrownBy(mojo::loadAndValidateConfig)
                    .isInstanceOf(MojoExecutionException.class)
                    .hasMessageContaining("strict.yaml");
        }

        @Test
        void configWithoutRulesOrDefaultsObserves() throws Exception {
            Path file = basedir.resolve("sigmund.yaml");
            Files.writeString(file, """
                    issuers: [keys.openpgp.org]
                    signers: { alice: "alice@example.com" }
                    signing: { signer: alice }
                    """);
            VerifyMojo mojo = mojoWithConfigAt(file);

            SigmundConfig config = mojo.loadAndValidateConfig();

            assertThat(config.trustPolicySpec().declared()).isFalse();
            assertThat(log.lines).anyMatch(line -> line.contains("observing only"));
        }

        @Test
        void configWithRulesEnforces() throws Exception {
            Path file = basedir.resolve("sigmund.yaml");
            Files.writeString(file, "rules: []\n");
            VerifyMojo mojo = mojoWithConfigAt(file);

            SigmundConfig config = mojo.loadAndValidateConfig();

            assertThat(config.trustPolicySpec().declared()).isTrue();
            assertThat(log.lines).noneMatch(line -> line.contains("observing only"));
        }
    }

    @Nested
    class PomVerificationTests {

        private ArtifactCoords jarArtifact(String groupId, String artifactId, String version) {
            return new ArtifactCoords(groupId, artifactId, "", "jar", version);
        }

        @Test
        void addPomArtifactsCreatesPomForEachJar() {
            var mojo = new VerifyMojo();
            List<ArtifactCoords> artifacts = new ArrayList<>();
            artifacts.add(jarArtifact("com.example", "lib-a", "1.0"));
            artifacts.add(jarArtifact("com.example", "lib-b", "2.0"));

            mojo.addPomArtifacts(artifacts);

            assertThat(artifacts.size()).isEqualTo(4);
            ArtifactCoords pomA = artifacts.get(2);
            assertThat(pomA.namespace()).isEqualTo("com.example");
            assertThat(pomA.name()).isEqualTo("lib-a");
            assertThat(pomA.extension()).isEqualTo("pom");
            assertThat(pomA.version()).isEqualTo("1.0");

            ArtifactCoords pomB = artifacts.get(3);
            assertThat(pomB.name()).isEqualTo("lib-b");
            assertThat(pomB.extension()).isEqualTo("pom");
        }

        @Test
        void addPomArtifactsDeduplicatesSameGav() {
            var mojo = new VerifyMojo();
            List<ArtifactCoords> artifacts = new ArrayList<>();
            artifacts.add(jarArtifact("com.example", "lib", "1.0"));
            artifacts.add(new ArtifactCoords("com.example", "lib", "sources", "jar", "1.0"));

            mojo.addPomArtifacts(artifacts);

            assertThat(artifacts.size()).isEqualTo(3);
            assertThat(artifacts.get(2).extension()).isEqualTo("pom");
        }

        @Test
        void addPomArtifactsSkipsExistingPomArtifacts() {
            var mojo = new VerifyMojo();
            List<ArtifactCoords> artifacts = new ArrayList<>();
            artifacts.add(new ArtifactCoords(
                    "com.example", "parent", "", "pom", "1.0"));

            mojo.addPomArtifacts(artifacts);

            assertThat(artifacts.size()).isEqualTo(1);
        }
    }

    @Nested
    class Reporting {

        private static final String FP = "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12";

        private VerificationReport reportOf(ArtifactOutcome outcome, ClaimResult... claims) {
            return reportOf(outcome, EnforcementAction.FAIL, claims);
        }

        private VerificationReport reportOf(ArtifactOutcome outcome, EnforcementAction action,
                ClaimResult... claims) {
            return VerificationReport.of(List.of(resultFor("lib", outcome, null, claims)),
                    actingAs(action));
        }

        private ArtifactResult resultFor(String name, ArtifactOutcome outcome,
                MatchedRule matchedRule, ClaimResult... claims) {
            ArtifactCoords coords = new ArtifactCoords("com.example", name, "", "jar", "1.0");
            return new ArtifactResult(
                    new ArtifactSubject(coords, DigestSet.sha256(FP.toLowerCase())),
                    outcome, null, matchedRule, List.of(claims), List.of(), Instant.EPOCH);
        }

        private ClaimResult verifiedClaim() {
            return new ClaimResult("openpgp", ClaimOutcome.VERIFIED, null,
                    List.of(new KeyCredential(Credential.TYPE_PGP4, FP)),
                    "Alice <alice@example.com>",
                    TrustRootRef.certD(Path.of("/home/alice/.local/share/pgp.cert.d")),
                    new EvidenceRef(Path.of("lib-1.0.jar.asc"),
                            DigestSet.sha256(FP.toLowerCase()), Evidence.SOURCE_SIDECAR),
                    Instant.parse("2026-03-12T10:04:11Z"), ClaimTimeSource.SIGNER,
                    Instant.EPOCH, "Ed25519", "bc");
        }

        @Test
        void listsArtifactsUnderTheAttesterThatSignedThem() {
            RecordingLog log = new RecordingLog();
            VerifyMojo mojo = new VerifyMojo();
            mojo.setLog(log);

            mojo.reportResults(reportOf(ArtifactOutcome.SATISFIED, verifiedClaim()));

            assertThat(log.lines).containsSubsequence(
                    "info: SATISFIED (1)",
                    "info:   openpgp VERIFIED by bc (Ed25519) - Alice <alice@example.com> (unverified)",
                    "info:     com.example:lib:1.0");
        }

        @Test
        void saysNothingPerClaimUnlessDetailIsAskedFor() {
            RecordingLog log = new RecordingLog();
            VerifyMojo mojo = new VerifyMojo();
            mojo.setLog(log);

            mojo.reportResults(reportOf(ArtifactOutcome.SATISFIED, verifiedClaim()));

            assertThat(log.lines).noneMatch(line -> line.contains("evidence"))
                    .noneMatch(line -> line.contains("trust root"))
                    .noneMatch(line -> line.contains("credential"));
        }

        @Test
        void explainsTheGroupAndEachArtifactWhenDetailIsAskedFor() {
            RecordingLog log = new RecordingLog();
            VerifyMojo mojo = new VerifyMojo();
            mojo.setLog(log);
            mojo.detail = true;

            mojo.reportResults(reportOf(ArtifactOutcome.SATISFIED, verifiedClaim()));

            assertThat(log.lines).containsSubsequence(
                    "info:   openpgp VERIFIED by bc (Ed25519) - Alice <alice@example.com> (unverified)",
                    "info:     credential pgp4 " + FP,
                    "info:     trust root openpgp-cert-d /home/alice/.local/share/pgp.cert.d",
                    "info:     com.example:lib:1.0",
                    "info:       evidence lib-1.0.jar.asc sha256:4aee18f83afd (sidecar)",
                    "info:       claimed 2026-03-12T10:04:11Z (signer)");
        }

        /** Detail is logged at the severity of the outcome it explains, not always at info. */
        @Test
        void explainsAFailingArtifactAtTheSameSeverityAsItsOutcome() {
            RecordingLog log = new RecordingLog();
            VerifyMojo mojo = new VerifyMojo();
            mojo.setLog(log);
            mojo.detail = true;

            mojo.reportResults(reportOf(ArtifactOutcome.FAILED, verifiedClaim()));

            assertThat(log.lines).anyMatch(line -> line.startsWith("error:   openpgp VERIFIED"))
                    .anyMatch(line -> line.startsWith("error:       evidence"));
        }

        @Test
        void listsArtifactsNothingAttestedWithoutAGroupHeader() {
            RecordingLog log = new RecordingLog();
            VerifyMojo mojo = new VerifyMojo();
            mojo.setLog(log);

            mojo.reportResults(reportOf(ArtifactOutcome.NO_CLAIM, EnforcementAction.WARN));

            assertThat(log.lines).containsSubsequence(
                    "warn: NO_CLAIM (1)", "warn:     com.example:lib:1.0 [warning]");
        }

        @Test
        void ignoredArtifactsAreCountedButListedOnlyAtDebug() {
            RecordingLog log = new RecordingLog();
            VerifyMojo mojo = new VerifyMojo();
            mojo.setLog(log);

            mojo.reportResults(reportOf(ArtifactOutcome.NO_CLAIM, EnforcementAction.IGNORE));

            assertThat(log.lines).containsSubsequence(
                    "info: NO_CLAIM (1) — ignored: 1 with no policy",
                    "debug:     com.example:lib:1.0 [ignored]");
        }

        @Test
        void ignoredArtifactsAreListedWhenDetailIsAskedFor() {
            RecordingLog log = new RecordingLog();
            VerifyMojo mojo = new VerifyMojo();
            mojo.setLog(log);
            mojo.detail = true;

            mojo.reportResults(reportOf(ArtifactOutcome.NO_CLAIM, EnforcementAction.IGNORE));

            assertThat(log.lines).contains("info:     com.example:lib:1.0 [ignored]");
        }

        @Test
        void aBlockingOutcomeIsAnErrorWhateverItIs() {
            RecordingLog log = new RecordingLog();
            VerifyMojo mojo = new VerifyMojo();
            mojo.setLog(log);

            mojo.reportResults(reportOf(ArtifactOutcome.NOT_CONFIGURED, EnforcementAction.FAIL));

            assertThat(log.lines).containsSubsequence(
                    "error: NOT_CONFIGURED (1)", "error:     com.example:lib:1.0 [blocks]");
        }

        @Test
        void aSectionMixingActionsIsHeadedAtItsMostSevereAndListsEachAtItsOwn() {
            RecordingLog log = new RecordingLog();
            VerifyMojo mojo = new VerifyMojo();
            mojo.setLog(log);
            MatchedRule strict = new MatchedRule("com.example:strict", "rules[0]", Map.of());
            VerificationReport report = VerificationReport.of(List.of(
                    resultFor("strict", ArtifactOutcome.NO_CLAIM, strict),
                    resultFor("lenient", ArtifactOutcome.NO_CLAIM, null)),
                    failingOnlyUnder(strict));

            mojo.reportResults(report);

            assertThat(log.lines).contains(
                    "error: NO_CLAIM (2) — ignored: 1 with no policy",
                    "error:     com.example:strict:1.0 [blocks]",
                    "debug:     com.example:lenient:1.0 [ignored]");
        }

        private TrustPolicy actingAs(EnforcementAction action) {
            return policyDeciding((outcome, matchedRule) -> action);
        }

        private TrustPolicy failingOnlyUnder(MatchedRule strict) {
            return policyDeciding((outcome, matchedRule) -> strict.equals(matchedRule)
                    ? EnforcementAction.FAIL
                    : EnforcementAction.IGNORE);
        }

        private TrustPolicy policyDeciding(
                BiFunction<ArtifactOutcome, MatchedRule, EnforcementAction> decision) {
            return new TrustPolicy() {
                @Override
                public Rule matchRule(ArtifactCoords coords) {
                    return null;
                }

                @Override
                public ClaimSetMode claimSetMode() {
                    return ClaimSetMode.ALL_CLAIMS;
                }

                @Override
                public List<String> issuers() {
                    return List.of();
                }

                @Override
                public boolean declared() {
                    return false;
                }

                @Override
                public EnforcementAction enforcementFor(ArtifactOutcome outcome,
                        MatchedRule matchedRule) {
                    return decision.apply(outcome, matchedRule);
                }
            };
        }
    }
}
