package dev.cyberstamp.sigmund.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import dev.cyberstamp.sigmund.core.ArtifactCoords;
import dev.cyberstamp.sigmund.core.ArtifactOutcome;
import dev.cyberstamp.sigmund.core.ArtifactResult;
import dev.cyberstamp.sigmund.core.ArtifactSubject;
import dev.cyberstamp.sigmund.core.AttesterRole;
import dev.cyberstamp.sigmund.core.ClaimOutcome;
import dev.cyberstamp.sigmund.core.ClaimResult;
import dev.cyberstamp.sigmund.core.ClaimTimeSource;
import dev.cyberstamp.sigmund.core.Credential;
import dev.cyberstamp.sigmund.core.DigestSet;
import dev.cyberstamp.sigmund.core.Evidence;
import dev.cyberstamp.sigmund.core.EvidenceRef;
import dev.cyberstamp.sigmund.core.FingerprintCredential;
import dev.cyberstamp.sigmund.core.ListedEvidencePolicy;
import dev.cyberstamp.sigmund.core.SignerIdentity;
import dev.cyberstamp.sigmund.core.TrustPolicy;
import dev.cyberstamp.sigmund.core.TrustRootRef;
import dev.cyberstamp.sigmund.core.UnlistedEvidencePolicy;
import dev.cyberstamp.sigmund.core.UntrustedPolicy;
import dev.cyberstamp.sigmund.core.VerificationReport;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class VerifyMojoTest {

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
            ArtifactCoords coords = new ArtifactCoords("com.example", "lib", "", "jar", "1.0");
            ArtifactResult result = new ArtifactResult(
                    new ArtifactSubject(coords, DigestSet.sha256(FP.toLowerCase())),
                    outcome, null, List.of(claims), Instant.EPOCH);
            return VerificationReport.of(List.of(result), permissivePolicy());
        }

        private ClaimResult verifiedClaim() {
            return new ClaimResult("openpgp", ClaimOutcome.VERIFIED, null,
                    List.of(new FingerprintCredential(Credential.TYPE_OPENPGP_V4, FP)),
                    "Alice <alice@example.com>", AttesterRole.UNKNOWN,
                    TrustRootRef.keyring(Path.of("/home/alice/.local/share/pgp.cert.d")),
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
                    "info:   openpgp VERIFIED by bc (Ed25519) - Alice <alice@example.com>",
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
                    "info:   openpgp VERIFIED by bc (Ed25519) - Alice <alice@example.com>",
                    "info:     credential openpgp4 " + FP,
                    "info:     trust root openpgp-keyring /home/alice/.local/share/pgp.cert.d",
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

            mojo.reportResults(reportOf(ArtifactOutcome.NO_CLAIM));

            assertThat(log.lines).containsSubsequence(
                    "warn: NO_CLAIM (1)", "warn:     com.example:lib:1.0");
        }

        private TrustPolicy permissivePolicy() {
            return new TrustPolicy() {
                @Override
                public List<SignerIdentity> expectedSigners(ArtifactCoords artifact) {
                    return List.of();
                }

                @Override
                public boolean isUnsignedAllowed(ArtifactCoords artifact) {
                    return true;
                }

                @Override
                public ListedEvidencePolicy listedEvidence() {
                    return ListedEvidencePolicy.ALL;
                }

                @Override
                public UnlistedEvidencePolicy unlistedEvidence() {
                    return UnlistedEvidencePolicy.IGNORE;
                }

                @Override
                public UntrustedPolicy onUntrusted() {
                    return UntrustedPolicy.WARN;
                }
            };
        }
    }
}
