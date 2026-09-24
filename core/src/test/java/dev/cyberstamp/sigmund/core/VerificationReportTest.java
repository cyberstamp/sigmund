package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class VerificationReportTest {

    private static final String FP = "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12";
    private static final SignerIdentity ALICE = new SignerIdentity("alice", "Alice",
            List.of(new FingerprintCredential(Credential.TYPE_OPENPGP_V4, FP)));

    private static ArtifactResult result(String name, ArtifactOutcome outcome,
            IndeterminateReason reason, ClaimResult... claims) {
        ArtifactCoords coords = new ArtifactCoords("org.example", name, "", "jar", "1.0");
        ArtifactSubject subject = new ArtifactSubject(coords, DigestSet.sha256(FP.toLowerCase()));
        return new ArtifactResult(subject, outcome, reason, List.of(claims), Instant.EPOCH);
    }

    private static ClaimResult claim(String attester) {
        return new ClaimResult("openpgp", ClaimOutcome.VERIFIED, null, List.of(), attester,
                AttesterRole.UNKNOWN, TrustRootRef.unknown(),
                new EvidenceRef(Path.of("lib.jar.asc"), DigestSet.sha256(FP.toLowerCase()),
                        Evidence.SOURCE_SIDECAR),
                null, ClaimTimeSource.SIGNER, Instant.EPOCH, "RSA", "bc");
    }

    private static TrustPolicy policy(UntrustedPolicy onUntrusted, List<String> unsigned) {
        return new DefaultTrustPolicy(Map.of("org.example", List.of(ALICE)), unsigned,
                ListedEvidencePolicy.ALL, UnlistedEvidencePolicy.IGNORE, onUntrusted);
    }

    @Nested
    class AttesterGrouping {

        private static final EvidenceRef REF = new EvidenceRef(Path.of("lib-1.0.jar.asc"),
                DigestSet.sha256("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
                Evidence.SOURCE_SIDECAR);

        private static ClaimResult by(String attester, String fingerprint) {
            return new ClaimResult("openpgp", ClaimOutcome.VERIFIED, null,
                    List.of(new FingerprintCredential(Credential.TYPE_OPENPGP_V4, fingerprint)),
                    attester, AttesterRole.UNKNOWN,
                    TrustRootRef.keyring(Path.of("/home/alice/.local/share/pgp.cert.d")), REF,
                    Instant.parse("2026-03-12T10:04:11Z"), ClaimTimeSource.SIGNER,
                    Instant.EPOCH, "Ed25519", "bc");
        }

        @Test
        void artifactsAttestedAlikeShareOneGroup() {
            List<VerificationReport.AttesterGroup> groups = VerificationReport.groupByAttester(
                    List.of(result("lib", ArtifactOutcome.SATISFIED, null, by("Alice", FP)),
                            result("other", ArtifactOutcome.SATISFIED, null, by("Alice", FP))));

            assertThat(groups).hasSize(1);
            assertThat(groups.get(0).summary()).containsExactly(
                    "openpgp VERIFIED by bc (Ed25519) - Alice");
            assertThat(groups.get(0).artifacts()).hasSize(2);
        }

        @Test
        void carriesWhatTheWholeGroupSharesOnceRatherThanPerArtifact() {
            List<VerificationReport.AttesterGroup> groups = VerificationReport.groupByAttester(
                    List.of(result("lib", ArtifactOutcome.SATISFIED, null, by("Alice", FP))));

            assertThat(groups.get(0).detail()).containsExactly(
                    "  credential openpgp4 " + FP,
                    "  trust root openpgp-keyring /home/alice/.local/share/pgp.cert.d");
        }

        @Test
        void differentAttestersFormDifferentGroups() {
            String otherFp = "1234567890ABCDEF1234567890ABCDEF12345678";

            List<VerificationReport.AttesterGroup> groups = VerificationReport.groupByAttester(
                    List.of(result("lib", ArtifactOutcome.SATISFIED, null, by("Alice", FP)),
                            result("other", ArtifactOutcome.SATISFIED, null, by("Bob", otherFp))));

            assertThat(groups).hasSize(2);
            assertThat(groups.get(0).summary().get(0)).endsWith("Alice");
            assertThat(groups.get(1).summary().get(0)).endsWith("Bob");
        }

        /** The same key with a different display name is the same key, not two signers. */
        @Test
        void groupsAreOrderedTheSameWayEveryRun() {
            String otherFp = "1234567890ABCDEF1234567890ABCDEF12345678";
            List<ArtifactResult> results = List.of(
                    result("z", ArtifactOutcome.SATISFIED, null, by("Bob", otherFp)),
                    result("a", ArtifactOutcome.SATISFIED, null, by("Alice", FP)));

            List<ArtifactResult> reversed = new ArrayList<>(results);
            Collections.reverse(reversed);

            assertThat(VerificationReport.groupByAttester(results).stream()
                    .map(group -> group.summary().get(0)).toList())
                    .isEqualTo(VerificationReport.groupByAttester(reversed).stream()
                            .map(group -> group.summary().get(0)).toList());
        }

        @Test
        void artifactsAreListedInCoordinateOrderWithinAGroup() {
            List<VerificationReport.AttesterGroup> groups = VerificationReport.groupByAttester(
                    List.of(result("zebra", ArtifactOutcome.SATISFIED, null, by("Alice", FP)),
                            result("apple", ArtifactOutcome.SATISFIED, null, by("Alice", FP))));

            assertThat(groups.get(0).artifacts().stream()
                    .map(r -> r.subject().coords().name()).toList())
                    .containsExactly("apple", "zebra");
        }

        @Test
        void anArtifactAttestedTwiceIsListedOnceUnderBothClaims() {
            String otherFp = "1234567890ABCDEF1234567890ABCDEF12345678";

            List<VerificationReport.AttesterGroup> groups = VerificationReport.groupByAttester(
                    List.of(result("lib", ArtifactOutcome.SATISFIED, null,
                            by("Alice", FP), by("Release Bot", otherFp))));

            assertThat(groups).hasSize(1);
            assertThat(groups.get(0).summary()).hasSize(2);
            assertThat(groups.get(0).artifacts()).hasSize(1);
        }

        @Test
        void aClaimThatCouldNotBeDecidedCarriesItsReasonAndRole() {
            ClaimResult unresolved = new ClaimResult("openpgp", ClaimOutcome.INDETERMINATE,
                    IndeterminateReason.KEY_UNAVAILABLE, List.of(), null, AttesterRole.PUBLISHER,
                    TrustRootRef.unknown(), REF, null, ClaimTimeSource.SIGNER, Instant.EPOCH,
                    null, "sq");

            List<VerificationReport.AttesterGroup> groups = VerificationReport.groupByAttester(
                    List.of(result("lib", ArtifactOutcome.INDETERMINATE,
                            IndeterminateReason.KEY_UNAVAILABLE, unresolved)));

            assertThat(groups.get(0).summary()).containsExactly(
                    "openpgp INDETERMINATE (KEY_UNAVAILABLE) by sq [publisher]");
            assertThat(groups.get(0).detail()).isEmpty();
        }

        @Test
        void artifactsWithNoClaimFormAnUnattributedGroupThatComesLast() {
            List<VerificationReport.AttesterGroup> groups = VerificationReport.groupByAttester(
                    List.of(result("nothing", ArtifactOutcome.NO_CLAIM, null),
                            result("lib", ArtifactOutcome.SATISFIED, null, by("Alice", FP))));

            assertThat(groups).hasSize(2);
            assertThat(groups.get(1).summary()).isEmpty();
            assertThat(groups.get(1).artifacts().get(0).subject().coords().name())
                    .isEqualTo("nothing");
        }
    }

    @Nested
    class ClaimDetail {

        private static final EvidenceRef REF = new EvidenceRef(Path.of("lib-1.0.jar.asc"),
                DigestSet.sha256("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
                Evidence.SOURCE_SIDECAR);

        private static ClaimResult detailedClaim(Instant claimTime) {
            return new ClaimResult("openpgp", ClaimOutcome.VERIFIED, null,
                    List.of(new FingerprintCredential(Credential.TYPE_OPENPGP_V4, FP)),
                    "Alice <alice@example.com>", AttesterRole.PUBLISHER,
                    TrustRootRef.keyring(Path.of("/home/alice/.local/share/pgp.cert.d")), REF,
                    claimTime, ClaimTimeSource.SIGNER, Instant.parse("2026-09-24T08:00:00Z"),
                    "Ed25519", "bc");
        }

        @Test
        void namesTheEvidenceTheClaimWasReadFrom() {
            List<String> lines = VerificationReport.explain(
                    result("lib", ArtifactOutcome.SATISFIED, null,
                            detailedClaim(Instant.parse("2026-03-12T10:04:11Z"))));

            assertThat(lines).contains("evidence lib-1.0.jar.asc sha256:ba7816bf8f01 (sidecar)");
        }

        @Test
        void namesWhenTheClaimWasMadeAndWhoSaidSo() {
            List<String> lines = VerificationReport.explain(
                    result("lib", ArtifactOutcome.SATISFIED, null,
                            detailedClaim(Instant.parse("2026-03-12T10:04:11Z"))));

            assertThat(lines).contains("claimed 2026-03-12T10:04:11Z (signer)");
        }

        @Test
        void omitsAClaimTimeTheToolCouldNotRecord() {
            List<String> lines = VerificationReport.explain(
                    result("lib", ArtifactOutcome.SATISFIED, null, detailedClaim(null)));

            assertThat(lines).noneMatch(line -> line.startsWith("claimed"));
        }

        /** Who attested is the group's to say; this repeats none of it per artifact. */
        @Test
        void leavesTheAttesterToTheGroup() {
            List<String> lines = VerificationReport.explain(
                    result("lib", ArtifactOutcome.SATISFIED, null,
                            detailedClaim(Instant.parse("2026-03-12T10:04:11Z"))));

            assertThat(lines).noneMatch(line -> line.contains("Alice"))
                    .noneMatch(line -> line.contains("credential"))
                    .noneMatch(line -> line.contains("trust root"));
        }

        @Test
        void explainsEveryClaimFoundForTheArtifact() {
            List<String> lines = VerificationReport.explain(
                    result("lib", ArtifactOutcome.SATISFIED, null,
                            detailedClaim(Instant.parse("2026-03-12T10:04:11Z")),
                            detailedClaim(Instant.parse("2026-03-12T10:04:11Z"))));

            assertThat(lines.stream().filter(line -> line.startsWith("evidence "))).hasSize(2);
        }

        @Test
        void anArtifactWithoutClaimsExplainsNothing() {
            assertThat(VerificationReport.explain(result("lib", ArtifactOutcome.NO_CLAIM, null)))
                    .isEmpty();
        }
    }

    @Nested
    class Grouping {

        @Test
        void groupsByOutcomeAndCounts() {
            VerificationReport report = VerificationReport.of(List.of(
                    result("a", ArtifactOutcome.SATISFIED, null),
                    result("b", ArtifactOutcome.SATISFIED, null),
                    result("c", ArtifactOutcome.NO_CLAIM, null)),
                    policy(UntrustedPolicy.FAIL, List.of()));

            assertThat(report.counts()).containsEntry(ArtifactOutcome.SATISFIED, 2)
                    .containsEntry(ArtifactOutcome.NO_CLAIM, 1);
            assertThat(report.byOutcome().get(ArtifactOutcome.SATISFIED)).hasSize(2);
        }

        @Test
        void groupsAreOrderedByTheOutcomeVocabulary() {
            VerificationReport report = VerificationReport.of(List.of(
                    result("a", ArtifactOutcome.NO_CLAIM, null),
                    result("b", ArtifactOutcome.FAILED, null),
                    result("c", ArtifactOutcome.SATISFIED, null)),
                    policy(UntrustedPolicy.FAIL, List.of()));

            // reports read the same way every run: the order is the enum's, not the order
            // artifacts happened to be resolved in
            assertThat(report.byOutcome().keySet()).containsExactly(
                    ArtifactOutcome.SATISFIED, ArtifactOutcome.FAILED, ArtifactOutcome.NO_CLAIM);
        }

        @Test
        void theGroupingCannotBeModifiedByCallers() {
            VerificationReport report = VerificationReport.of(
                    List.of(result("a", ArtifactOutcome.SATISFIED, null)),
                    policy(UntrustedPolicy.FAIL, List.of()));

            assertThatThrownBy(() -> report.byOutcome().clear())
                    .isInstanceOf(UnsupportedOperationException.class);
            assertThatThrownBy(
                    () -> report.byOutcome().get(ArtifactOutcome.SATISFIED).clear())
                    .isInstanceOf(UnsupportedOperationException.class);
        }

        @Test
        void countsOnlyWhatWasSeen() {
            VerificationReport report = VerificationReport.of(
                    List.of(result("a", ArtifactOutcome.SATISFIED, null)),
                    policy(UntrustedPolicy.FAIL, List.of()));

            assertThat(report.counts()).doesNotContainKey(ArtifactOutcome.FAILED);
        }
    }

    @Nested
    class TheFailureDecision {

        @Test
        void aFailedSignatureAlwaysBlocks() {
            VerificationReport report = VerificationReport.of(
                    List.of(result("a", ArtifactOutcome.FAILED, null)),
                    policy(UntrustedPolicy.WARN, List.of()));

            assertThat(report.blocking()).hasSize(1);
        }

        @Test
        void anUnsatisfiedArtifactBlocksWhenPolicySaysSo() {
            List<ArtifactResult> results = List.of(result("a", ArtifactOutcome.UNSATISFIED, null));

            assertThat(VerificationReport.of(results, policy(UntrustedPolicy.FAIL, List.of()))
                    .blocking()).hasSize(1);
            assertThat(VerificationReport.of(results, policy(UntrustedPolicy.WARN, List.of()))
                    .blocking()).isEmpty();
        }

        @Test
        void missingEvidenceBlocksUnlessPolicyToleratesIt() {
            List<ArtifactResult> results = List.of(result("a", ArtifactOutcome.NO_CLAIM, null));

            assertThat(VerificationReport.of(results, policy(UntrustedPolicy.FAIL, List.of()))
                    .blocking()).hasSize(1);
            assertThat(VerificationReport
                    .of(results, policy(UntrustedPolicy.FAIL, List.of("org.example:a")))
                    .blocking()).isEmpty();
        }

        @Test
        void anArtifactNoRuleCoversDoesNotBlock() {
            VerificationReport report = VerificationReport.of(
                    List.of(result("a", ArtifactOutcome.NOT_CONFIGURED, null)),
                    policy(UntrustedPolicy.FAIL, List.of()));

            assertThat(report.blocking()).isEmpty();
        }

        @Test
        void aToleratedArtifactStillBlocksOnABrokenSignature() {
            // the point of verifying rather than skipping: policy tolerates missing evidence,
            // not evidence that fails
            VerificationReport report = VerificationReport.of(
                    List.of(result("a", ArtifactOutcome.FAILED, null)),
                    policy(UntrustedPolicy.FAIL, List.of("org.example:a")));

            assertThat(report.blocking()).hasSize(1);
        }
    }
}
