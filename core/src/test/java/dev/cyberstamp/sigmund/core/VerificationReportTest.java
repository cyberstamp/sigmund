package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class VerificationReportTest {

    private static final String FP = "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12";

    private static ArtifactResult result(String name, ArtifactOutcome outcome,
            IndeterminateReason reason, ClaimResult... claims) {
        return result(name, outcome, reason, null, claims);
    }

    private static ArtifactResult result(String name, ArtifactOutcome outcome,
            IndeterminateReason reason, MatchedRule matchedRule, ClaimResult... claims) {
        ArtifactCoords coords = new ArtifactCoords("org.example", name, "", "jar", "1.0");
        ArtifactSubject subject = new ArtifactSubject(coords, DigestSet.sha256(FP.toLowerCase()));
        return new ArtifactResult(subject, outcome, reason, matchedRule, List.of(claims),
                Instant.EPOCH);
    }

    private static VerificationReport reportFor(TrustPolicy policy, List<ArtifactResult> results) {
        return VerificationReport.of(results, policy);
    }

    private static TrustPolicy requiring(String pattern, String signerId) {
        var signer = new SignerIdentity(signerId,
                List.of(new KeyCredential(Credential.TYPE_PGP4, FP)));
        var spec = new TrustPolicySpec(
                List.of(new RuleSpec(List.of(ArtifactPattern.parse(pattern)),
                        List.of(Set.of(signerId)), Map.of(), "rules[0]", null)),
                ClaimSetMode.ALL_CLAIMS, Map.of(), List.of(), true);
        return RulePolicy.compile(spec, new SignersConfig(Map.of(signerId, signer)));
    }

    private static TrustPolicy catchAllIgnore() {
        var spec = new TrustPolicySpec(
                List.of(new RuleSpec(List.of(ArtifactPattern.parse("*")), List.of(),
                        Map.of(ArtifactOutcome.NO_CLAIM, EnforcementAction.IGNORE), "rules[0]", null)),
                ClaimSetMode.ALL_CLAIMS, Map.of(), List.of(), true);
        return RulePolicy.compile(spec, SignersConfig.EMPTY);
    }

    @Nested
    class EnforcementInTheReport {

        private static MatchedRule matched(TrustPolicy policy, String name) {
            ArtifactCoords coords = new ArtifactCoords("org.example", name, "", "jar", "1.0");
            return policy.matchRule(coords).toMatchedRule(coords);
        }

        private static TrustPolicy ignoringByRuleAndByDefaults() {
            var spec = new TrustPolicySpec(List.of(
                    new RuleSpec(List.of(ArtifactPattern.parse("org.example:a")), List.of(),
                            Map.of(ArtifactOutcome.NO_CLAIM, EnforcementAction.IGNORE),
                            "rules[0]", null),
                    new RuleSpec(List.of(ArtifactPattern.parse("org.example:*")), List.of(),
                            Map.of(), "rules[1]", null)),
                    ClaimSetMode.ALL_CLAIMS,
                    Map.of(ArtifactOutcome.NO_CLAIM, EnforcementAction.IGNORE), List.of(), true);
            return RulePolicy.compile(spec, SignersConfig.EMPTY);
        }

        @Test
        void eachResultCarriesTheActionThePolicyResolvesForIt() {
            TrustPolicy policy = catchAllIgnore();
            ArtifactResult tolerated = result("x", ArtifactOutcome.NO_CLAIM, null,
                    matched(policy, "x"));
            ArtifactResult broken = result("y", ArtifactOutcome.FAILED, null, matched(policy, "y"));
            VerificationReport report = reportFor(policy, List.of(tolerated, broken));

            assertThat(report.enforcement(tolerated)).isEqualTo(EnforcementAction.IGNORE);
            assertThat(report.enforcement(broken)).isEqualTo(EnforcementAction.FAIL);
        }

        @Test
        void headingCountsAnOutcomeNothingIgnored() {
            VerificationReport report = reportFor(requiring("org.example:*", "a"),
                    List.of(result("a", ArtifactOutcome.NO_CLAIM, null)));

            assertThat(report.heading(ArtifactOutcome.NO_CLAIM)).isEqualTo("NO_CLAIM (1)");
        }

        @Test
        void headingNamesTheRuleThatIgnoredArtifacts() {
            TrustPolicy policy = catchAllIgnore();
            VerificationReport report = reportFor(policy, List.of(
                    result("x", ArtifactOutcome.NO_CLAIM, null, matched(policy, "x")),
                    result("y", ArtifactOutcome.NO_CLAIM, null, matched(policy, "y"))));

            assertThat(report.heading(ArtifactOutcome.NO_CLAIM))
                    .isEqualTo("NO_CLAIM (2) — ignored: 2 by rules[0] '*'");
        }

        @Test
        void headingSplitsIgnoredArtifactsByWhereTheActionCameFrom() {
            TrustPolicy policy = ignoringByRuleAndByDefaults();
            VerificationReport report = reportFor(policy, List.of(
                    result("a", ArtifactOutcome.NO_CLAIM, null, matched(policy, "a")),
                    result("b", ArtifactOutcome.NO_CLAIM, null, matched(policy, "b")),
                    result("c", ArtifactOutcome.NO_CLAIM, null, matched(policy, "c"))));

            assertThat(report.heading(ArtifactOutcome.NO_CLAIM)).isEqualTo(
                    "NO_CLAIM (3) — ignored: 2 by defaults, 1 by rules[0] 'org.example:a'");
        }

        @Test
        void headingSaysWhenNothingIsEnforcedForLackOfAPolicy() {
            VerificationReport report = reportFor(RulePolicy.EMPTY,
                    List.of(result("a", ArtifactOutcome.NOT_CONFIGURED, null)));

            assertThat(report.heading(ArtifactOutcome.NOT_CONFIGURED))
                    .isEqualTo("NOT_CONFIGURED (1) — ignored: 1 with no policy");
        }

        @Test
        void headingOfSatisfiedArtifactsMentionsNoEnforcement() {
            VerificationReport report = reportFor(RulePolicy.EMPTY,
                    List.of(result("a", ArtifactOutcome.SATISFIED, null)));

            assertThat(report.heading(ArtifactOutcome.SATISFIED)).isEqualTo("SATISFIED (1)");
        }

        @Test
        void artifactLineIsTaggedWithWhatItsOutcomeDoes() {
            TrustPolicy policy = catchAllIgnore();
            ArtifactResult blocking = result("a", ArtifactOutcome.FAILED, null, matched(policy, "a"));
            ArtifactResult ignored = result("b", ArtifactOutcome.NO_CLAIM, null, matched(policy, "b"));
            ArtifactResult satisfied = result("c", ArtifactOutcome.SATISFIED, null,
                    matched(policy, "c"));
            VerificationReport report = reportFor(policy,
                    List.of(blocking, ignored, satisfied));

            assertThat(report.describe(blocking)).isEqualTo("org.example:a:1.0 [blocks]");
            assertThat(report.describe(ignored)).isEqualTo("org.example:b:1.0 [ignored]");
            assertThat(report.describe(satisfied)).isEqualTo("org.example:c:1.0");
        }

        @Test
        void artifactLineIsTaggedAsAWarningWhenTheRuleWarns() {
            var spec = new TrustPolicySpec(List.of(new RuleSpec(
                    List.of(ArtifactPattern.parse("*")), List.of(),
                    Map.of(ArtifactOutcome.NO_CLAIM, EnforcementAction.WARN), "rules[0]", null)),
                    ClaimSetMode.ALL_CLAIMS, Map.of(), List.of(), true);
            TrustPolicy policy = RulePolicy.compile(spec, SignersConfig.EMPTY);
            ArtifactResult warned = result("a", ArtifactOutcome.NO_CLAIM, null, matched(policy, "a"));

            assertThat(reportFor(policy, List.of(warned)).describe(warned))
                    .isEqualTo("org.example:a:1.0 [warning]");
        }
    }

    @Nested
    class AttesterGrouping {

        private static final EvidenceRef REF = new EvidenceRef(Path.of("lib-1.0.jar.asc"),
                DigestSet.sha256("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
                Evidence.SOURCE_SIDECAR);

        private static ClaimResult by(String attester, String fingerprint) {
            return new ClaimResult("openpgp", ClaimOutcome.VERIFIED, null,
                    List.of(new KeyCredential(Credential.TYPE_PGP4, fingerprint)),
                    attester,
                    TrustRootRef.certD(Path.of("/home/alice/.local/share/pgp.cert.d")), REF,
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
                    "  credential pgp4 " + FP,
                    "  trust root openpgp-cert-d /home/alice/.local/share/pgp.cert.d");
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
        void aClaimThatCouldNotBeDecidedCarriesItsReason() {
            ClaimResult unresolved = new ClaimResult("openpgp", ClaimOutcome.INDETERMINATE,
                    IndeterminateReason.KEY_UNAVAILABLE, List.of(), null,
                    TrustRootRef.unknown(), REF, null, ClaimTimeSource.SIGNER, Instant.EPOCH,
                    null, "sq");

            List<VerificationReport.AttesterGroup> groups = VerificationReport.groupByAttester(
                    List.of(result("lib", ArtifactOutcome.INDETERMINATE,
                            IndeterminateReason.KEY_UNAVAILABLE, unresolved)));

            assertThat(groups.get(0).summary()).containsExactly(
                    "openpgp INDETERMINATE (KEY_UNAVAILABLE) by sq");
            assertThat(groups.get(0).detail()).isEmpty();
        }

        @Test
        void aReasonCarriesTheToolsDetail() {
            ClaimResult unresolved = new ClaimResult("openpgp", ClaimOutcome.INDETERMINATE,
                    IndeterminateReason.KEY_UNAVAILABLE, List.of(), null,
                    TrustRootRef.unknown(), REF, null, ClaimTimeSource.SIGNER, Instant.EPOCH,
                    null, "bc", null, "no local key store or configured keyserver has it");

            List<VerificationReport.AttesterGroup> groups = VerificationReport.groupByAttester(
                    List.of(result("lib", ArtifactOutcome.INDETERMINATE,
                            IndeterminateReason.KEY_UNAVAILABLE, unresolved)));

            assertThat(groups.get(0).summary()).containsExactly(
                    "openpgp INDETERMINATE (KEY_UNAVAILABLE: no local key store or configured keyserver has it) by bc");
        }

        /** Without it an operator told the signer is not accepted cannot tell which key to add. */
        @Test
        void anUncheckableClaimNamesTheKeyItDeclaresAsUnverified() {
            String pqc = "CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9";
            ClaimResult uncheckable = new ClaimResult("openpgp", ClaimOutcome.INDETERMINATE,
                    IndeterminateReason.UNSUPPORTED_ALGORITHM, List.of(), null,
                    TrustRootRef.unknown(), REF, null, ClaimTimeSource.SIGNER, Instant.EPOCH,
                    "ML-DSA-87+Ed448", null, KeyCredential.openPgp(pqc), null);

            List<VerificationReport.AttesterGroup> groups = VerificationReport.groupByAttester(
                    List.of(result("lib", ArtifactOutcome.UNSATISFIED, null, uncheckable)));

            assertThat(groups.get(0).detail()).containsExactly(
                    "  declared issuer pgp6 " + pqc + " (not verified)");
        }

        @Test
        void aDeclaredIssuerTheClaimProvedIsNotRepeated() {
            ClaimResult verified = new ClaimResult("openpgp", ClaimOutcome.VERIFIED, null,
                    List.of(KeyCredential.openPgp(FP)), "Alice", TrustRootRef.unknown(), REF,
                    null, ClaimTimeSource.SIGNER, Instant.EPOCH, "Ed25519", "bc",
                    KeyCredential.openPgp(FP), null);

            List<VerificationReport.AttesterGroup> groups = VerificationReport.groupByAttester(
                    List.of(result("lib", ArtifactOutcome.SATISFIED, null, verified)));

            assertThat(groups.get(0).detail()).containsExactly("  credential pgp4 " + FP);
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
                    List.of(new KeyCredential(Credential.TYPE_PGP4, FP)),
                    "Alice <alice@example.com>",
                    TrustRootRef.certD(Path.of("/home/alice/.local/share/pgp.cert.d")), REF,
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
                    RulePolicy.EMPTY);

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
                    RulePolicy.EMPTY);

            // reports read the same way every run: the order is the enum's, not the order
            // artifacts happened to be resolved in
            assertThat(report.byOutcome().keySet()).containsExactly(
                    ArtifactOutcome.SATISFIED, ArtifactOutcome.FAILED, ArtifactOutcome.NO_CLAIM);
        }

        @Test
        void theGroupingCannotBeModifiedByCallers() {
            VerificationReport report = VerificationReport.of(
                    List.of(result("a", ArtifactOutcome.SATISFIED, null)),
                    RulePolicy.EMPTY);

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
                    RulePolicy.EMPTY);

            assertThat(report.counts()).doesNotContainKey(ArtifactOutcome.FAILED);
        }
    }

    @Nested
    class TheFailureDecision {

        @Test
        void zeroConfigPassesExceptFailed() {
            assertThat(reportFor(RulePolicy.EMPTY,
                    List.of(result("a", ArtifactOutcome.NOT_CONFIGURED, null))).blocks()).isFalse();
            assertThat(reportFor(RulePolicy.EMPTY,
                    List.of(result("a", ArtifactOutcome.FAILED, null))).blocks()).isTrue();
        }

        @Test
        void notConfiguredFailsWhenPolicyDeclared() {
            TrustPolicy policy = requiring("com.acme.*", "a");
            assertThat(reportFor(policy,
                    List.of(result("a", ArtifactOutcome.NOT_CONFIGURED, null))).blocks()).isTrue();
        }

        @Test
        void anUnsatisfiedArtifactBlocksWhenPolicyDeclared() {
            TrustPolicy policy = requiring("org.example:*", "a");
            ArtifactCoords coords = new ArtifactCoords("org.example", "a", "", "jar", "1.0");
            MatchedRule mr = policy.matchRule(coords).toMatchedRule(coords);

            assertThat(reportFor(policy,
                    List.of(result("a", ArtifactOutcome.UNSATISFIED, null, mr))).blocks()).isTrue();
        }

        @Test
        void catchAllIgnoreToleratesUnsigned() {
            TrustPolicy policy = catchAllIgnore();
            ArtifactCoords coords = new ArtifactCoords("org.other", "x", "", "jar", "1");
            MatchedRule mr = policy.matchRule(coords).toMatchedRule(coords);

            assertThat(reportFor(policy,
                    List.of(result("x", ArtifactOutcome.NO_CLAIM, null, mr))).blocks()).isFalse();
        }

        @Test
        void aToleratedArtifactStillBlocksOnABrokenSignature() {
            // the point of verifying rather than skipping: policy tolerates missing evidence,
            // not evidence that fails
            TrustPolicy policy = catchAllIgnore();
            ArtifactCoords coords = new ArtifactCoords("org.other", "x", "", "jar", "1");
            MatchedRule mr = policy.matchRule(coords).toMatchedRule(coords);

            assertThat(reportFor(policy,
                    List.of(result("x", ArtifactOutcome.FAILED, null, mr))).blocks()).isTrue();
        }
    }
}
