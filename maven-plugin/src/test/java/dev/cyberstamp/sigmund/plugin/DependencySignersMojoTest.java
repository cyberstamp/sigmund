package dev.cyberstamp.sigmund.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.cyberstamp.sigmund.core.ArtifactCoords;
import dev.cyberstamp.sigmund.core.ClaimOutcome;
import dev.cyberstamp.sigmund.core.Credential;
import dev.cyberstamp.sigmund.core.IdentityCredential;
import dev.cyberstamp.sigmund.core.IndeterminateReason;
import dev.cyberstamp.sigmund.core.IssuerKind;
import dev.cyberstamp.sigmund.core.KeyCredential;
import dev.cyberstamp.sigmund.core.OpenPgpVerifyResult;
import dev.cyberstamp.sigmund.core.RulePolicy;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.SigmundSchema;
import dev.cyberstamp.sigmund.core.TrustPolicy;
import dev.cyberstamp.sigmund.core.UnverifiedResult;
import dev.cyberstamp.sigmund.core.VerifyResult;
import dev.cyberstamp.sigmund.plugin.SignatureInspector.SignedArtifact;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.maven.plugin.MojoExecutionException;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DependencySignersMojoTest {

    private static final ArtifactCoords LIB_COORDS = ArtifactCoords.parse("com.example:lib:1.0");
    private static final String FULL_FP = "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12";
    private static final String FP4 = FULL_FP;
    private static final String FP6 = "CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9";

    @Test
    void signedArtifactV4WithSigner() {
        VerifyResult vr = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null,
                "User <user@example.com>", "RSA", 4, "ABCD1234", "ABCD1234");
        SignedArtifact signer = new SignedArtifact(LIB_COORDS, "central", vr, null, null);
        assertThat(signer.coords()).isEqualTo(LIB_COORDS);
        assertThat(signer.repoId()).isEqualTo("central");
        assertThat(signer.verifyResult()).isInstanceOf(OpenPgpVerifyResult.class);
        OpenPgpVerifyResult opvr = (OpenPgpVerifyResult) signer.verifyResult();
        assertThat(opvr.version()).isEqualTo(4);
        assertThat(opvr.preferredKeyId()).isEqualTo("ABCD1234");
        assertThat(opvr.signerDisplayName()).isEqualTo("User <user@example.com>");
    }

    @Test
    void signedArtifactV6Detected() {
        VerifyResult vr = new OpenPgpVerifyResult(ClaimOutcome.INDETERMINATE, IndeterminateReason.UNSUPPORTED_ALGORITHM,
                null, null, 6, null, null);
        SignedArtifact signer = new SignedArtifact(LIB_COORDS, "central", vr, null, null);
        OpenPgpVerifyResult opvr = (OpenPgpVerifyResult) signer.verifyResult();
        assertThat(opvr.version()).isEqualTo(6);
        assertThat(opvr.preferredKeyId()).isNull();
        assertThat(signer.isIndeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM)).isTrue();
    }

    @Test
    void signedArtifactNoSignature() {
        SignedArtifact signer = SignedArtifact.noClaim(LIB_COORDS, null);
        assertThat(signer.repoId()).isNull();
        assertThat(signer.verifyResult()).isNull();
        assertThat(signer.hasClaim()).isFalse();
    }

    // --- ArtifactCoords.toString tests ---

    @Test
    void artifactCoordsSimpleJar() {
        ArtifactCoords coords = createArtifact("com.example", "lib", "1.0");
        assertThat(coords.toString()).isEqualTo("com.example:lib:1.0");
    }

    @Test
    void artifactCoordsWithClassifier() {
        ArtifactCoords coords = new ArtifactCoords(
                "com.example", "lib", "sources", "jar", "1.0");
        assertThat(coords.toString()).isEqualTo("com.example:lib:jar:sources:1.0");
    }

    @Test
    void artifactCoordsNonJarType() {
        ArtifactCoords coords = new ArtifactCoords(
                "com.example", "lib", "", "pom", "1.0");
        assertThat(coords.toString()).isEqualTo("com.example:lib:pom:1.0");
    }

    @Test
    void artifactCoordsNonJarTypeWithClassifier() {
        ArtifactCoords coords = new ArtifactCoords(
                "com.example", "lib", "dist", "zip", "1.0");
        assertThat(coords.toString()).isEqualTo("com.example:lib:zip:dist:1.0");
    }

    @Nested
    class GenerateSignerIdTests {

        private final DependencySignersMojo mojo = new DependencySignersMojo();

        @Test
        void normalUidProducesKebabCaseId() {
            assertThat(mojo.generateSignerId("John Smith <john@example.com>", 1))
                    .isEqualTo("john-smith");
        }

        @Test
        void uidWithoutEmailBrackets() {
            assertThat(mojo.generateSignerId("Jane Doe", 1)).isEqualTo("jane-doe");
        }

        @Test
        void emptyNameFallsBackToCounter() {
            assertThat(mojo.generateSignerId(" <user@example.com>", 1)).isEqualTo("signer-1");
        }

        @Test
        void specialCharsOnlyFallsBackToCounter() {
            assertThat(mojo.generateSignerId("... <user@example.com>", 2)).isEqualTo("signer-2");
        }

        @Test
        void nullUidFallsBackToCounter() {
            assertThat(mojo.generateSignerId(null, 3)).isEqualTo("signer-3");
        }

        @Test
        void collisionProducesUniqueSuffix() {
            VerifyResult vr1 = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null,
                    "John Smith <john@a.com>", "RSA", 4, "KEY1", "KEY1");
            VerifyResult vr2 = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null,
                    "John Smith <john@b.com>", "RSA", 4, "KEY2", "KEY2");

            Map<String, DependencySignersMojo.SignerInfo> existingSigners = new LinkedHashMap<>();
            var info1 = new DependencySignersMojo.SignerInfo(
                    mojo.resolveUniqueSignerId(vr1, 1, existingSigners, Set.of()), vr1);
            existingSigners.put("KEY1", info1);

            String id2 = mojo.resolveUniqueSignerId(vr2, 2, existingSigners, Set.of());
            assertThat(info1.id).isEqualTo("john-smith");
            assertThat(id2).isEqualTo("john-smith-2");
        }

        @Test
        void collisionWithReservedIds() {
            VerifyResult vr = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null,
                    "Alice <alice@example.com>", "RSA", 4, "KEY1", "KEY1");
            String id = mojo.resolveUniqueSignerId(vr, 1, new LinkedHashMap<>(), Set.of("alice"));
            assertThat(id).isEqualTo("alice-2");
        }
    }

    @Nested
    class SignerInfoTests {

        @Test
        void v4KeyClassifiedAsPgp4() {
            VerifyResult vr = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null,
                    "User <user@example.com>", "RSA", 4, null, FP4);
            var info = new DependencySignersMojo.SignerInfo("test", vr);
            assertThat(info.pgp4Key).isEqualTo(FP4);
            assertThat(info.pgp6Key).isNull();
        }

        @Test
        void v6KeyClassifiedAsPgp6() {
            VerifyResult vr = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null,
                    "User <user@example.com>", "ML-DSA-87+Ed448", 6, null, FP6);
            var info = new DependencySignersMojo.SignerInfo("test", vr);
            assertThat(info.pgp4Key).isNull();
            assertThat(info.pgp6Key).isEqualTo(FP6);
        }

        @Test
        void mergeAccumulatesBothKeys() {
            VerifyResult vr4 = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null,
                    "User <user@example.com>", "RSA", 4, null, FP4);
            VerifyResult vr6 = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null,
                    null, "ML-DSA-87+Ed448", 6, null, FP6);
            var info = new DependencySignersMojo.SignerInfo("test", vr4);
            info.merge(vr6);
            assertThat(info.pgp4Key).isEqualTo(FP4);
            assertThat(info.pgp6Key).isEqualTo(FP6);
            assertThat(info.userId).isEqualTo("User <user@example.com>");
        }
    }

    @Nested
    class SignedArtifactEdgeCases {

        @Test
        void unverifiedResultCannotClaimVerified() {
            assertThatThrownBy(() -> new UnverifiedResult(ClaimOutcome.VERIFIED, null))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void toolUnavailableIsIndeterminateNotFailed() {
            var sa = SignedArtifact.toolUnavailable(LIB_COORDS, "repo");
            assertThat(sa.isFailed()).isFalse();
            assertThat(sa.isIndeterminate(IndeterminateReason.TOOL_UNAVAILABLE)).isTrue();
            assertThat(sa.verifyResult()).isInstanceOf(UnverifiedResult.class);
        }
    }

    @Nested
    class ArtifactsWithNoClaim {

        /**
         * An artifact with no signature at all carries no verify result, which is a
         * different thing from a claim no installed tool supports.
         */
        private final SignedArtifact noClaim = SignedArtifact.noClaim(LIB_COORDS, "central");

        private final SignedArtifact signed = new SignedArtifact(
                ArtifactCoords.parse("com.example:other:1.0"), "central",
                new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, "User <user@example.com>",
                        "RSA", 4, "ABCD1234", FULL_FP),
                null, null);

        @Test
        void areListedAsUnsignedInTheReport() {
            RecordingLog log = new RecordingLog();
            DependencySignersMojo mojo = new DependencySignersMojo();
            mojo.setLog(log);

            mojo.logReport(List.of(noClaim, signed));

            assertThat(log.lines).contains("warn: UNSIGNED", "warn:   " + LIB_COORDS);
        }

        @Test
        void areRecordedAsSignatureOptionalInAGeneratedConfig(@TempDir Path dir) throws Exception {
            DependencySignersMojo mojo = new DependencySignersMojo();
            mojo.setLog(new RecordingLog());
            Path configFile = dir.resolve("sigmund.yaml");

            mojo.writeTrustConfigYaml(List.of(noClaim, signed), configFile.toFile());

            SigmundConfig config = SigmundConfig.parse(configFile);
            TrustPolicy policy = RulePolicy.compile(config.trustPolicySpec(), config.signers());
            // Check that a rule matches for the unsigned artifact
            assertThat(policy.matchRule(LIB_COORDS)).isNotNull();
        }

        /**
         * When every artifact is unsigned there are no trust requirements, so the config carries
         * only the tolerant {@code on-no-claim} rule. The {@code rules:} header must still be emitted
         * exactly once ahead of that item, or the file is malformed YAML that fails to reparse.
         */
        @Test
        void produceAWellFormedRulesSectionWhenNothingIsSigned(@TempDir Path dir) throws Exception {
            DependencySignersMojo mojo = new DependencySignersMojo();
            mojo.setLog(new RecordingLog());
            Path configFile = dir.resolve("sigmund.yaml");

            mojo.writeTrustConfigYaml(List.of(noClaim), configFile.toFile());

            String yaml = Files.readString(configFile);
            assertThat(yaml.split("rules:", -1).length - 1).isEqualTo(1);
            assertThat(yaml).contains("on-no-claim: ignore");
            SigmundConfig config = SigmundConfig.parse(configFile);
            TrustPolicy policy = RulePolicy.compile(config.trustPolicySpec(), config.signers());
            assertThat(policy.matchRule(LIB_COORDS)).isNotNull();
        }
    }

    @Nested
    class GeneratedSigners {

        private final ArtifactCoords coords = ArtifactCoords.parse("com.example:other:1.0");

        @Test
        void recordFullFingerprintsAndShowTheUserIdAsAComment(@TempDir Path dir) throws Exception {
            SignedArtifact signed = new SignedArtifact(coords, "central",
                    new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, "User <user@example.com>",
                            "RSA", 4, "ABCD1234", FULL_FP),
                    null, null);
            Path configFile = dir.resolve("sigmund.yaml");

            generate(List.of(signed), configFile);

            List<String> lines = Files.readAllLines(configFile);
            assertThat(lines).contains("  user:",
                    "    pgp4: \"" + FULL_FP + "\"  # user ID on the key, unverified: User <user@example.com>")
                    .noneMatch(line -> line.contains("email:") || line.contains("name:"));
            SigmundConfig config = SigmundConfig.parse(configFile);
            TrustPolicy policy = RulePolicy.compile(config.trustPolicySpec(), config.signers());
            // Check that a rule exists for the artifact
            assertThat(policy.matchRule(coords)).isNotNull();
        }

        @Test
        void leaveOutASignerKnownOnlyByKeyId(@TempDir Path dir) throws Exception {
            SignedArtifact signed = new SignedArtifact(coords, "central",
                    new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, "User <user@example.com>",
                            "RSA", 4, "ABCD1234", "ABCD1234"),
                    null, null);
            Path configFile = dir.resolve("sigmund.yaml");

            generate(List.of(signed), configFile);

            SigmundConfig config = SigmundConfig.parse(configFile);
            assertThat(config.signers().isEmpty()).isTrue();
            // With no full fingerprint, no rule should be generated
            assertThat(config.trustPolicySpec().rules()).isEmpty();
        }

        private void generate(List<SignedArtifact> results, Path configFile) throws Exception {
            DependencySignersMojo mojo = new DependencySignersMojo();
            mojo.setLog(new RecordingLog());
            mojo.writeTrustConfigYaml(results, configFile.toFile());
        }
    }

    /**
     * A generated signer is named by the address the directory verified for its key, next to the
     * fingerprint: the fingerprint proves the keys already seen, offline, and the address accepts
     * the keys the publisher rotates to, which the next update pins. The directory is trusted in
     * the file, under {@code issuers}, where the review sees it — never by a default in code.
     */
    @Nested
    class DirectoryAddresses {

        private final ArtifactCoords lib = ArtifactCoords.parse("com.example:lib:1.0");
        private final RecordingLog log = new RecordingLog();

        private SignedArtifact signed(String userId, int version, String fingerprint) {
            return new SignedArtifact(lib, "central",
                    new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, userId,
                            version == 6 ? "ML-DSA-87+Ed448" : "RSA", version,
                            fingerprint.substring(fingerprint.length() - 16), fingerprint),
                    null, null);
        }

        private DirectoryLookup serving(Map<String, List<String>> addressesByKey) {
            return (key, issuers) -> addressesByKey.getOrDefault(key.fingerprint(), List.of()).stream()
                    .map(address -> IdentityCredential.email(IssuerKind.KEYS_OPENPGP_ORG, address))
                    .toList();
        }

        private List<String> generate(Path dir, DirectoryLookup lookup, SignedArtifact... results)
                throws Exception {
            DependencySignersMojo mojo = new DependencySignersMojo();
            mojo.setLog(log);
            mojo.directoryLookup(lookup);
            Path file = dir.resolve("sigmund.yaml");
            mojo.writeTrustConfigYaml(List.of(results), file.toFile());
            SigmundConfig config = SigmundConfig.parse(file);
            RulePolicy.compile(config.trustPolicySpec(), config.signers());
            return Files.readAllLines(file);
        }

        @Test
        void aKeyWithAVerifiedAddressIsNamedByItAndTheDirectoryIsTrusted(@TempDir Path dir)
                throws Exception {
            List<String> lines = generate(dir, serving(Map.of(FULL_FP, List.of("alice@example.com"))),
                    signed("Alice <alice@example.com>", 4, FULL_FP));

            assertThat(lines).contains("issuers: [keys.openpgp.org]",
                    "    pgp4: \"" + FULL_FP + "\"", "    email: \"alice@example.com\"");
            assertThat(lines.get(0)).isEqualTo(SigmundSchema.modeline());
        }

        /**
         * The user ID comment is a reviewer's only hint for a signer named by fingerprint alone.
         * Once the directory has verified the address the user ID shows, the {@code email:} line
         * says it, and calling the same address unverified would only read as a contradiction.
         */
        @Test
        void aSignerNamedByTheAddressOnItsKeyNeedsNoUserIdComment(@TempDir Path dir) throws Exception {
            List<String> lines = generate(dir, serving(Map.of(FULL_FP, List.of("alice@example.com"))),
                    signed("Alice <Alice@Example.com>", 4, FULL_FP));

            assertThat(lines).contains("  alice:").noneMatch(line -> line.contains("# user ID"));
        }

        @Test
        void aUserIdShowingAnotherAddressKeepsItsComment(@TempDir Path dir) throws Exception {
            List<String> lines = generate(dir, serving(Map.of(FULL_FP, List.of("alice@example.com"))),
                    signed("Alice <alice@personal.example>", 4, FULL_FP));

            assertThat(lines).contains("  alice:",
                    "    pgp4: \"" + FULL_FP + "\"  # user ID on the key, unverified: Alice <alice@personal.example>",
                    "    email: \"alice@example.com\"");
        }

        @Test
        void withoutAVerifiedAddressNoIssuerIsTrusted(@TempDir Path dir) throws Exception {
            List<String> lines = generate(dir, serving(Map.of()),
                    signed("Alice <alice@example.com>", 4, FULL_FP));

            assertThat(lines).noneMatch(line -> line.startsWith("issuers:") || line.contains("email:"));
        }

        @Test
        void withoutDirectoryLookupsSignersAreFingerprintsOnly(@TempDir Path dir) throws Exception {
            List<String> lines = generate(dir, null, signed("Alice <alice@example.com>", 4, FULL_FP));

            assertThat(lines).noneMatch(line -> line.startsWith("issuers:") || line.contains("email:"));
        }

        @Test
        void anUnreachableDirectoryLeavesFingerprintsOnly(@TempDir Path dir) throws Exception {
            List<String> lines = generate(dir, (key, issuers) -> {
                throw new IOException("connection refused");
            }, signed("Alice <alice@example.com>", 4, FULL_FP));

            assertThat(lines).noneMatch(line -> line.contains("email:"));
            assertThat(log.lines).anyMatch(line -> line.startsWith("warn:") && line.contains("connection refused"));
        }

        @Test
        void theAddressOnTheKeyIsPreferredAmongSeveralVerified(@TempDir Path dir) throws Exception {
            List<String> lines = generate(dir,
                    serving(Map.of(FULL_FP, List.of("old@example.com", "alice@example.com"))),
                    signed("Alice <alice@example.com>", 4, FULL_FP));

            assertThat(lines).contains("    email: \"alice@example.com\"");
        }

        @Test
        void aPublishersClassicAndPqcKeysAreAskedForTogether(@TempDir Path dir) throws Exception {
            List<String> lines = generate(dir, serving(Map.of(FP6, List.of("alice@example.com"))),
                    signed("Alice <alice@example.com>", 4, FULL_FP),
                    signed("Alice <alice@example.com>", 6, FP6));

            assertThat(lines).contains("    email: \"alice@example.com\"");
            assertThat(lines.stream().filter(line -> line.contains("email:"))).hasSize(1);
        }

        @Test
        void anUpdateNamesANewSignerInlineWhenTheFileDoesNotTrustTheDirectory(@TempDir Path dir)
                throws Exception {
            Path file = dir.resolve("sigmund.yaml");
            Files.writeString(file, "rules:\n  - match: [\"*\"]\n    on-no-claim: ignore\n");
            DependencySignersMojo mojo = new DependencySignersMojo();
            mojo.setLog(log);
            mojo.directoryLookup(serving(Map.of(FULL_FP, List.of("alice@example.com"))));

            mojo.updateExistingTrustConfig(List.of(signed("Alice <alice@example.com>", 4, FULL_FP)),
                    file.toFile());

            List<String> lines = Files.readAllLines(file);
            assertThat(lines).noneMatch(line -> line.startsWith("issuers:"))
                    .contains("      - issuer: \"" + IssuerKind.KEYS_OPENPGP_ORG + "\"",
                            "        email: \"alice@example.com\"");
        }

        @Test
        void anUpdateUsesTheShortFormWhenTheFileTrustsTheDirectory(@TempDir Path dir) throws Exception {
            Path file = dir.resolve("sigmund.yaml");
            Files.writeString(file, "issuers: [keys.openpgp.org]\nrules:\n  - match: [\"*\"]\n    on-no-claim: ignore\n");
            DependencySignersMojo mojo = new DependencySignersMojo();
            mojo.setLog(log);
            mojo.directoryLookup(serving(Map.of(FULL_FP, List.of("alice@example.com"))));

            mojo.updateExistingTrustConfig(List.of(signed("Alice <alice@example.com>", 4, FULL_FP)),
                    file.toFile());

            assertThat(Files.readAllLines(file)).contains("    email: \"alice@example.com\"");
        }
    }

    /**
     * Keys that sign together. A publisher's classic and post-quantum keys — the same user ID,
     * on exactly the same artifacts — are one signer, so either key's signature satisfies its
     * rule and a verifier without post-quantum support still reaches a verdict. Keys that sign
     * together but belong to different parties stay separate signers, all required.
     */
    @Nested
    class CoSigningKeys {

        private static final String CLASSIC = FULL_FP;
        private static final String PQC = FP6;
        private static final String OTHER = "BBE7232D7991050B54C8EA0ADC08637CA615D22C";

        private final ArtifactCoords lib = ArtifactCoords.parse("com.example:lib:1.0");
        private final ArtifactCoords tool = ArtifactCoords.parse("org.other:tool:1.0");

        private SignedArtifact signed(ArtifactCoords coords, String userId, int version,
                String fingerprint) {
            return new SignedArtifact(coords, "central",
                    new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, userId,
                            version == 6 ? "ML-DSA-87+Ed448" : "RSA", version,
                            fingerprint.substring(fingerprint.length() - 16), fingerprint),
                    null, null);
        }

        private SigmundConfig generate(Path dir, SignedArtifact... results) throws Exception {
            DependencySignersMojo mojo = new DependencySignersMojo();
            mojo.setLog(new RecordingLog());
            Path file = dir.resolve("sigmund.yaml");
            mojo.writeTrustConfigYaml(List.of(results), file.toFile());
            return SigmundConfig.parse(file);
        }

        @Test
        void aPublishersClassicAndPqcKeysBecomeOneSigner(@TempDir Path dir) throws Exception {
            SigmundConfig config = generate(dir,
                    signed(lib, "Alice <alice@example.com>", 4, CLASSIC),
                    signed(lib, "Alice <alice@example.com>", 6, PQC));

            assertThat(config.signers().names()).containsExactly("alice");
            assertThat(config.signers().get("alice").credentials()).containsExactlyInAnyOrder(
                    KeyCredential.openPgp(CLASSIC), KeyCredential.openPgp(PQC));
            assertThat(config.trustPolicySpec().rules().get(0).clauseIds())
                    .containsExactly(Set.of("alice"));
        }

        /** The user ID is the key's, so each fingerprint carries it — both keys carry the same one. */
        @Test
        void eachOfThePublishersKeysCarriesItsUserId(@TempDir Path dir) throws Exception {
            generate(dir, signed(lib, "Alice <alice@example.com>", 4, CLASSIC),
                    signed(lib, "Alice <alice@example.com>", 6, PQC));

            assertThat(Files.readAllLines(dir.resolve("sigmund.yaml"))).contains("  alice:",
                    "    pgp4: \"" + CLASSIC + "\"  # user ID on the key, unverified: Alice <alice@example.com>",
                    "    pgp6: \"" + PQC + "\"  # user ID on the key, unverified: Alice <alice@example.com>");
        }

        @Test
        void keysThatDoNotAlwaysSignTogetherStaySeparate(@TempDir Path dir) throws Exception {
            SigmundConfig config = generate(dir,
                    signed(lib, "Alice <alice@example.com>", 4, CLASSIC),
                    signed(lib, "Alice <alice@example.com>", 6, PQC),
                    signed(tool, "Alice <alice@example.com>", 4, CLASSIC));

            assertThat(config.signers().names()).hasSize(2);
        }

        @Test
        void differentPartiesSigningTogetherAreAllRequired(@TempDir Path dir) throws Exception {
            SigmundConfig config = generate(dir,
                    signed(lib, "Alice <alice@example.com>", 4, CLASSIC),
                    signed(lib, "Bob <bob@example.com>", 6, PQC));

            assertThat(config.signers().names()).hasSize(2);
            assertThat(config.trustPolicySpec().rules().get(0).clauseIds()).hasSize(2);
        }

        @Test
        void twoClassicKeysWithOneUserIdStaySeparate(@TempDir Path dir) throws Exception {
            SigmundConfig config = generate(dir,
                    signed(lib, "Alice <alice@example.com>", 4, CLASSIC),
                    signed(lib, "Alice <alice@example.com>", 4, OTHER));

            assertThat(config.signers().names()).hasSize(2);
        }

        @Test
        void anUpdateCombinesANewPublishersKeysToo(@TempDir Path dir) throws Exception {
            Path file = dir.resolve("sigmund.yaml");
            Files.writeString(file, "rules:\n  - match: [\"*\"]\n    on-no-claim: ignore\n");
            DependencySignersMojo mojo = new DependencySignersMojo();
            mojo.setLog(new RecordingLog());

            mojo.updateExistingTrustConfig(List.of(
                    signed(lib, "Alice <alice@example.com>", 4, CLASSIC),
                    signed(lib, "Alice <alice@example.com>", 6, PQC)), file.toFile());

            SigmundConfig config = SigmundConfig.parse(file);
            assertThat(config.signers().names()).containsExactly("alice");
            TrustPolicy policy = RulePolicy.compile(config.trustPolicySpec(), config.signers());
            assertThat(policy.matchRule(lib).requirement().clauses()).hasSize(1);
        }
    }

    /**
     * The shape of the rules bootstrap writes: a single pattern or signer is written as a string,
     * the way a person would write it, and a list only when there are several. The rule tolerating
     * unsigned modules stays a flow list whatever its length, because that is the shape an update
     * edits when a module starts being signed.
     */
    @Nested
    class GeneratedRules {

        private final ArtifactCoords lib = ArtifactCoords.parse("com.example:lib:1.0");

        private SignedArtifact signed(String userId, int version, String fingerprint) {
            return new SignedArtifact(lib, "central",
                    new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, userId,
                            version == 6 ? "ML-DSA-87+Ed448" : "RSA", version,
                            fingerprint.substring(fingerprint.length() - 16), fingerprint),
                    null, null);
        }

        private List<String> generate(Path dir, SignedArtifact... results) throws Exception {
            DependencySignersMojo mojo = new DependencySignersMojo();
            mojo.setLog(new RecordingLog());
            Path file = dir.resolve("sigmund.yaml");
            mojo.writeTrustConfigYaml(List.of(results), file.toFile());
            SigmundConfig config = SigmundConfig.parse(file);
            RulePolicy.compile(config.trustPolicySpec(), config.signers());
            return Files.readAllLines(file);
        }

        @Test
        void aSinglePatternAndSignerAreWrittenAsStrings(@TempDir Path dir) throws Exception {
            List<String> lines = generate(dir, signed("Alice <alice@example.com>", 4, FULL_FP));

            assertThat(lines).contains("  - match: com.example:lib", "    requires: alice");
        }

        @Test
        void severalRequiredSignersAreWrittenAsAList(@TempDir Path dir) throws Exception {
            List<String> lines = generate(dir, signed("Alice <alice@example.com>", 4, FULL_FP),
                    signed("Bob <bob@example.com>", 6, FP6));

            assertThat(lines).contains("    requires: [alice, bob]");
        }

        @Test
        void aGeneratedConfigNamesItsSchemaForEditors(@TempDir Path dir) throws Exception {
            List<String> lines = generate(dir, signed("Alice <alice@example.com>", 4, FULL_FP));

            assertThat(lines.get(0)).isEqualTo(SigmundSchema.modeline());
        }

        @Test
        void theUnsignedModulesRuleStaysAFlowListOfOne(@TempDir Path dir) throws Exception {
            List<String> lines = generate(dir, SignedArtifact.noClaim(lib, "central"));

            assertThat(lines).contains("  - match: [com.example:lib]");
        }
    }

    @Nested
    class UpdatingAConfig {

        private static final String OTHER_FP = "0123456789ABCDEF0123456789ABCDEF01234567";

        private final ArtifactCoords lib = ArtifactCoords.parse("com.example:lib:1.0");
        private final ArtifactCoords util = ArtifactCoords.parse("com.example:util:1.0");

        private final RecordingLog log = new RecordingLog();

        private SignedArtifact signedBy(ArtifactCoords coords, String fingerprint) {
            return new SignedArtifact(coords, "central",
                    new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, "User <user@example.com>",
                            "RSA", 4, fingerprint.substring(24), fingerprint),
                    null, null);
        }

        private SignedArtifact signedByV6(ArtifactCoords coords, String fingerprint) {
            return new SignedArtifact(coords, "central",
                    new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, "User <user@example.com>",
                            "ML-DSA-87+Ed448", 6, fingerprint.substring(48), fingerprint),
                    null, null);
        }

        private Path configWith(Path dir, String yaml) throws Exception {
            Path file = dir.resolve("sigmund.yaml");
            Files.writeString(file, yaml);
            return file;
        }

        private TrustPolicy update(Path file, SignedArtifact... results) throws Exception {
            DependencySignersMojo mojo = new DependencySignersMojo();
            mojo.setLog(log);
            mojo.updateExistingTrustConfig(List.of(results), file.toFile());
            SigmundConfig config = SigmundConfig.parse(file);
            return RulePolicy.compile(config.trustPolicySpec(), config.signers());
        }

        /**
         * The everyday update: a dependency added later, signed by a publisher the policy already
         * names, needs a rule of its own requiring that signer — not a second definition of it.
         */
        @Test
        void aNewArtifactSignedByAKnownSignerGetsARequirementOnThatSigner(@TempDir Path dir)
                throws Exception {
            Path file = configWith(dir, """
                    signers:
                      alice:
                        pgp4: "%s"
                    rules:
                      - match: com.example:lib
                        requires: alice
                    """.formatted(FULL_FP));

            TrustPolicy policy = update(file, signedBy(lib, FULL_FP), signedBy(util, FULL_FP));

            assertThat(policy.matchRule(util)).as("a rule for the new artifact").isNotNull();
            assertThat(policy.matchRule(util).requirement().clauses())
                    .flatExtracting(clause -> clause.signers())
                    .extracting(signer -> signer.id())
                    .containsExactly("alice");
            assertThat(SigmundConfig.parse(file).signers().names()).containsExactly("alice");
        }

        @Test
        void aCatchAllDoesNotHideANewlySignedModule(@TempDir Path dir) throws Exception {
            Path file = configWith(dir, """
                    rules:
                      - match: ["*"]
                        on-no-claim: ignore
                    """);

            TrustPolicy policy = update(file, signedBy(lib, FULL_FP));

            assertThat(policy.matchRule(lib).requirement().clauses()).hasSize(1);
            assertThat(policy.matchRule(util).location()).isEqualTo("rules[0]");
        }

        @Test
        void aModuleThatStartedSigningMovesOutOfTheTolerantRule(@TempDir Path dir)
                throws Exception {
            Path file = configWith(dir, """
                    rules:
                      - match: [com.example:lib, com.example:util]
                        on-no-claim: ignore
                    """);

            TrustPolicy policy = update(file, signedBy(lib, FULL_FP),
                    SignedArtifact.noClaim(util, "central"));

            assertThat(policy.matchRule(lib).requirement().clauses()).hasSize(1);
            assertThat(policy.matchRule(util).requirement().clauses()).isEmpty();
            assertThat(Files.readString(file)).contains("- match: [com.example:util]");
        }

        @Test
        void theLastModuleLeavingTheTolerantRuleTakesTheRuleWithIt(@TempDir Path dir)
                throws Exception {
            Path file = configWith(dir, """
                    rules:
                      - match: [com.example:lib]
                        on-no-claim: ignore
                    """);

            TrustPolicy policy = update(file, signedBy(lib, FULL_FP));

            assertThat(policy.matchRule(lib).requirement().clauses()).hasSize(1);
            assertThat(Files.readString(file)).doesNotContain("on-no-claim");
        }

        @Test
        void aHandWrittenTolerantRuleIsLeftForReview(@TempDir Path dir) throws Exception {
            String yaml = """
                    rules:
                      - match:
                          - com.example:lib
                        on-no-claim: ignore
                    """;
            Path file = configWith(dir, yaml);

            update(file, signedBy(lib, FULL_FP));

            assertThat(Files.readString(file)).isEqualTo(yaml);
            assertThat(log.lines).anyMatch(line -> line.contains("Needs review"))
                    .anyMatch(line -> line.contains("com.example:lib")
                            && line.contains("rules[0]"));
        }

        /**
         * A rotated key: the publisher's new key, which the directory confirms for the address of
         * the signer the rule requires. Verification already accepts it through the address, but
         * the binding is current state — once the publisher rotates again the directory serves
         * this key without the address — so the update pins the fingerprint onto the signer,
         * where it keeps proving these artifacts offline and for good.
         */
        @Nested
        class PinningARotatedKey {

            private static final String ALICE = """
                    issuers: [keys.openpgp.org]
                    signers:
                      alice:
                        pgp4: "%s"
                        email: "alice@example.com"

                    rules:
                      - match: com.example:lib
                        requires: alice
                    """.formatted(FULL_FP);

            private final List<String> asked = new ArrayList<>();

            /** A directory confirming the address for every v4 key; like keys.openpgp.org, it serves no v6 keys. */
            private DirectoryLookup confirming(String address) {
                return (key, issuers) -> {
                    asked.add(key.fingerprint());
                    return issuers.contains(IssuerKind.KEYS_OPENPGP_ORG)
                            && key.type().equals(Credential.TYPE_PGP4)
                                    ? List.of(IdentityCredential.email(IssuerKind.KEYS_OPENPGP_ORG, address))
                                    : List.of();
                };
            }

            private TrustPolicy update(Path file, DirectoryLookup lookup, SignedArtifact... results)
                    throws Exception {
                DependencySignersMojo mojo = new DependencySignersMojo();
                mojo.setLog(log);
                mojo.directoryLookup(lookup);
                mojo.updateExistingTrustConfig(List.of(results), file.toFile());
                SigmundConfig config = SigmundConfig.parse(file);
                return RulePolicy.compile(config.trustPolicySpec(), config.signers());
            }

            @Test
            void aKeyTheDirectoryConfirmsForTheRequiredSignerIsPinnedOntoIt(@TempDir Path dir)
                    throws Exception {
                Path file = configWith(dir, ALICE);

                update(file, confirming("alice@example.com"), signedBy(lib, OTHER_FP));

                assertThat(Files.readAllLines(file)).containsSubsequence(
                        "    pgp4:",
                        "      - \"" + FULL_FP + "\"",
                        "      - \"" + OTHER_FP + "\"  # pinned by update: " + IssuerKind.KEYS_OPENPGP_ORG
                                + " confirmed alice@example.com");
                assertThat(SigmundConfig.parse(file).signers().get("alice").credentials())
                        .contains(KeyCredential.openPgp(OTHER_FP));
                assertThat(log.lines).noneMatch(line -> line.contains("Needs review"))
                        .anyMatch(line -> line.contains("com.example:lib") && line.contains(OTHER_FP)
                                && line.contains("alice@example.com") && line.contains("'alice'"));
            }

            /**
             * A hybrid publisher rotating both keys: the directory confirms the new v4 key, but
             * serves no v6 keys, so the new v6 key cannot be confirmed. Under the default
             * {@code extra-claims: reject} its claim alone would leave the artifact unsatisfied,
             * so it is listed for review rather than passed over with the pinned v4 key.
             */
            @Test
            void aHybridRotationPinsTheConfirmedKeyAndListsTheOtherForReview(@TempDir Path dir)
                    throws Exception {
                Path file = configWith(dir, ALICE);

                update(file, confirming("alice@example.com"), signedBy(lib, OTHER_FP),
                        signedByV6(lib, FP6));

                assertThat(Files.readString(file)).contains(OTHER_FP).doesNotContain(FP6);
                assertThat(log.lines).anyMatch(line -> line.contains("Needs review"))
                        .anyMatch(line -> line.contains("signed by pgp6 " + FP6)
                                && line.contains("; signed alongside pgp4 " + OTHER_FP
                                        + ", which https://keys.openpgp.org confirmed for"
                                        + " alice@example.com of signer 'alice' — signing alongside"
                                        + " does not show who holds this key"));
            }

            @Test
            void aKeyUsedForSeveralArtifactsIsPinnedOnce(@TempDir Path dir) throws Exception {
                Path file = configWith(dir, ALICE.replace("match: com.example:lib", "match: com.example"));

                update(file, confirming("alice@example.com"), signedBy(lib, OTHER_FP),
                        signedBy(util, OTHER_FP));

                assertThat(Files.readString(file).split(OTHER_FP, -1)).hasSize(2);
            }

            /**
             * A pin adds the key to one signer. Under a rule requiring another signer the key is
             * not accepted by it, so it is asked about again rather than passed over as pinned.
             */
            @Test
            void aKeyPinnedForOneRuleIsStillReviewedUnderARuleRequiringAnotherSigner(@TempDir Path dir)
                    throws Exception {
                Path file = configWith(dir, """
                        issuers: [keys.openpgp.org]
                        signers:
                          alice:
                            pgp4: "%s"
                            email: "alice@example.com"
                          bob:
                            pgp4: "%s"
                            email: "bob@example.com"

                        rules:
                          - match: com.example:lib
                            requires: alice
                          - match: com.example:util
                            requires: bob
                        """.formatted(FULL_FP, "BBE7232D7991050B54C8EA0ADC08637CA615D22C"));

                update(file, confirming("alice@example.com"), signedBy(lib, OTHER_FP),
                        signedBy(util, OTHER_FP));

                assertThat(Files.readString(file).split(OTHER_FP, -1)).hasSize(2);
                assertThat(log.lines).anyMatch(line -> line.contains("Needs review"))
                        .anyMatch(line -> line.contains("com.example:util") && line.contains(OTHER_FP)
                                && line.contains("requires [bob]"));
            }

            @Test
            void aKeyConfirmedForAnotherAddressIsLeftForReview(@TempDir Path dir) throws Exception {
                Path file = configWith(dir, ALICE);

                update(file, confirming("mallory@example.com"), signedBy(lib, OTHER_FP));

                assertThat(Files.readString(file)).isEqualTo(ALICE);
                assertThat(log.lines).anyMatch(line -> line.contains("Needs review"));
            }

            @Test
            void withoutDirectoryLookupsTheKeyIsLeftForReview(@TempDir Path dir) throws Exception {
                Path file = configWith(dir, ALICE);

                update(file, null, signedBy(lib, OTHER_FP));

                assertThat(Files.readString(file)).isEqualTo(ALICE);
                assertThat(log.lines).anyMatch(line -> line.contains(OTHER_FP)
                        && line.contains("directory not asked (resolve-signers: false)"));
            }

            @Test
            void anUnreachableDirectoryLeavesTheKeyForReview(@TempDir Path dir) throws Exception {
                Path file = configWith(dir, ALICE);

                update(file, (key, issuers) -> {
                    throw new IOException("connection refused");
                }, signedBy(lib, OTHER_FP));

                assertThat(Files.readString(file)).isEqualTo(ALICE);
                assertThat(log.lines).anyMatch(line -> line.contains(OTHER_FP)
                        && line.contains("directory unreachable"));
            }

            @Test
            void aSignerNamedOnlyByFingerprintCostsNoLookup(@TempDir Path dir) throws Exception {
                Path file = configWith(dir, ALICE.replace("    email: \"alice@example.com\"\n", ""));

                update(file, confirming("alice@example.com"), signedBy(lib, OTHER_FP));

                assertThat(asked).isEmpty();
                assertThat(log.lines).anyMatch(line -> line.contains("Needs review"));
            }

            @Test
            void anAddressTheFileLetsNoDirectoryVouchForCostsNoLookup(@TempDir Path dir) throws Exception {
                Path file = configWith(dir, ALICE.replace("issuers: [keys.openpgp.org]",
                        "issuers: [\"https://token.actions.githubusercontent.com\"]"));

                update(file, confirming("alice@example.com"), signedBy(lib, OTHER_FP));

                assertThat(log.lines).anyMatch(line -> line.contains("Needs review"));
            }

            @Test
            void aSignerUpdateCannotEditIsLeftForReviewNamingTheKey(@TempDir Path dir) throws Exception {
                String yaml = """
                        issuers: [keys.openpgp.org]
                        signers:
                          alice: "alice@example.com"

                        rules:
                          - match: com.example:lib
                            requires: alice
                        """;
                Path file = configWith(dir, yaml);

                update(file, confirming("alice@example.com"), signedBy(lib, OTHER_FP));

                assertThat(Files.readString(file)).isEqualTo(yaml);
                assertThat(log.lines).anyMatch(line -> line.contains("Needs review"))
                        .anyMatch(line -> line.contains(OTHER_FP) && line.contains("add it to signer 'alice' by hand"));
            }
        }

        @Test
        void aSignerChangeUnderARequirementIsReportedNotRewritten(@TempDir Path dir)
                throws Exception {
            String yaml = """
                    signers:
                      alice:
                        pgp4: "%s"

                    rules:
                      - match: [com.example:lib]
                        requires: [alice]
                    """.formatted(FULL_FP);
            Path file = configWith(dir, yaml);

            update(file, signedBy(lib, OTHER_FP));

            assertThat(Files.readString(file)).isEqualTo(yaml);
            assertThat(log.lines).anyMatch(line -> line.contains("Needs review"))
                    .anyMatch(line -> line.contains("com.example:lib")
                            && line.contains("signed by pgp4 " + OTHER_FP)
                            && line.contains("rules[0] 'com.example:lib' requires [alice]"));
        }

        /**
         * Under the default {@code extra-claims: reject} every verified claim must be accepted, so
         * a key the rule does not name is a change to review even beside one it does.
         */
        @Test
        void aKeyBesideANamedOneIsListedForReviewUnderReject(@TempDir Path dir) throws Exception {
            Path file = configWith(dir, """
                    signers:
                      alice:
                        pgp4: "%s"

                    rules:
                      - match: com.example:lib
                        requires: alice
                    """.formatted(FULL_FP));

            update(file, signedBy(lib, FULL_FP), signedBy(lib, OTHER_FP));

            assertThat(log.lines).anyMatch(line -> line.contains("Needs review"))
                    .anyMatch(line -> line.contains("signed by pgp4 " + OTHER_FP)
                            && !line.contains(FULL_FP));
        }

        @Test
        void aKeyBesideANamedOneNeedsNoReviewUnderIgnore(@TempDir Path dir) throws Exception {
            Path file = configWith(dir, """
                    signers:
                      alice:
                        pgp4: "%s"

                    rules:
                      - match: com.example:lib
                        requires: alice
                        extra-claims: ignore
                    """.formatted(FULL_FP));

            update(file, signedBy(lib, FULL_FP), signedBy(lib, OTHER_FP));

            assertThat(log.lines).noneMatch(line -> line.contains("Needs review"));
        }

        @Test
        void aSignatureFromANamedSignerNeedsNoReview(@TempDir Path dir) throws Exception {
            Path file = configWith(dir, """
                    signers:
                      alice:
                        pgp4: "%s"

                    rules:
                      - match: [com.example:lib]
                        requires: [alice]
                    """.formatted(FULL_FP));

            update(file, signedBy(lib, FULL_FP));

            assertThat(log.lines).noneMatch(line -> line.contains("Needs review"))
                    .anyMatch(line -> line.contains("already up to date"));
        }

        @Test
        void anUpdateThatWouldNotLoadIsNotWritten(@TempDir Path dir) throws Exception {
            String yaml = """
                    rules:
                      - match: ["com.example:*:1.0"]
                        on-no-claim: ignore
                    """;
            Path file = configWith(dir, yaml);
            DependencySignersMojo mojo = new DependencySignersMojo();
            mojo.setLog(log);

            assertThatThrownBy(() -> mojo.updateExistingTrustConfig(
                    List.of(signedBy(lib, FULL_FP)), file.toFile()))
                    .isInstanceOf(MojoExecutionException.class)
                    .hasMessageContaining("tie on specificity");
            assertThat(Files.readString(file)).isEqualTo(yaml);
        }
    }

    private ArtifactCoords createArtifact(String groupId, String artifactId, String version) {
        return new ArtifactCoords(groupId, artifactId, "", "jar", version);
    }
}
