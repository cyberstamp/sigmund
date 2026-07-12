package io.github.aloubyansky.sigmund.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class TrustVerifierTest {

    private static final SignerIdentity ALICE = new SignerIdentity("alice", "Alice",
            List.of(new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23")));

    @Nested
    class VerdictAssignment {

        @Test
        void trusted_whenEvidenceMatchesExpectedSigner() {
            var policy = policyFor(ALICE, false);
            var provider = passingProvider("openpgp",
                    new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23"));
            var verifier = new TrustVerifier(policy, List.of(provider));

            var result = verifier.assess(
                    artifact("org.example", "lib", "1.0"),
                    Path.of("lib.jar"),
                    List.of(Path.of("lib.jar.asc")));

            assertEquals(TrustVerdict.TRUSTED, result.verdict());
            assertEquals(1, result.matchedEvidence().size());
        }

        @Test
        void untrusted_whenEvidenceDoesNotMatch() {
            var policy = policyFor(ALICE, false);
            var provider = passingProvider("openpgp",
                    new FingerprintCredential("openpgp4", "DIFFERENT18F83AFD"));
            var verifier = new TrustVerifier(policy, List.of(provider));

            var result = verifier.assess(
                    artifact("org.example", "lib", "1.0"),
                    Path.of("lib.jar"),
                    List.of(Path.of("lib.jar.asc")));

            assertEquals(TrustVerdict.UNTRUSTED, result.verdict());
        }

        @Test
        void unsigned_whenNoEvidence() {
            var policy = policyFor(ALICE, false);
            var verifier = new TrustVerifier(policy, List.of());

            var result = verifier.assess(
                    artifact("org.example", "lib", "1.0"),
                    Path.of("lib.jar"),
                    List.of());

            assertEquals(TrustVerdict.UNSIGNED, result.verdict());
        }

        @Test
        void notConfigured_whenArtifactNotInPolicy() {
            var policy = emptyPolicy();
            var verifier = new TrustVerifier(policy, List.of());

            var result = verifier.assess(
                    artifact("com.unknown", "lib", "1.0"),
                    Path.of("lib.jar"),
                    List.of());

            assertEquals(TrustVerdict.NOT_CONFIGURED, result.verdict());
        }

        @Test
        void verificationFailed_whenEvidenceFails() {
            var policy = policyFor(ALICE, false);
            var provider = failingProvider();
            var verifier = new TrustVerifier(policy, List.of(provider));

            var result = verifier.assess(
                    artifact("org.example", "lib", "1.0"),
                    Path.of("lib.jar"),
                    List.of(Path.of("lib.jar.asc")));

            assertEquals(TrustVerdict.VERIFICATION_FAILED, result.verdict());
        }
    }

    @Nested
    class RequireAllEvidenceMatch {

        @Test
        void untrusted_whenUnmatchedEvidenceAndPolicyRequiresAll() {
            var alice = ALICE;
            var policy = policyFor(alice, true);
            var provider = multiResultProvider(
                    new EvidenceResult(PGP_PASS,
                            List.of(new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23")),
                            "openpgp"),
                    new EvidenceResult(PGP_PASS,
                            List.of(new FingerprintCredential("openpgp6", "UNKNOWNFINGERPRINT")),
                            "openpgp"));
            var verifier = new TrustVerifier(policy, List.of(provider));

            var result = verifier.assess(
                    artifact("org.example", "lib", "1.0"),
                    Path.of("lib.jar"),
                    List.of(Path.of("lib.jar.asc")));

            assertEquals(TrustVerdict.UNTRUSTED, result.verdict());
        }

        @Test
        void trusted_whenUnmatchedEvidenceButPolicyDoesNotRequireAll() {
            var policy = policyFor(ALICE, false);
            var provider = multiResultProvider(
                    new EvidenceResult(PGP_PASS,
                            List.of(new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23")),
                            "openpgp"),
                    new EvidenceResult(PGP_PASS,
                            List.of(new FingerprintCredential("openpgp6", "UNKNOWNFINGERPRINT")),
                            "openpgp"));
            var verifier = new TrustVerifier(policy, List.of(provider));

            var result = verifier.assess(
                    artifact("org.example", "lib", "1.0"),
                    Path.of("lib.jar"),
                    List.of(Path.of("lib.jar.asc")));

            assertEquals(TrustVerdict.TRUSTED, result.verdict());
            assertEquals(1, result.unmatchedEvidence().size());
        }
    }

    @Nested
    class EvidencePreservation {

        @Test
        void noKeyEvidence_includedInUnmatched() {
            var policy = policyFor(ALICE, false);
            var noKeyResult = new OpenPgpVerifyResult(Verdict.NO_KEY, null, null, 4,
                    null, "DEADBEEFDEADBEEF");
            var provider = multiResultProvider(
                    new EvidenceResult(noKeyResult,
                            List.of(new FingerprintCredential("openpgp4", "DEADBEEFDEADBEEF")),
                            "openpgp"));
            var verifier = new TrustVerifier(policy, List.of(provider));

            var result = verifier.assess(
                    artifact("org.example", "lib", "1.0"),
                    Path.of("lib.jar"),
                    List.of(Path.of("lib.jar.asc")));

            assertEquals(TrustVerdict.UNTRUSTED, result.verdict());
            assertEquals(1, result.unmatchedEvidence().size());
            assertEquals(Verdict.NO_KEY, result.unmatchedEvidence().get(0).verdict());
        }

        @Test
        void notConfigured_carriesEvidence() {
            var provider = passingProvider("openpgp",
                    new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23"));
            var verifier = new TrustVerifier(emptyPolicy(), List.of(provider));

            var result = verifier.assess(
                    artifact("org.example", "lib", "1.0"),
                    Path.of("lib.jar"),
                    List.of(Path.of("lib.jar.asc")));

            assertEquals(TrustVerdict.NOT_CONFIGURED, result.verdict());
            assertFalse(result.unmatchedEvidence().isEmpty());
        }
    }

    @Nested
    class BatchAssessment {

        @Test
        void assessAll_returnsOneResultPerRequest() {
            var policy = emptyPolicy();
            var verifier = new TrustVerifier(policy, List.of());

            var results = verifier.assessAll(List.of(
                    new AssessmentRequest(artifact("a", "b", "1"), Path.of("b.jar"), List.of()),
                    new AssessmentRequest(artifact("c", "d", "2"), Path.of("d.jar"), List.of())));

            assertEquals(2, results.size());
        }
    }

    // --- Helpers ---

    private static ArtifactIdentity artifact(String ns, String name, String version) {
        return new ArtifactIdentity() {
            public String namespace() {
                return ns;
            }

            public String name() {
                return name;
            }

            public String version() {
                return version;
            }
        };
    }

    private static TrustPolicy policyFor(SignerIdentity signer, boolean requireAll) {
        return new TrustPolicy() {
            public List<SignerIdentity> expectedSigners(ArtifactIdentity a) {
                return List.of(signer);
            }

            public boolean isUnsignedAllowed(ArtifactIdentity a) {
                return false;
            }

            public boolean requireAllEvidenceMatch() {
                return requireAll;
            }

            public UntrustedPolicy onUntrusted() {
                return UntrustedPolicy.FAIL;
            }
        };
    }

    private static TrustPolicy emptyPolicy() {
        return new TrustPolicy() {
            public List<SignerIdentity> expectedSigners(ArtifactIdentity a) {
                return List.of();
            }

            public boolean isUnsignedAllowed(ArtifactIdentity a) {
                return false;
            }

            public boolean requireAllEvidenceMatch() {
                return false;
            }

            public UntrustedPolicy onUntrusted() {
                return UntrustedPolicy.FAIL;
            }
        };
    }

    private static final VerifyResult PGP_PASS = new OpenPgpVerifyResult(
            Verdict.PASS, null, null, 4, null, null);

    private static EvidenceProvider passingProvider(String mechanism, Credential... proven) {
        return new EvidenceProvider() {
            public String name() {
                return mechanism;
            }

            public boolean isAvailable() {
                return true;
            }

            public boolean canHandle(Path f) {
                return true;
            }

            public List<EvidenceResult> verify(Path a, Path e) {
                return List.of(new EvidenceResult(PGP_PASS,
                        List.of(proven), mechanism));
            }
        };
    }

    private static EvidenceProvider failingProvider() {
        return new EvidenceProvider() {
            public String name() {
                return "openpgp";
            }

            public boolean isAvailable() {
                return true;
            }

            public boolean canHandle(Path f) {
                return true;
            }

            public List<EvidenceResult> verify(Path a, Path e) {
                return List.of(new EvidenceResult(new UnverifiedResult(Verdict.FAIL), List.of(), "openpgp"));
            }
        };
    }

    private static EvidenceProvider multiResultProvider(EvidenceResult... results) {
        return new EvidenceProvider() {
            public String name() {
                return "openpgp";
            }

            public boolean isAvailable() {
                return true;
            }

            public boolean canHandle(Path f) {
                return true;
            }

            public List<EvidenceResult> verify(Path a, Path e) {
                return List.of(results);
            }
        };
    }
}
