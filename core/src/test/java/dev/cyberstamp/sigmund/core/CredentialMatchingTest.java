package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class CredentialMatchingTest {

    private static final ArtifactCoords COORDS = new ArtifactCoords("org.example", "lib", "", "jar", "1.0");

    private static final EvidenceRef EVIDENCE_REF = new EvidenceRef(
            Path.of("artifact.jar.asc"),
            DigestSet.sha256("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            Evidence.SOURCE_SIDECAR);

    private static final VerifyResult PGP_PASS = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, null, null, 4, null,
            null);
    private static final VerifyResult SIGSTORE_PASS = new SigstoreVerifyResult(ClaimOutcome.VERIFIED, null, null, null, null,
            null, -1);

    @Test
    void fingerprintMatchV4() {
        var signer = new SignerIdentity("alice", "Alice", List.of(
                new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23")));

        var evidence = claim(List.of(
                new FingerprintCredential("openpgp4",
                        "AB01CD23EF45678901234AEE18F83AFDEB23")));

        assertThat(matchesAny(signer, evidence)).isTrue();
    }

    @Test
    void emailMatchAcrossBackends() {
        var signer = new SignerIdentity("alice", "Alice", List.of(
                new EmailCredential("alice@example.com")));

        var evidence = claim(List.of(
                new SigstoreCredential.Builder()
                        .issuer("https://accounts.google.com")
                        .subject("alice@example.com")
                        .build(),
                new EmailCredential("alice@example.com")));

        assertThat(matchesAny(signer, evidence)).isTrue();
    }

    @Test
    void sigstoreMatchStrictIssuer() {
        var signer = new SignerIdentity("ci", "CI Pipeline", List.of(
                new SigstoreCredential.Builder()
                        .issuer("https://token.actions.githubusercontent.com")
                        .subject("https://github.com/org/repo")
                        .build()));

        var evidence = claim(List.of(
                new SigstoreCredential.Builder()
                        .issuer("https://token.actions.githubusercontent.com")
                        .subject("https://github.com/org/repo")
                        .build()));

        assertThat(matchesAny(signer, evidence)).isTrue();
    }

    @Test
    void sigstoreMismatchWrongIssuer() {
        var signer = new SignerIdentity("ci", "CI Pipeline", List.of(
                new SigstoreCredential.Builder()
                        .issuer("https://token.actions.githubusercontent.com")
                        .subject("https://github.com/org/repo")
                        .build()));

        var evidence = claim(List.of(
                new SigstoreCredential.Builder()
                        .issuer("https://evil-issuer.com")
                        .subject("https://github.com/org/repo")
                        .build()));

        assertThat(matchesAny(signer, evidence)).isFalse();
    }

    @Test
    void noOverlapDifferentCredentialTypes() {
        var signer = new SignerIdentity("alice", "Alice", List.of(
                new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23")));

        var evidence = claim(List.of(
                new EmailCredential("alice@example.com")));

        assertThat(matchesAny(signer, evidence)).isFalse();
    }

    @Test
    void multipleCredentialsOneMatches() {
        var signer = new SignerIdentity("alice", "Alice", List.of(
                new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23"),
                new FingerprintCredential("openpgp6", "ABCD1234ABCD1234"),
                new EmailCredential("alice@example.com")));

        var evidence = claim(List.of(
                new FingerprintCredential("openpgp6", "ABCD1234ABCD1234")));

        assertThat(matchesAny(signer, evidence)).isTrue();
    }

    @Test
    void emptyCredentialsNoMatch() {
        var signer = new SignerIdentity("empty", "Empty", List.of());
        var evidence = claim(List.of(
                new EmailCredential("alice@example.com")));

        assertThat(matchesAny(signer, evidence)).isFalse();
    }

    /**
     * Runs the production matching path: a policy that expects this signer, evaluated over a
     * claim that proved these credentials.
     */
    private static boolean matchesAny(SignerIdentity signer, ClaimResult claim) {
        TrustPolicy policy = new DefaultTrustPolicy(
                Map.of(COORDS.namespace(), List.of(signer)), List.of(),
                ListedEvidencePolicy.ALL, UnlistedEvidencePolicy.IGNORE, UntrustedPolicy.FAIL);

        RequirementEvaluator.Evaluation evaluation = policy.requirements().evaluate(COORDS, List.of(claim));

        return evaluation != null && evaluation.satisfied();
    }

    private static ClaimResult claim(List<Credential> provenCredentials) {
        return new ClaimResult("openpgp", ClaimOutcome.VERIFIED, null, provenCredentials, null,
                AttesterRole.UNKNOWN, TrustRootRef.unknown(), EVIDENCE_REF, null,
                ClaimTimeSource.SIGNER, Instant.EPOCH, "RSA", "bc");
    }
}
