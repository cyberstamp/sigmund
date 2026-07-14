package io.github.cyberstamp.sigmund.core;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class CredentialMatchingTest {

    private static final VerifyResult PGP_PASS = new OpenPgpVerifyResult(
            Verdict.PASS, null, null, 4, null, null);
    private static final VerifyResult SIGSTORE_PASS = new SigstoreVerifyResult(
            Verdict.PASS, null, null, null, null);

    @Test
    void fingerprintMatchV4() {
        var signer = new SignerIdentity("alice", "Alice", List.of(
                new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23")));

        var evidence = new EvidenceResult(PGP_PASS, List.of(
                new FingerprintCredential("openpgp4",
                        "AB01CD23EF45678901234AEE18F83AFDEB23")),
                "openpgp");

        assertTrue(matchesAny(signer, evidence));
    }

    @Test
    void emailMatchAcrossBackends() {
        var signer = new SignerIdentity("alice", "Alice", List.of(
                new EmailCredential("alice@example.com")));

        var evidence = new EvidenceResult(SIGSTORE_PASS, List.of(
                new OidcCredential("https://accounts.google.com", "alice@example.com"),
                new EmailCredential("alice@example.com")),
                "sigstore");

        assertTrue(matchesAny(signer, evidence));
    }

    @Test
    void oidcMatchStrictIssuer() {
        var signer = new SignerIdentity("ci", "CI Pipeline", List.of(
                new OidcCredential("https://token.actions.githubusercontent.com",
                        "https://github.com/org/repo")));

        var evidence = new EvidenceResult(SIGSTORE_PASS, List.of(
                new OidcCredential("https://token.actions.githubusercontent.com",
                        "https://github.com/org/repo")),
                "sigstore");

        assertTrue(matchesAny(signer, evidence));
    }

    @Test
    void oidcMismatchWrongIssuer() {
        var signer = new SignerIdentity("ci", "CI Pipeline", List.of(
                new OidcCredential("https://token.actions.githubusercontent.com",
                        "https://github.com/org/repo")));

        var evidence = new EvidenceResult(SIGSTORE_PASS, List.of(
                new OidcCredential("https://evil-issuer.com",
                        "https://github.com/org/repo")),
                "sigstore");

        assertFalse(matchesAny(signer, evidence));
    }

    @Test
    void noOverlapDifferentCredentialTypes() {
        var signer = new SignerIdentity("alice", "Alice", List.of(
                new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23")));

        var evidence = new EvidenceResult(SIGSTORE_PASS, List.of(
                new EmailCredential("alice@example.com")),
                "sigstore");

        assertFalse(matchesAny(signer, evidence));
    }

    @Test
    void multipleCredentialsOneMatches() {
        var signer = new SignerIdentity("alice", "Alice", List.of(
                new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23"),
                new FingerprintCredential("openpgp6", "ABCD1234ABCD1234"),
                new EmailCredential("alice@example.com")));

        var evidence = new EvidenceResult(PGP_PASS, List.of(
                new FingerprintCredential("openpgp6", "ABCD1234ABCD1234")),
                "openpgp");

        assertTrue(matchesAny(signer, evidence));
    }

    @Test
    void emptyCredentialsNoMatch() {
        var signer = new SignerIdentity("empty", "Empty", List.of());
        var evidence = new EvidenceResult(SIGSTORE_PASS, List.of(
                new EmailCredential("alice@example.com")),
                "sigstore");

        assertFalse(matchesAny(signer, evidence));
    }

    private static boolean matchesAny(SignerIdentity signer, EvidenceResult evidence) {
        for (Credential proven : evidence.provenCredentials()) {
            for (Credential expected : signer.credentials()) {
                if (expected.matches(proven)) {
                    return true;
                }
            }
        }
        return false;
    }
}
