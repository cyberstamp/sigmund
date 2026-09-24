package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class OpenPgpCredentialsTest {

    private static final String FP = "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12";

    @Nested
    class EmailFromUserId {

        @Test
        void nameAndAngleBracketedAddress() {
            assertThat(OpenPgpCredentials.email("Alice <alice@example.com>"))
                    .isEqualTo("alice@example.com");
        }

        @Test
        void bareAddress() {
            assertThat(OpenPgpCredentials.email("alice@example.com"))
                    .isEqualTo("alice@example.com");
        }

        @Test
        void nameWithoutAnAddress() {
            assertThat(OpenPgpCredentials.email("Alice Example")).isNull();
        }

        @Test
        void emptyAngleBrackets() {
            assertThat(OpenPgpCredentials.email("Alice <>")).isNull();
        }

        @Test
        void missingUserId() {
            assertThat(OpenPgpCredentials.email(null)).isNull();
        }
    }

    @Nested
    class CredentialsFromResult {

        @Test
        void v4SignatureProvesAV4Fingerprint() {
            VerifyResult result = OpenPgpVerifyResult.verified(
                    "Alice <alice@example.com>", "RSA", 4, FP, FP);

            assertThat(OpenPgpCredentials.from(result)).containsExactly(
                    new FingerprintCredential(Credential.TYPE_OPENPGP_V4, FP),
                    new EmailCredential("alice@example.com"));
        }

        @Test
        void v6SignatureProvesAV6Fingerprint() {
            VerifyResult result = OpenPgpVerifyResult.verified(null, "Ed25519", 6, FP, FP);

            assertThat(OpenPgpCredentials.from(result))
                    .containsExactly(new FingerprintCredential(Credential.TYPE_OPENPGP_V6, FP));
        }

        @Test
        void anUnverifiedClaimProvesNothing() {
            VerifyResult failed = OpenPgpVerifyResult.failed(
                    "Alice <alice@example.com>", "RSA", 4, FP, FP);

            assertThat(OpenPgpCredentials.from(failed)).isEmpty();
        }

        @Test
        void anIndeterminateClaimProvesNothing() {
            VerifyResult unresolved = OpenPgpVerifyResult.indeterminate(
                    IndeterminateReason.KEY_UNAVAILABLE, "Alice <alice@example.com>", "RSA", 4,
                    FP, FP);

            assertThat(OpenPgpCredentials.from(unresolved)).isEmpty();
        }

        @Test
        void aResultWithoutAFingerprintProvesNothing() {
            VerifyResult noFingerprint = OpenPgpVerifyResult.verified("Alice <alice@example.com>", "RSA", 4, null, null);

            assertThat(OpenPgpCredentials.from(noFingerprint)).isEmpty();
        }

        @Test
        void aSigstoreResultIsNotAnOpenPgpClaim() {
            VerifyResult sigstore = SigstoreVerifyResult.indeterminate(IndeterminateReason.EVIDENCE_MALFORMED);

            assertThat(OpenPgpCredentials.from(sigstore)).isEmpty();
        }
    }
}
