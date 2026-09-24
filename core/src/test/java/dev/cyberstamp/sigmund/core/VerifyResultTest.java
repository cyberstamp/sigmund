package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class VerifyResultTest {

    private static final EvidenceRef EVIDENCE_REF = new EvidenceRef(
            Path.of("artifact.jar.asc"),
            DigestSet.sha256("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            Evidence.SOURCE_SIDECAR);

    @Nested
    class Factories {

        @Test
        void bareIndeterminateCarriesOnlyTheReason() {
            OpenPgpVerifyResult result = OpenPgpVerifyResult.indeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM);

            assertThat(result.isIndeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM)).isTrue();
            assertThat(result.signerDisplayName()).isNull();
            assertThat(result.algorithm()).isNull();
            assertThat(result.version()).isEqualTo(-1);
            assertThat(result.keyId()).isNull();
            assertThat(result.fingerprint()).isNull();
        }

        @Test
        void indeterminateKeepsWhatTheSignatureAlreadyRevealed() {
            OpenPgpVerifyResult result = OpenPgpVerifyResult.indeterminate(
                    IndeterminateReason.KEY_UNAVAILABLE, "User <user@example.com>", "RSA", 4,
                    "ABCD1234", "ABCD1234");

            assertThat(result.isIndeterminate(IndeterminateReason.KEY_UNAVAILABLE)).isTrue();
            assertThat(result.algorithm()).isEqualTo("RSA");
            assertThat(result.preferredKeyId()).isEqualTo("ABCD1234");
        }

        @Test
        void verifiedCarriesNoReason() {
            OpenPgpVerifyResult result = OpenPgpVerifyResult.verified("User", "Ed25519", 4, "AAAA", "AAAA");

            assertThat(result.isVerified()).isTrue();
            assertThat(result.reason()).isNull();
        }

        @Test
        void failedCarriesNoReason() {
            OpenPgpVerifyResult result = OpenPgpVerifyResult.failed("User", "Ed25519", 4, "AAAA", "AAAA");

            assertThat(result.isFailed()).isTrue();
            assertThat(result.reason()).isNull();
        }

        @Test
        void sigstoreIndeterminateCarriesOnlyTheReason() {
            SigstoreVerifyResult result = SigstoreVerifyResult.indeterminate(IndeterminateReason.EVIDENCE_MALFORMED);

            assertThat(result.isIndeterminate(IndeterminateReason.EVIDENCE_MALFORMED)).isTrue();
            assertThat(result.sigstoreCredential()).isNull();
            assertThat(result.logIndex()).isNull();
        }

        @Test
        void aConclusiveOutcomeCannotCarryAReason() {
            assertThatThrownBy(() -> new OpenPgpVerifyResult(ClaimOutcome.VERIFIED,
                    IndeterminateReason.KEY_UNAVAILABLE, null, null, 4, null, null))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    class UnverifiedResultTests {

        @Test
        void skippedVerdict() {
            var result = new UnverifiedResult(ClaimOutcome.INDETERMINATE, IndeterminateReason.UNSUPPORTED_ALGORITHM);
            assertThat(result.isIndeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM)).isTrue();
            assertThat(result.signerDisplayName()).isNull();
            assertThat(result.algorithm()).isNull();
            assertThat(result.signerIdentifier()).isNull();
        }

        @Test
        void failVerdict() {
            var result = new UnverifiedResult(ClaimOutcome.FAILED, null);
            assertThat(result.isFailed()).isTrue();
        }

        @Test
        void noKeyVerdict() {
            var result = new UnverifiedResult(ClaimOutcome.INDETERMINATE, IndeterminateReason.KEY_UNAVAILABLE);
            assertThat(result.isIndeterminate(IndeterminateReason.KEY_UNAVAILABLE)).isTrue();
        }

        @Test
        void passVerdictThrows() {
            assertThatThrownBy(() -> new UnverifiedResult(ClaimOutcome.VERIFIED, null))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    class OpenPgpPreferredKeyId {

        @Test
        void prefersFingerprint() {
            var result = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, null, null, 4, "SHORT", "FULL_FP");
            assertThat(result.preferredKeyId()).isEqualTo("FULL_FP");
        }

        @Test
        void fallsBackToKeyId() {
            var result = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, null, null, 4, "SHORT", null);
            assertThat(result.preferredKeyId()).isEqualTo("SHORT");
        }

        @Test
        void nullWhenBothNull() {
            var result = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, null, null, 4, null, null);
            assertThat(result.preferredKeyId()).isNull();
        }
    }

    @Nested
    class SignerIdentifier {

        @Test
        void openPgpReturnsPreferredKeyId() {
            var result = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, null, null, 4, "SHORT", "FULL_FP");
            assertThat(result.signerIdentifier()).isEqualTo("FULL_FP");
        }

        @Test
        void openPgpFallsBackToKeyId() {
            var result = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, null, null, 6, "SHORT", null);
            assertThat(result.signerIdentifier()).isEqualTo("SHORT");
        }

        @Test
        void sigstoreReturnsOidcSubject() {
            var sc = new SigstoreCredential.Builder()
                    .issuer("https://accounts.google.com")
                    .subject("alice@example.com")
                    .build();
            var result = new SigstoreVerifyResult(ClaimOutcome.VERIFIED, null, "alice@example.com", "ECDSA",
                    sc, "12345", 1);
            assertThat(result.signerIdentifier()).isEqualTo("alice@example.com");
        }

        @Test
        void unverifiedReturnsNull() {
            var result = new UnverifiedResult(ClaimOutcome.INDETERMINATE, IndeterminateReason.UNSUPPORTED_ALGORITHM);
            assertThat(result.signerIdentifier()).isNull();
        }
    }
}
