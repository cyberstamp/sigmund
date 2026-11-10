package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class SignatureVerificationReportTest {

    @Nested
    class OutcomeTests {

        @Test
        void allPass() {
            var report = reportWith(passResult(), passResult());
            assertThat(report.counts()).containsExactly(Map.entry(ClaimOutcome.VERIFIED, 2));
            assertThat(report.isPass()).isTrue();
            assertThat(report.isLenientPass()).isTrue();
        }

        @Test
        void passWithSkipped() {
            var report = reportWith(passResult(), skippedResult());
            assertThat(report.counts()).containsEntry(ClaimOutcome.INDETERMINATE, 1);
            assertThat(report.isPass()).isFalse();
            assertThat(report.isLenientPass()).isTrue();
        }

        @Test
        void passWithNoKey() {
            var report = reportWith(passResult(), noKeyResult());
            assertThat(report.counts()).containsEntry(ClaimOutcome.INDETERMINATE, 1);
            assertThat(report.isPass()).isFalse();
            assertThat(report.isLenientPass()).isTrue();
        }

        @Test
        void passWithFailures() {
            var report = reportWith(passResult(), failResult());
            assertThat(report.counts()).containsEntry(ClaimOutcome.FAILED, 1);
            assertThat(report.isPass()).isFalse();
            assertThat(report.isLenientPass()).isFalse();
        }

        @Test
        void allFail() {
            var report = reportWith(failResult(), failResult());
            assertThat(report.counts()).doesNotContainKey(ClaimOutcome.VERIFIED);
            assertThat(report.isPass()).isFalse();
            assertThat(report.isLenientPass()).isFalse();
        }

        @Test
        void allSkipped() {
            var report = reportWith(skippedResult());
            assertThat(report.counts()).doesNotContainKey(ClaimOutcome.VERIFIED);
        }

        @Test
        void emptyReport() {
            var report = new SignatureVerificationReport(List.of());
            assertThat(report.counts()).doesNotContainKey(ClaimOutcome.VERIFIED);
            assertThat(report.isPass()).isFalse();
            assertThat(report.isLenientPass()).isFalse();
        }

        @Test
        void emptyFileReport() {
            var report = new SignatureVerificationReport(
                    List.of(new FileSignatureReport(Path.of("test.asc"), "openpgp", List.of())));
            assertThat(report.counts()).doesNotContainKey(ClaimOutcome.VERIFIED);
        }
    }

    @Nested
    class MultiFileTests {

        @Test
        void aggregatesAcrossFiles() {
            var file1 = new FileSignatureReport(Path.of("a.asc"), "openpgp", List.of(claimOf(passResult())));
            var file2 = new FileSignatureReport(Path.of("b.asc"), "openpgp", List.of(claimOf(failResult())));
            var report = new SignatureVerificationReport(List.of(file1, file2));
            assertThat(report.counts()).containsEntry(ClaimOutcome.FAILED, 1);
        }

        @Test
        void filesListIsUnmodifiable() {
            var report = reportWith(passResult());
            assertThatThrownBy(() -> report.files().add(null))
                    .isInstanceOf(UnsupportedOperationException.class);
        }
    }

    @Nested
    class FormatTests {

        @Test
        void formatContainsResultsAndOutcome() {
            var report = reportWith(passResult());
            String formatted = report.format();
            assertThat(formatted).contains("Signature Verification Report:");
            assertThat(formatted).contains("[1]");
            assertThat(formatted).contains("VERIFIED");
            assertThat(formatted).contains("Overall: 1 VERIFIED");
        }

        @Test
        void formatIncludesAlgorithm() {
            var result = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null,
                    "Alice", "RSA", 4, "ABCD1234", "FULL_FP");
            var report = reportWith(result);
            String formatted = report.format();
            assertThat(formatted).contains("(RSA)");
        }

        @Test
        void formatIncludesKeyId() {
            var result = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null,
                    null, null, 4, "ABCD1234", "FULL_FP");
            var report = reportWith(result);
            String formatted = report.format();
            assertThat(formatted).contains("[key: ABCD1234]");
        }

        @Test
        void formatIncludesSignerName() {
            var result = new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null,
                    "Alice <alice@example.com>", "RSA", 4, null, null);
            var report = reportWith(result);
            String formatted = report.format();
            assertThat(formatted).contains("[signer: Alice <alice@example.com>]");
        }
    }

    // --- Helpers ---

    private static SignatureVerificationReport reportWith(VerifyResult... results) {
        return new SignatureVerificationReport(List.of(new FileSignatureReport(Path.of("test.asc"),
                "openpgp", Stream.of(results).map(SignatureVerificationReportTest::claimOf).toList())));
    }

    /** What a claim established when a bc answer is the one that counts. */
    private static ClaimResult claimOf(VerifyResult result) {
        return ClaimResult.of(new OpenPgpClaim("armored", 4, null, 1, null), "openpgp", result,
                List.of(), new EvidenceRef(Path.of("test.asc"),
                        DigestSet.sha256("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
                        Evidence.SOURCE_SIDECAR),
                TrustRootRef.unknown(), "bc", Instant.EPOCH);
    }

    private static OpenPgpVerifyResult passResult() {
        return new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, null, "RSA", 4, null, null);
    }

    private static OpenPgpVerifyResult failResult() {
        return new OpenPgpVerifyResult(ClaimOutcome.FAILED, null, null, null, 4, null, null);
    }

    private static OpenPgpVerifyResult skippedResult() {
        return new OpenPgpVerifyResult(ClaimOutcome.INDETERMINATE, IndeterminateReason.UNSUPPORTED_ALGORITHM, null, null, 4,
                null, null);
    }

    private static OpenPgpVerifyResult noKeyResult() {
        return new OpenPgpVerifyResult(ClaimOutcome.INDETERMINATE, IndeterminateReason.KEY_UNAVAILABLE, null, null, 4, null,
                null);
    }
}
