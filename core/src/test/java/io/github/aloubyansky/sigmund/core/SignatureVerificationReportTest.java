package io.github.aloubyansky.sigmund.core;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class SignatureVerificationReportTest {

    @Nested
    class OutcomeTests {

        @Test
        void allPass() {
            var report = reportWith(passResult(), passResult());
            assertEquals(ReportVerdict.ALL_PASS, report.verdict());
            assertTrue(report.isPass());
            assertTrue(report.isLenientPass());
        }

        @Test
        void passWithSkipped() {
            var report = reportWith(passResult(), skippedResult());
            assertEquals(ReportVerdict.PASS_WITH_SKIPS, report.verdict());
            assertFalse(report.isPass());
            assertTrue(report.isLenientPass());
        }

        @Test
        void passWithNoKey() {
            var report = reportWith(passResult(), noKeyResult());
            assertEquals(ReportVerdict.PASS_WITH_SKIPS, report.verdict());
            assertFalse(report.isPass());
            assertTrue(report.isLenientPass());
        }

        @Test
        void passWithFailures() {
            var report = reportWith(passResult(), failResult());
            assertEquals(ReportVerdict.PASS_WITH_FAILURES, report.verdict());
            assertFalse(report.isPass());
            assertFalse(report.isLenientPass());
        }

        @Test
        void allFail() {
            var report = reportWith(failResult(), failResult());
            assertEquals(ReportVerdict.NONE_PASSED, report.verdict());
            assertFalse(report.isPass());
            assertFalse(report.isLenientPass());
        }

        @Test
        void allSkipped() {
            var report = reportWith(skippedResult());
            assertEquals(ReportVerdict.NONE_PASSED, report.verdict());
        }

        @Test
        void emptyReport() {
            var report = new SignatureVerificationReport(List.of());
            assertEquals(ReportVerdict.NONE_PASSED, report.verdict());
            assertFalse(report.isPass());
            assertFalse(report.isLenientPass());
        }

        @Test
        void emptyFileReport() {
            var report = new SignatureVerificationReport(
                    List.of(new FileSignatureReport(Path.of("test.asc"), "openpgp", List.of())));
            assertEquals(ReportVerdict.NONE_PASSED, report.verdict());
        }
    }

    @Nested
    class MultiFileTests {

        @Test
        void aggregatesAcrossFiles() {
            var file1 = new FileSignatureReport(Path.of("a.asc"), "openpgp", List.of(passResult()));
            var file2 = new FileSignatureReport(Path.of("b.asc"), "openpgp", List.of(failResult()));
            var report = new SignatureVerificationReport(List.of(file1, file2));
            assertEquals(ReportVerdict.PASS_WITH_FAILURES, report.verdict());
        }

        @Test
        void filesListIsUnmodifiable() {
            var report = reportWith(passResult());
            assertThrows(UnsupportedOperationException.class, () -> report.files().add(null));
        }
    }

    @Nested
    class FormatTests {

        @Test
        void formatContainsResultsAndOutcome() {
            var report = reportWith(passResult());
            String formatted = report.format();
            assertTrue(formatted.contains("Signature Verification Report:"));
            assertTrue(formatted.contains("[1]"));
            assertTrue(formatted.contains("PASS"));
            assertTrue(formatted.contains("Overall: ALL_PASS"));
        }

        @Test
        void formatIncludesAlgorithm() {
            var result = new OpenPgpVerifyResult(Verdict.PASS,
                    "Alice", "RSA", 4, "ABCD1234", "FULL_FP");
            var report = reportWith(result);
            String formatted = report.format();
            assertTrue(formatted.contains("(RSA)"));
        }

        @Test
        void formatIncludesKeyId() {
            var result = new OpenPgpVerifyResult(Verdict.PASS,
                    null, null, 4, "ABCD1234", "FULL_FP");
            var report = reportWith(result);
            String formatted = report.format();
            assertTrue(formatted.contains("[key: ABCD1234]"));
        }

        @Test
        void formatIncludesSignerName() {
            var result = new OpenPgpVerifyResult(Verdict.PASS,
                    "Alice <alice@example.com>", "RSA", 4, null, null);
            var report = reportWith(result);
            String formatted = report.format();
            assertTrue(formatted.contains("[signer: Alice <alice@example.com>]"));
        }
    }

    // --- Helpers ---

    private static SignatureVerificationReport reportWith(VerifyResult... results) {
        return new SignatureVerificationReport(
                List.of(new FileSignatureReport(Path.of("test.asc"), "openpgp", List.of(results))));
    }

    private static OpenPgpVerifyResult passResult() {
        return new OpenPgpVerifyResult(Verdict.PASS, null, "RSA", 4, null, null);
    }

    private static OpenPgpVerifyResult failResult() {
        return new OpenPgpVerifyResult(Verdict.FAIL, null, null, 4, null, null);
    }

    private static OpenPgpVerifyResult skippedResult() {
        return new OpenPgpVerifyResult(Verdict.SKIPPED, null, null, 4, null, null);
    }

    private static OpenPgpVerifyResult noKeyResult() {
        return new OpenPgpVerifyResult(Verdict.NO_KEY, null, null, 4, null, null);
    }
}
