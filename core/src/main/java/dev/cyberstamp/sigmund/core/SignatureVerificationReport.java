package dev.cyberstamp.sigmund.core;

import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Hierarchical verification report for direct signature verification (without trust policy).
 * <p>
 * Aggregates per-file sub-reports. Callers can read the counts by claim outcome, ask whether
 * the file passed strictly or leniently, or drill into each file's results.
 */
public class SignatureVerificationReport {

    private final List<FileSignatureReport> files;

    /**
     * Creates a new report from per-file sub-reports.
     *
     * @param files the per-file verification reports
     */
    public SignatureVerificationReport(List<FileSignatureReport> files) {
        this.files = List.copyOf(files);
    }

    /**
     * Returns how many claims reached each outcome across every file in this report.
     *
     * <p>
     * Counts rather than a single summary name: "2 verified, 1 indeterminate" says what
     * happened, where a name like "pass with skips" hides the numbers and speaks a vocabulary
     * the model no longer uses — an unverifiable claim is indeterminate, with a reason, not
     * skipped.
     *
     * @return counts by claim outcome, omitting outcomes nothing reached
     */
    public Map<ClaimOutcome, Integer> counts() {
        Map<ClaimOutcome, Integer> counts = new EnumMap<>(ClaimOutcome.class);
        for (FileSignatureReport file : files) {
            for (VerifyResult result : file.results()) {
                counts.merge(result.outcome(), 1, Integer::sum);
            }
        }
        return Collections.unmodifiableMap(counts);
    }

    /**
     * Renders the counts as a one-line summary, such as {@code 2 VERIFIED, 1 INDETERMINATE}.
     *
     * @return the summary, or {@code no claims found} when nothing was verified
     */
    public String summary() {
        Map<ClaimOutcome, Integer> counts = counts();
        if (counts.isEmpty()) {
            return "no claims found";
        }
        return counts.entrySet().stream()
                .map(entry -> entry.getValue() + " " + entry.getKey())
                .collect(Collectors.joining(", "));
    }

    /**
     * Returns the per-file sub-reports.
     *
     * @return an unmodifiable list of file reports
     */
    public List<FileSignatureReport> files() {
        return files;
    }

    /**
     * Strict pass: all signatures must be valid.
     *
     * @return {@code true} when at least one claim verified and none failed or was left
     *         undecided
     */
    public boolean isPass() {
        Map<ClaimOutcome, Integer> counts = counts();
        return counts.containsKey(ClaimOutcome.VERIFIED)
                && !counts.containsKey(ClaimOutcome.FAILED)
                && !counts.containsKey(ClaimOutcome.INDETERMINATE);
    }

    /**
     * Lenient pass: at least one signature valid, none failed.
     *
     * @return {@code true} when at least one claim verified and none failed, whatever was
     *         left undecided
     */
    public boolean isLenientPass() {
        Map<ClaimOutcome, Integer> counts = counts();
        return counts.containsKey(ClaimOutcome.VERIFIED)
                && !counts.containsKey(ClaimOutcome.FAILED);
    }

    /**
     * Formats the report as a human-readable multi-line string.
     *
     * @return the formatted report
     */
    public String format() {
        var sb = new StringBuilder();
        sb.append("Signature Verification Report:\n");
        int idx = 1;
        for (FileSignatureReport file : files) {
            for (VerifyResult r : file.results()) {
                sb.append("  [").append(idx++).append("] ");
                formatResult(sb, r);
                sb.append('\n');
            }
        }
        sb.append("  Overall: ").append(summary());
        return sb.toString();
    }

    private void formatResult(StringBuilder sb, VerifyResult r) {
        sb.append(r.outcome());
        if (r.reason() != null) {
            sb.append(" [").append(r.reason()).append(']');
        }
        if (r.algorithm() != null) {
            sb.append(" (").append(r.algorithm()).append(')');
        }
        if (r instanceof OpenPgpVerifyResult opvr) {
            if (opvr.keyId() != null) {
                sb.append(" [key: ").append(opvr.keyId()).append(']');
            }
        }
        if (r.signerDisplayName() != null) {
            sb.append(" [signer: ").append(r.signerDisplayName()).append(']');
        }
    }
}
