package io.github.aloubyansky.sigmund.core;

import java.util.List;

/**
 * Represents the combined result of verifying all signatures in an ASC file.
 * <p>
 * Each signature block is parsed, classified by its OpenPGP version, and
 * verified independently. The report holds the verification result for
 * every signature found.
 *
 * @param signatures the verification results for each signature block, in order
 *
 * @see HybridVerifier
 * @see SignatureInfo
 * @see VerificationResult
 */
public record VerificationReport(List<SignatureInfo> signatures) {

    public VerificationReport {
        signatures = List.copyOf(signatures);
    }

    /**
     * Computes the aggregate outcome from the individual signature results.
     *
     * @return the {@link VerificationOutcome} for this report
     */
    public VerificationOutcome outcome() {
        if (signatures.isEmpty()) {
            return VerificationOutcome.NONE_PASSED;
        }
        boolean anyPass = signatures.stream()
                .anyMatch(s -> s.result() == VerificationResult.PASS);
        if (!anyPass) {
            return VerificationOutcome.NONE_PASSED;
        }
        boolean anyFail = signatures.stream()
                .anyMatch(s -> s.result() == VerificationResult.FAIL);
        if (anyFail) {
            return VerificationOutcome.PASS_WITH_FAILURES;
        }
        boolean allPass = signatures.stream()
                .allMatch(s -> s.result() == VerificationResult.PASS);
        return allPass ? VerificationOutcome.ALL_PASS : VerificationOutcome.PASS_WITH_SKIPS;
    }

    /**
     * Determines if verification passes under the default (strict) policy.
     * <p>
     * Requires every signature in the file to be verified successfully.
     * Returns false if there are no signatures.
     *
     * @return true if the signature list is non-empty and every signature
     *         has {@link VerificationResult#PASS}
     */
    public boolean isPass() {
        return outcome() == VerificationOutcome.ALL_PASS;
    }

    /**
     * Determines if verification passes under lenient policy.
     * <p>
     * Requires at least one signature to pass and no signature to have failed.
     * Skipped or no-key signatures are tolerated.
     *
     * @return true if at least one signature passed and none failed
     */
    public boolean isLenientPass() {
        VerificationOutcome o = outcome();
        return o == VerificationOutcome.ALL_PASS || o == VerificationOutcome.PASS_WITH_SKIPS;
    }

    /**
     * Formats the verification report as a human-readable multi-line string.
     * <p>
     * Lists each signature with its version, algorithm, verification result,
     * and key information, followed by an overall assessment.
     *
     * @return a formatted multi-line string describing the verification results
     */
    public String format() {
        StringBuilder sb = new StringBuilder();
        sb.append("Signature Verification Report:\n");

        if (signatures.isEmpty()) {
            sb.append("  No signatures found\n");
            sb.append("  Overall: FAIL (no valid signatures)");
            return sb.toString();
        }

        for (int i = 0; i < signatures.size(); i++) {
            formatSignatureLine(sb, i + 1, signatures.get(i));
            sb.append("\n");
        }

        formatOverallLine(sb);
        return sb.toString();
    }

    private void formatSignatureLine(StringBuilder sb, int index, SignatureInfo sig) {
        sb.append("  [").append(index).append("] ");
        sb.append(versionLabel(sig.version(), sig.algorithm()));

        String algo = sig.algorithm();
        if (algo != null && !algo.isEmpty()) {
            sb.append(" (").append(algo).append(")");
        }

        sb.append(": ");
        sb.append(String.format("%-11s", sig.result()));

        if (sig.keyId() != null && !sig.keyId().isEmpty()) {
            sb.append(" [key: ").append(sig.keyId()).append("]");
        }

        if (sig.signerUserId() != null && !sig.signerUserId().isEmpty()) {
            sb.append(" [signer: ").append(sig.signerUserId()).append("]");
        }
    }

    private void formatOverallLine(StringBuilder sb) {
        sb.append("  Overall: ");
        long passCount = signatures.stream()
                .filter(s -> s.result() == VerificationResult.PASS).count();
        switch (outcome()) {
            case ALL_PASS -> {
                sb.append("PASS (all ").append(signatures.size()).append(" signature");
                if (signatures.size() > 1) {
                    sb.append("s");
                }
                sb.append(" valid)");
            }
            case PASS_WITH_SKIPS ->
                sb.append("PASS (").append(passCount).append("/")
                        .append(signatures.size()).append(" verified)");
            case PASS_WITH_FAILURES -> {
                long failCount = signatures.stream()
                        .filter(s -> s.result() == VerificationResult.FAIL).count();
                sb.append("FAIL (").append(passCount).append("/")
                        .append(signatures.size()).append(" passed, ")
                        .append(failCount).append(" failed)");
            }
            case NONE_PASSED ->
                sb.append("FAIL (no valid signatures)");
        }
    }

    static String versionLabel(int version, String algorithm) {
        if (version > 0 && version <= 4) {
            return "GPG v" + version;
        } else if (version > 4) {
            if (algorithm != null && AscCombiner.isPqcAlgorithmName(algorithm)) {
                return "PQC v" + version;
            }
            return "SQ v" + version;
        }
        return "unknown";
    }
}
