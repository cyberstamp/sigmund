package dev.cyberstamp.sigmund.core;

import java.nio.file.Path;
import java.util.List;

/**
 * Verification report for a single signature file.
 *
 * @param signatureFile the signature file that was verified
 * @param format the signature format name (e.g., {@code "openpgp"})
 * @param results what each claim in the file established, in the order the file holds them
 */
public record FileSignatureReport(
        Path signatureFile,
        String format,
        List<ClaimResult> results) {

    /**
     * Creates a report with a defensive copy.
     */
    public FileSignatureReport {
        results = List.copyOf(results);
    }
}
