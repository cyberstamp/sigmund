package io.github.aloubyansky.sigmund.core;

import java.nio.file.Path;
import java.util.List;

/**
 * Verification report for a single signature file.
 *
 * @param signatureFile the signature file that was verified
 * @param format the signature format name (e.g., {@code "openpgp"})
 * @param results the typed per-backend verification results
 */
public record FileSignatureReport(
        Path signatureFile,
        String format,
        List<VerifyResult> results) {

    /**
     * Creates a report with a defensive copy.
     */
    public FileSignatureReport {
        results = List.copyOf(results);
    }
}
