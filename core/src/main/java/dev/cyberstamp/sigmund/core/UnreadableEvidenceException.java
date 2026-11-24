package dev.cyberstamp.sigmund.core;

/**
 * Thrown when an evidence file cannot be read, carrying the record of it.
 *
 * <p>
 * A caller verifying many artifacts records the file as {@link EvidenceWithoutClaims} and goes
 * on with the rest; one handed a single signature file to check reports the error.
 */
public class UnreadableEvidenceException extends ToolExecutionException {

    private final transient EvidenceWithoutClaims evidence;

    /**
     * Creates the exception for a file that could not be read.
     *
     * @param evidence the record of the file and why, {@link IndeterminateReason#EVIDENCE_UNREADABLE}
     * @param cause the error reading it
     */
    public UnreadableEvidenceException(EvidenceWithoutClaims evidence, Throwable cause) {
        super("Failed to read evidence file: " + evidence.file(), cause);
        this.evidence = evidence;
    }

    /**
     * Returns the record of the file that could not be read.
     *
     * @return the record
     */
    public EvidenceWithoutClaims evidence() {
        return evidence;
    }
}
