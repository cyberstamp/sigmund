package dev.cyberstamp.sigmund.core;

import java.nio.file.Path;

/**
 * An evidence file that was found for an artifact but yielded no claim: one that could not be
 * read, or one whose bytes hold no signature its format recognises, such as an empty
 * {@code .asc} or one without an armored block.
 *
 * <p>
 * It is kept beside an artifact's claims rather than among them, since there is no claim to
 * record. It still counts: an artifact whose evidence did not all yield claims cannot be known
 * to satisfy a rule that rejects surplus claims, and one whose only evidence yielded none is not
 * unsigned. The roll-up reads it as an unresolved claim with its {@code reason}.
 *
 * @param file the evidence file
 * @param source the source that supplied it, such as {@link Evidence#SOURCE_SIDECAR}
 * @param reason {@link IndeterminateReason#EVIDENCE_UNREADABLE} when the file could not be read,
 *        which a later run may not repeat; {@link IndeterminateReason#EVIDENCE_MALFORMED} when
 *        its bytes hold no signature, which they never will
 * @param digest the digest of the bytes read, or {@code null} when nothing could be read
 * @param message why the file yielded no claim, said after its path in a report
 */
public record EvidenceWithoutClaims(Path file, String source, IndeterminateReason reason, DigestSet digest,
        String message) {

    /**
     * Rejects a record that cannot say what yielded no claim, or why.
     *
     * @throws IllegalArgumentException if the file, source or reason is missing, the reason is
     *         neither {@code EVIDENCE_UNREADABLE} nor {@code EVIDENCE_MALFORMED}, or the digest
     *         disagrees with it: absent for a file that was read, present for one that was not
     */
    public EvidenceWithoutClaims {
        if (file == null) {
            throw new IllegalArgumentException("evidence without claims must name its file");
        }
        if (source == null || source.isBlank()) {
            throw new IllegalArgumentException("evidence source must not be blank: " + file);
        }
        if (reason != IndeterminateReason.EVIDENCE_UNREADABLE && reason != IndeterminateReason.EVIDENCE_MALFORMED) {
            throw new IllegalArgumentException("evidence without claims is unreadable or malformed, not " + reason
                    + ": " + file);
        }
        if ((reason == IndeterminateReason.EVIDENCE_UNREADABLE) != (digest == null)) {
            throw new IllegalArgumentException("a digest is recorded exactly when the file was read: " + file);
        }
    }

    /**
     * Records a file that could not be read.
     *
     * @param file the evidence file
     * @param source the source that supplied it
     * @param message why it could not be read, as the file system said
     * @return the record
     */
    public static EvidenceWithoutClaims unreadable(Path file, String source, String message) {
        return new EvidenceWithoutClaims(file, source, IndeterminateReason.EVIDENCE_UNREADABLE, null, message);
    }

    /**
     * Records a file that was read but holds no signature its format recognises.
     *
     * @param evidence the evidence read
     * @return the record, saying whether the file was empty
     */
    public static EvidenceWithoutClaims holdingNoSignature(Evidence evidence) {
        return new EvidenceWithoutClaims(evidence.file(), evidence.source(), IndeterminateReason.EVIDENCE_MALFORMED,
                evidence.digest(), evidence.text().isBlank() ? "is empty" : "holds no signature");
    }

    /**
     * Describes the file and why it yielded no claim, for a report.
     *
     * @return the description, such as {@code lib.jar.asc could not be read: permission denied}
     *         or {@code lib.jar.asc is empty}
     */
    public String describe() {
        if (reason == IndeterminateReason.EVIDENCE_UNREADABLE) {
            return file + " could not be read" + (message == null ? "" : ": " + message);
        }
        return file + " " + message;
    }
}
