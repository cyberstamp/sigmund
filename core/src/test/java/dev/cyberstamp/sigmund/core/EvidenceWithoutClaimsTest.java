package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class EvidenceWithoutClaimsTest {

    private static final Path FILE = Path.of("repo/lib-1.0.jar.asc");
    private static final DigestSet EMPTY = DigestSet.sha256(new byte[0]);

    @Test
    void anUnreadableFileHasNoDigestAndSaysWhy() {
        EvidenceWithoutClaims unreadable = EvidenceWithoutClaims.unreadable(FILE, Evidence.SOURCE_SIDECAR,
                "permission denied");

        assertThat(unreadable.reason()).isEqualTo(IndeterminateReason.EVIDENCE_UNREADABLE);
        assertThat(unreadable.digest()).isNull();
        assertThat(unreadable.describe()).isEqualTo(FILE + " could not be read: permission denied");
    }

    @Test
    void aMalformedFileKeepsTheDigestOfWhatWasRead() {
        EvidenceWithoutClaims malformed = new EvidenceWithoutClaims(FILE, Evidence.SOURCE_SIDECAR,
                IndeterminateReason.EVIDENCE_MALFORMED, EMPTY, "is empty");

        assertThat(malformed.describe()).isEqualTo(FILE + " is empty");
    }

    @Test
    void aFileThatWasReadMustCarryItsDigest() {
        assertThatThrownBy(() -> new EvidenceWithoutClaims(FILE, Evidence.SOURCE_SIDECAR,
                IndeterminateReason.EVIDENCE_MALFORMED, null, "is empty"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aFileThatWasNotReadHasNoDigest() {
        assertThatThrownBy(() -> new EvidenceWithoutClaims(FILE, Evidence.SOURCE_SIDECAR,
                IndeterminateReason.EVIDENCE_UNREADABLE, EMPTY, "permission denied"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    /** Any other reason belongs to a claim a tool was asked about. */
    @Test
    void onlyAnUnreadableOrMalformedFileIsRecorded() {
        assertThatThrownBy(() -> new EvidenceWithoutClaims(FILE, Evidence.SOURCE_SIDECAR,
                IndeterminateReason.KEY_UNAVAILABLE, EMPTY, "no key"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
