package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EvidenceRefTest {

    /** SHA-256 of the string {@code abc}. */
    private static final String ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    @Nested
    class FromFile {

        @Test
        void digestsTheEvidenceThatWasConsumed(@TempDir Path dir) throws IOException {
            Path evidence = Files.writeString(dir.resolve("lib.jar.asc"), "abc");

            EvidenceRef ref = EvidenceRef.of(evidence, Evidence.SOURCE_SIDECAR);

            assertThat(ref.file()).isEqualTo(evidence);
            assertThat(ref.digest().sha256()).isEqualTo(ABC_SHA256);
            assertThat(ref.source()).isEqualTo(Evidence.SOURCE_SIDECAR);
        }

        @Test
        void unreadableEvidenceIsAnError(@TempDir Path dir) {
            assertThatThrownBy(
                    () -> EvidenceRef.of(dir.resolve("absent.asc"), Evidence.SOURCE_SIDECAR))
                    .isInstanceOf(SigmundException.class);
        }
    }

    @Nested
    class Construction {

        @Test
        void sourceIsRequired(@TempDir Path dir) {
            assertThatThrownBy(() -> new EvidenceRef(dir.resolve("x.asc"),
                    DigestSet.sha256(ABC_SHA256), " "))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void digestIsRequired(@TempDir Path dir) {
            assertThatThrownBy(() -> new EvidenceRef(dir.resolve("x.asc"), null,
                    Evidence.SOURCE_SIDECAR))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }
}
