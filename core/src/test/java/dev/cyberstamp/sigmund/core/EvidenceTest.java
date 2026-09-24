package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EvidenceTest {

    /** SHA-256 of the string {@code abc}. */
    private static final String ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    @Nested
    class Reading {

        @Test
        void digestsTheBytesItRead(@TempDir Path dir) throws IOException {
            Path file = Files.writeString(dir.resolve("lib.jar.asc"), "abc");

            Evidence evidence = Evidence.read(file, Evidence.SOURCE_SIDECAR);

            assertThat(evidence.file()).isEqualTo(file);
            assertThat(evidence.source()).isEqualTo(Evidence.SOURCE_SIDECAR);
            assertThat(evidence.text()).isEqualTo("abc");
            assertThat(evidence.digest().sha256()).isEqualTo(ABC_SHA256);
        }

        @Test
        void digestDescribesTheContentEvenIfTheFileChangesLater(@TempDir Path dir)
                throws IOException {
            Path file = Files.writeString(dir.resolve("lib.jar.asc"), "abc");
            Evidence evidence = Evidence.read(file, Evidence.SOURCE_SIDECAR);

            Files.writeString(file, "replaced after reading");

            assertThat(evidence.text()).isEqualTo("abc");
            assertThat(evidence.digest().sha256()).isEqualTo(ABC_SHA256);
        }

        @Test
        void unreadableEvidenceIsAnError(@TempDir Path dir) {
            assertThatThrownBy(
                    () -> Evidence.read(dir.resolve("absent.asc"), Evidence.SOURCE_SIDECAR))
                    .isInstanceOf(ToolExecutionException.class);
        }
    }

    @Nested
    class Referencing {

        @Test
        void carriesItsDigestAndSourceIntoTheReference(@TempDir Path dir) throws IOException {
            Evidence evidence = Evidence.read(
                    Files.writeString(dir.resolve("x.asc"), "abc"), Evidence.SOURCE_SIDECAR);

            EvidenceRef ref = evidence.ref();

            assertThat(ref.file()).isEqualTo(evidence.file());
            assertThat(ref.digest()).isEqualTo(evidence.digest());
            assertThat(ref.source()).isEqualTo(Evidence.SOURCE_SIDECAR);
        }

        @Test
        void aSourceOtherThanSidecarIsCarriedThrough(@TempDir Path dir) throws IOException {
            Evidence evidence = Evidence.read(
                    Files.writeString(dir.resolve("x.asc"), "abc"), "internal-store");

            assertThat(evidence.ref().source()).isEqualTo("internal-store");
        }

        @Test
        void evidenceWithoutASourceIsRejected(@TempDir Path dir) throws IOException {
            Path file = Files.writeString(dir.resolve("x.asc"), "abc");

            assertThatThrownBy(() -> Evidence.read(file, " "))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }
}
