package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.nio.file.FileSystemException;
import java.nio.file.FileSystemLoopException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
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
        void unreadableEvidenceIsAnErrorCarryingTheRecordOfIt(@TempDir Path dir) {
            Path absent = dir.resolve("absent.asc");

            assertThatThrownBy(() -> Evidence.read(absent, Evidence.SOURCE_SIDECAR))
                    .isInstanceOfSatisfying(UnreadableEvidenceException.class, e -> assertThat(e.evidence())
                            .isEqualTo(EvidenceWithoutClaims.unreadable(absent, Evidence.SOURCE_SIDECAR, "no such file")));
        }

        @Test
        void evidenceThatIsNotAFileIsUnreadableWithTheFileSystemsWords(@TempDir Path dir) throws IOException {
            Path directory = Files.createDirectory(dir.resolve("lib.jar.asc"));

            assertThatThrownBy(() -> Evidence.read(directory, Evidence.SOURCE_SIDECAR))
                    .isInstanceOfSatisfying(UnreadableEvidenceException.class,
                            e -> assertThat(e.evidence().message()).isNotBlank());
        }
    }

    /** The reason shown after an unreadable file's path, which must never be the path again. */
    @Nested
    class WhyAFileCouldNotBeRead {

        @Test
        void aPermissionItLacksIsNamed() {
            assertThat(Evidence.messageOf(new AccessDeniedException("repo/lib.jar.asc"))).isEqualTo("permission denied");
        }

        @Test
        void aMissingFileIsNamed() {
            assertThat(Evidence.messageOf(new NoSuchFileException("repo/lib.jar.asc"))).isEqualTo("no such file");
        }

        @Test
        void theFileSystemsOwnReasonIsKept() {
            assertThat(Evidence.messageOf(new FileSystemException("repo/lib.jar.asc", null, "Input/output error")))
                    .isEqualTo("Input/output error");
        }

        @Test
        void anotherFileSystemFailureIsNamedByItsKind() {
            assertThat(Evidence.messageOf(new FileSystemLoopException("repo/lib.jar.asc")))
                    .isEqualTo("FileSystemLoopException");
        }

        @Test
        void anyOtherErrorKeepsItsMessage() {
            assertThat(Evidence.messageOf(new IOException("Is a directory"))).isEqualTo("Is a directory");
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
