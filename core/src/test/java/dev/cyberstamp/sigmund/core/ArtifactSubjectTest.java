package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ArtifactSubjectTest {

    private static final ArtifactCoords COORDS = new ArtifactCoords("org.example", "lib", "", "jar", "1.0");

    /** SHA-256 of the string {@code abc}. */
    private static final String ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    @Nested
    class Construction {

        @Test
        void carriesCoordinatesAndDigest() {
            ArtifactSubject subject = new ArtifactSubject(COORDS, DigestSet.sha256(ABC_SHA256));
            assertThat(subject.coords()).isEqualTo(COORDS);
            assertThat(subject.digests().sha256()).isEqualTo(ABC_SHA256);
        }

        @Test
        void digestIsRequired() {
            assertThatThrownBy(() -> new ArtifactSubject(COORDS, new DigestSet(java.util.Map.of())))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void coordinatesAreRequired() {
            assertThatThrownBy(() -> new ArtifactSubject(null, DigestSet.sha256(ABC_SHA256)))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    class FromFile {

        @Test
        void computesSha256OverTheFileBytes(@TempDir Path dir) throws IOException {
            Path file = Files.writeString(dir.resolve("lib.jar"), "abc");
            ArtifactSubject subject = ArtifactSubject.of(COORDS, file);
            assertThat(subject.digests().sha256()).isEqualTo(ABC_SHA256);
            assertThat(subject.coords()).isEqualTo(COORDS);
        }
    }

    @Nested
    class Identity {

        @Test
        void sameCoordinatesWithDifferentBytesAreDifferentSubjects() {
            ArtifactSubject one = new ArtifactSubject(COORDS, DigestSet.sha256(ABC_SHA256));
            ArtifactSubject other = new ArtifactSubject(COORDS, DigestSet.sha256(
                    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));
            assertThat(one).isNotEqualTo(other);
        }

        @Test
        void purlComesFromTheCoordinates() {
            ArtifactSubject subject = new ArtifactSubject(COORDS, DigestSet.sha256(ABC_SHA256));
            assertThat(subject.purl()).isEqualTo("pkg:maven/org.example/lib@1.0");
        }
    }
}
