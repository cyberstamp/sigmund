package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class ArtifactCoordsTest {

    @Nested
    class Parsing {

        @Test
        void groupArtifactVersion() {
            assertThat(ArtifactCoords.parse("org.example:lib:1.0"))
                    .isEqualTo(new ArtifactCoords("org.example", "lib", "", "jar", "1.0"));
        }

        @Test
        void groupArtifactExtensionVersion() {
            assertThat(ArtifactCoords.parse("org.example:lib:pom:1.0"))
                    .isEqualTo(new ArtifactCoords("org.example", "lib", "", "pom", "1.0"));
        }

        @Test
        void groupArtifactExtensionClassifierVersion() {
            assertThat(ArtifactCoords.parse("org.example:lib:jar:sources:1.0"))
                    .isEqualTo(new ArtifactCoords("org.example", "lib", "sources", "jar", "1.0"));
        }

        @Test
        void roundTripsThroughToString() {
            ArtifactCoords coords = new ArtifactCoords("org.example", "lib", "linux-x86_64", "so", "1.0");
            assertThat(ArtifactCoords.parse(coords.toString())).isEqualTo(coords);
        }

        @Test
        void coordinateWithoutVersionIsRejected() {
            assertThatThrownBy(() -> ArtifactCoords.parse("org.example:lib"))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    class Normalization {

        @Test
        void missingClassifierBecomesEmpty() {
            assertThat(new ArtifactCoords("org.example", "lib", null, "jar", "1.0").classifier())
                    .isEmpty();
        }

        @Test
        void missingExtensionDefaultsToJar() {
            assertThat(new ArtifactCoords("org.example", "lib", "", null, "1.0").extension())
                    .isEqualTo("jar");
        }

        @Test
        void blankNamespaceIsRejected() {
            assertThatThrownBy(() -> new ArtifactCoords(" ", "lib", "", "jar", "1.0"))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void blankVersionIsRejected() {
            assertThatThrownBy(() -> new ArtifactCoords("org.example", "lib", "", "jar", " "))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    class Ordering {

        @Test
        void sortsByNamespaceThenNameThenVersion() {
            ArtifactCoords a = new ArtifactCoords("org.a", "lib", "", "jar", "1.0");
            ArtifactCoords b = new ArtifactCoords("org.b", "alib", "", "jar", "1.0");
            ArtifactCoords c = new ArtifactCoords("org.b", "blib", "", "jar", "1.0");
            assertThat(List.of(c, b, a).stream().sorted().toList()).containsExactly(a, b, c);
        }
    }

    @Nested
    class PurlProjection {

        @Test
        void plainJarOmitsQualifiers() {
            assertThat(new ArtifactCoords("org.example", "lib", "", "jar", "1.0").purl())
                    .isEqualTo("pkg:maven/org.example/lib@1.0");
        }

        @Test
        void qualifiersAreSortedAlphabetically() {
            assertThat(new ArtifactCoords("org.example", "lib", "linux-x86_64", "so", "1.0").purl())
                    .isEqualTo("pkg:maven/org.example/lib@1.0?classifier=linux-x86_64&type=so");
        }
    }
}
