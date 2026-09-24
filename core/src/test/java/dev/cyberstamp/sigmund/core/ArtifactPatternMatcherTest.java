package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class ArtifactPatternMatcherTest {

    private static ArtifactCoords coords(String namespace, String name, String version) {
        return new ArtifactCoords(namespace, name, "", "jar", version);
    }

    private static List<ArtifactPattern> patterns(String... patterns) {
        return List.of(patterns).stream().map(ArtifactPattern::parse).toList();
    }

    @Nested
    class FindBestMatch {

        @Test
        void returnsNullWhenNothingMatches() {
            assertThat(ArtifactPatternMatcher.findBestMatch(
                    coords("org.example", "lib", "1.0"), patterns("com.other")))
                    .isNull();
        }

        @Test
        void returnsTheOnlyMatch() {
            assertThat(ArtifactPatternMatcher.findBestMatch(
                    coords("org.example", "lib", "1.0"), patterns("org.example")))
                    .isEqualTo(ArtifactPattern.parse("org.example"));
        }

        @Test
        void exactArtifactBeatsGroupWildcard() {
            assertThat(ArtifactPatternMatcher.findBestMatch(
                    coords("org.example", "lib", "1.0"),
                    patterns("org.example.*", "org.example:lib")))
                    .isEqualTo(ArtifactPattern.parse("org.example:lib"));
        }

        @Test
        void versionedPatternBeatsUnversioned() {
            assertThat(ArtifactPatternMatcher.findBestMatch(
                    coords("org.example", "lib", "1.0"),
                    patterns("org.example:lib", "org.example:lib:1.0")))
                    .isEqualTo(ArtifactPattern.parse("org.example:lib:1.0"));
        }

        @Test
        void deeperNamespaceBeatsShallower() {
            assertThat(ArtifactPatternMatcher.findBestMatch(
                    coords("org.example.sub", "lib", "1.0"),
                    patterns("org.example.*", "org.example.sub")))
                    .isEqualTo(ArtifactPattern.parse("org.example.sub"));
        }

        @Test
        void catchAllAppliesWhenNothingElseMatches() {
            assertThat(ArtifactPatternMatcher.findBestMatch(
                    coords("com.other", "lib", "1.0"), patterns("*", "org.example")))
                    .isEqualTo(ArtifactPattern.parse("*"));
        }

        @Test
        void classifiedArtifactsMatchTheirModulePattern() {
            ArtifactCoords sources = new ArtifactCoords("org.example", "lib", "sources", "jar", "1.0");
            assertThat(ArtifactPatternMatcher.findBestMatch(sources, patterns("org.example:lib")))
                    .isEqualTo(ArtifactPattern.parse("org.example:lib"));
        }
    }
}
