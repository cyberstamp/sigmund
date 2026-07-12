package io.github.aloubyansky.sigmund.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class ArtifactPatternMatcherTest {

    @Nested
    class FindBestMatch {

        @Test
        void exactNamespace() {
            String match = ArtifactPatternMatcher.findBestMatch(
                    artifact("org.example", "lib", "1.0"),
                    List.of("org.example"));
            assertEquals("org.example", match);
        }

        @Test
        void wildcardName() {
            String match = ArtifactPatternMatcher.findBestMatch(
                    artifact("org.example", "any-lib", "1.0"),
                    List.of("org.example:*"));
            assertEquals("org.example:*", match);
        }

        @Test
        void exactNameAndNamespace() {
            String match = ArtifactPatternMatcher.findBestMatch(
                    artifact("org.example", "lib", "1.0"),
                    List.of("org.example:lib"));
            assertEquals("org.example:lib", match);
            assertNull(ArtifactPatternMatcher.findBestMatch(
                    artifact("org.example", "other", "1.0"),
                    List.of("org.example:lib")));
        }

        @Test
        void threePartPattern() {
            String match = ArtifactPatternMatcher.findBestMatch(
                    artifact("org.example", "lib", "2.0"),
                    List.of("org.example:lib:2.0"));
            assertEquals("org.example:lib:2.0", match);
            assertNull(ArtifactPatternMatcher.findBestMatch(
                    artifact("org.example", "lib", "1.0"),
                    List.of("org.example:lib:2.0")));
        }

        @Test
        void moreSpecificWins() {
            String match = ArtifactPatternMatcher.findBestMatch(
                    artifact("org.example", "special-lib", "1.0"),
                    List.of("org.example:*", "org.example:special-lib"));
            assertEquals("org.example:special-lib", match);
        }

        @Test
        void noMatch() {
            assertNull(ArtifactPatternMatcher.findBestMatch(
                    artifact("com.other", "lib", "1.0"),
                    List.of("org.example:*")));
        }

        @Test
        void namespaceWildcard() {
            String match = ArtifactPatternMatcher.findBestMatch(
                    artifact("org.example.sub", "lib", "1.0"),
                    List.of("org.example.*"));
            assertEquals("org.example.*", match);
            assertNull(ArtifactPatternMatcher.findBestMatch(
                    artifact("org.other", "lib", "1.0"),
                    List.of("org.example.*")));
        }

        @Test
        void unsignedExactMatch() {
            assertEquals("org.example:unsigned-lib",
                    ArtifactPatternMatcher.findBestMatch(
                            artifact("org.example", "unsigned-lib", "1.0"),
                            List.of("org.example:unsigned-lib")));
            assertNull(ArtifactPatternMatcher.findBestMatch(
                    artifact("org.example", "other", "1.0"),
                    List.of("org.example:unsigned-lib")));
        }

        @Test
        void unsignedWildcardMatch() {
            assertEquals("org.test:*",
                    ArtifactPatternMatcher.findBestMatch(
                            artifact("org.test", "anything", "1.0"),
                            List.of("org.test:*")));
        }
    }

    @Nested
    class MatchScore {

        @Test
        void exactNamespaceScoresHigherThanWildcard() {
            var a = artifact("org.example", "lib", "1.0");
            assertTrue(ArtifactPatternMatcher.matchScore(a, "org.example") > ArtifactPatternMatcher.matchScore(a, "org.*"));
        }

        @Test
        void deeperNamespaceScoresHigher() {
            var a = artifact("org.example.sub", "lib", "1.0");
            assertTrue(ArtifactPatternMatcher.matchScore(a, "org.example.sub") > ArtifactPatternMatcher.matchScore(a,
                    "org.example.*"));
        }

        @Test
        void noMatchReturnsNegative() {
            assertEquals(-1, ArtifactPatternMatcher.matchScore(
                    artifact("com.other", "lib", "1.0"), "org.example"));
        }

        @Test
        void fourPartsInvalid() {
            assertEquals(-1, ArtifactPatternMatcher.matchScore(
                    artifact("org", "lib", "1.0"), "a:b:c:d"));
        }
    }

    private static ArtifactIdentity artifact(String ns, String name, String version) {
        return new ArtifactIdentity() {
            @Override
            public String namespace() {
                return ns;
            }

            @Override
            public String name() {
                return name;
            }

            @Override
            public String version() {
                return version;
            }
        };
    }
}
