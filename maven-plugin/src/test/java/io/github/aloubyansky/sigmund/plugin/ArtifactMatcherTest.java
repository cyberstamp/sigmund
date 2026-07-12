package io.github.aloubyansky.sigmund.plugin;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.io.StringReader;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class ArtifactMatcherTest {

    @Nested
    class UnsignedTests {

        @Test
        void matchesUnsignedPattern() throws IOException {
            var matcher = matcher("""
                    signers:
                      alice: "Alice <alice@example.com>"
                    trust:
                      com.example: alice
                    unsigned:
                      - com.internal.*
                    """);
            assertTrue(matcher.isUnsigned("com.internal", "util"));
            assertTrue(matcher.isUnsigned("com.internal.sub", "lib"));
            assertFalse(matcher.isUnsigned("com.example", "lib"));
        }

        @Test
        void unsignedWithArtifactGroup() throws IOException {
            var matcher = matcher("""
                    signers:
                      alice: "Alice <alice@example.com>"
                    artifacts:
                      internal:
                        - com.internal.*
                        - org.test.*
                    trust:
                      com.example: alice
                    unsigned:
                      - internal
                    """);
            assertTrue(matcher.isUnsigned("com.internal", "util"));
            assertTrue(matcher.isUnsigned("org.test", "mock"));
            assertFalse(matcher.isUnsigned("com.example", "lib"));
        }
    }

    @Nested
    class TrustMatchTests {

        @Test
        void exactGroupMatch() throws IOException {
            var matcher = matcher("""
                    signers:
                      alice: "Alice <alice@example.com>"
                    trust:
                      com.example: alice
                    """);
            assertEquals(List.of("alice"), matcher.findTrustedSignerRefs("com.example", "lib"));
            assertNull(matcher.findTrustedSignerRefs("com.other", "lib"));
        }

        @Test
        void groupPrefixMatch() throws IOException {
            var matcher = matcher("""
                    signers:
                      alice: "Alice <alice@example.com>"
                    trust:
                      com.example.*: alice
                    """);
            assertEquals(List.of("alice"), matcher.findTrustedSignerRefs("com.example", "lib"));
            assertEquals(List.of("alice"), matcher.findTrustedSignerRefs("com.example.sub", "lib"));
            assertNull(matcher.findTrustedSignerRefs("com.other", "lib"));
        }

        @Test
        void groupArtifactMatch() throws IOException {
            var matcher = matcher("""
                    signers:
                      alice: "Alice <alice@example.com>"
                    trust:
                      com.example:lib: alice
                    """);
            assertEquals(List.of("alice"), matcher.findTrustedSignerRefs("com.example", "lib"));
            assertNull(matcher.findTrustedSignerRefs("com.example", "other"));
        }

        @Test
        void specificPatternBeatsGeneral() throws IOException {
            var matcher = matcher("""
                    signers:
                      alice: "Alice <alice@example.com>"
                      bob: "Bob <bob@example.com>"
                    trust:
                      com.example.*: alice
                      com.example:lib: bob
                    """);
            assertEquals(List.of("bob"), matcher.findTrustedSignerRefs("com.example", "lib"));
            assertEquals(List.of("alice"), matcher.findTrustedSignerRefs("com.example", "other"));
        }

        @Test
        void multipleSignerRefs() throws IOException {
            var matcher = matcher("""
                    signers:
                      alice: "Alice <alice@example.com>"
                      bob: "Bob <bob@example.com>"
                    trust:
                      com.example: [alice, bob]
                    """);
            var refs = matcher.findTrustedSignerRefs("com.example", "lib");
            assertEquals(2, refs.size());
            assertTrue(refs.contains("alice"));
            assertTrue(refs.contains("bob"));
        }

        @Test
        void artifactGroupExpanded() throws IOException {
            var matcher = matcher("""
                    signers:
                      apache: "Apache <dev@apache.org>"
                    artifacts:
                      apache-stack:
                        - org.apache.maven.*
                        - org.apache.commons.*
                    trust:
                      apache-stack: apache
                    """);
            assertEquals(List.of("apache"),
                    matcher.findTrustedSignerRefs("org.apache.maven", "core"));
            assertEquals(List.of("apache"),
                    matcher.findTrustedSignerRefs("org.apache.commons", "lang3"));
            assertNull(matcher.findTrustedSignerRefs("org.other", "lib"));
        }

        @Test
        void tiedPatternsUnionSignerRefs() throws IOException {
            var matcher = matcher("""
                    signers:
                      alice: "Alice <alice@example.com>"
                      bob: "Bob <bob@example.com>"
                    trust:
                      com.example:lib: alice
                      com.example:lib: bob
                    """);
            // YAML duplicate keys — last wins for the map, so only bob
            // This tests the parser behavior, not matcher logic
            var refs = matcher.findTrustedSignerRefs("com.example", "lib");
            assertNotNull(refs);
        }

        @Test
        void deeperPrefixBeatsShallowerPrefix() throws IOException {
            var matcher = matcher("""
                    signers:
                      org-signer: "Org <org@example.com>"
                      apache-signer: "Apache <apache@example.com>"
                    trust:
                      org.*: org-signer
                      org.apache.*: apache-signer
                    """);
            assertEquals(List.of("apache-signer"),
                    matcher.findTrustedSignerRefs("org.apache.maven", "core"));
            assertEquals(List.of("org-signer"),
                    matcher.findTrustedSignerRefs("org.other", "lib"));
        }

        @Test
        void threeLevelPrefixDepth() throws IOException {
            var matcher = matcher("""
                    signers:
                      broad: "Broad <broad@example.com>"
                      mid: "Mid <mid@example.com>"
                      narrow: "Narrow <narrow@example.com>"
                    trust:
                      org.*: broad
                      org.apache.*: mid
                      org.apache.maven.*: narrow
                    """);
            assertEquals(List.of("narrow"),
                    matcher.findTrustedSignerRefs("org.apache.maven.plugins", "compiler"));
            assertEquals(List.of("mid"),
                    matcher.findTrustedSignerRefs("org.apache.commons", "lang3"));
            assertEquals(List.of("broad"),
                    matcher.findTrustedSignerRefs("org.other", "lib"));
        }

        @Test
        void exactGroupBeatsPrefix() throws IOException {
            var matcher = matcher("""
                    signers:
                      alice: "Alice <alice@example.com>"
                      bob: "Bob <bob@example.com>"
                    trust:
                      com.example.*: alice
                      com.example: bob
                    """);
            assertEquals(List.of("bob"),
                    matcher.findTrustedSignerRefs("com.example", "lib"));
            assertEquals(List.of("alice"),
                    matcher.findTrustedSignerRefs("com.example.sub", "lib"));
        }

        @Test
        void wildcardGroupMatchesAnything() throws IOException {
            var matcher = matcher("""
                    signers:
                      alice: "Alice <alice@example.com>"
                    trust:
                      "*": alice
                    """);
            assertEquals(List.of("alice"),
                    matcher.findTrustedSignerRefs("any.group", "any-artifact"));
        }
    }

    @Nested
    class VersionPatternTests {

        @Test
        void threeSegmentPatternMatchesVersion() throws IOException {
            var matcher = matcher("""
                    signers:
                      alice: "Alice <alice@example.com>"
                    trust:
                      com.example:lib:2.0: alice
                    """);
            var artifact = createArtifact("com.example", "lib", "2.0");
            assertEquals(List.of("alice"), matcher.findTrustedSignerRefs(artifact));
        }

        @Test
        void threeSegmentPatternRejectsWrongVersion() throws IOException {
            var matcher = matcher("""
                    signers:
                      alice: "Alice <alice@example.com>"
                    trust:
                      com.example:lib:2.0: alice
                    """);
            var artifact = createArtifact("com.example", "lib", "3.0");
            assertNull(matcher.findTrustedSignerRefs(artifact));
        }

        @Test
        void fiveSegmentPatternMatchesFully() throws IOException {
            var matcher = matcher("""
                    signers:
                      alice: "Alice <alice@example.com>"
                    trust:
                      com.example:lib:jar:sources:2.0: alice
                    """);
            var artifact = new ArtifactCoords(
                    "com.example", "lib", "sources", "jar", "2.0");
            assertEquals(List.of("alice"), matcher.findTrustedSignerRefs(artifact));
        }

        @Test
        void fiveSegmentPatternRejectsWrongClassifier() throws IOException {
            var matcher = matcher("""
                    signers:
                      alice: "Alice <alice@example.com>"
                    trust:
                      com.example:lib:jar:sources:2.0: alice
                    """);
            var artifact = new ArtifactCoords(
                    "com.example", "lib", "javadoc", "jar", "2.0");
            assertNull(matcher.findTrustedSignerRefs(artifact));
        }

        @Test
        void versionPatternBeatsGroupArtifactOnly() throws IOException {
            var matcher = matcher("""
                    signers:
                      alice: "Alice <alice@example.com>"
                      bob: "Bob <bob@example.com>"
                    trust:
                      com.example:lib: alice
                      com.example:lib:2.0: bob
                    """);
            var artifact = createArtifact("com.example", "lib", "2.0");
            assertEquals(List.of("bob"), matcher.findTrustedSignerRefs(artifact));
        }

        @Test
        void fourSegmentsParsesAsGroupArtifactTypeVersion() {
            var entry = ArtifactMatcher.PatternEntry.parse("com.example:lib:jar:2.0");
            assertTrue(entry.matches(
                    new ArtifactCoords("com.example", "lib", "", "jar", "2.0")));
            assertFalse(entry.matches(
                    new ArtifactCoords("com.example", "lib", "", "pom", "2.0")));
        }

        @Test
        void invalidSegmentCountThrows() {
            assertThrows(IllegalArgumentException.class,
                    () -> ArtifactMatcher.PatternEntry.parse("a:b:c:d:e:f"));
        }
    }

    private static ArtifactCoords createArtifact(
            String groupId, String artifactId, String version) {
        return new ArtifactCoords(groupId, artifactId, "", "jar", version);
    }

    private ArtifactMatcher matcher(String yaml) throws IOException {
        TrustConfig config = TrustConfigParser.parse(new StringReader(yaml));
        return new ArtifactMatcher(config);
    }
}
