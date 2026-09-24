package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class ArtifactPatternTest {

    private static ArtifactCoords coords(String namespace, String name, String version) {
        return new ArtifactCoords(namespace, name, "", "jar", version);
    }

    @Nested
    class Parsing {

        @Test
        void namespaceOnly() {
            assertThat(ArtifactPattern.parse("org.example").toString()).isEqualTo("org.example");
        }

        @Test
        void namespaceAndName() {
            assertThat(ArtifactPattern.parse("org.example:lib").toString())
                    .isEqualTo("org.example:lib");
        }

        @Test
        void namespaceNameAndVersion() {
            assertThat(ArtifactPattern.parse("org.example:lib:1.0").toString())
                    .isEqualTo("org.example:lib:1.0");
        }

        @Test
        void classifierScopedPatternIsRejected() {
            assertThatThrownBy(() -> ArtifactPattern.parse("org.example:lib:jar:sources"))
                    .isInstanceOf(PolicyConfigException.class)
                    .hasMessageContaining("group, artifact and version");
        }

        @Test
        void blankPatternIsRejected() {
            assertThatThrownBy(() -> ArtifactPattern.parse(" "))
                    .isInstanceOf(PolicyConfigException.class);
        }
    }

    @Nested
    class ForModule {

        @Test
        void dropsVersionClassifierAndExtension() {
            ArtifactCoords sources = new ArtifactCoords("org.example", "lib", "sources", "jar", "1.0");
            assertThat(ArtifactPattern.forModule(sources).toString())
                    .isEqualTo("org.example:lib");
        }

        @Test
        void matchesEveryFileOfThatModule() {
            ArtifactCoords jar = new ArtifactCoords("org.example", "lib", "", "jar", "1.0");
            ArtifactPattern pattern = ArtifactPattern.forModule(jar);
            assertThat(pattern.matches(jar)).isTrue();
            assertThat(pattern.matches(
                    new ArtifactCoords("org.example", "lib", "", "pom", "2.0"))).isTrue();
            assertThat(pattern.matches(
                    new ArtifactCoords("org.example", "other", "", "jar", "1.0"))).isFalse();
        }
    }

    @Nested
    class Matching {

        @Test
        void exactNamespaceMatchesAnyArtifactInIt() {
            ArtifactPattern pattern = ArtifactPattern.parse("org.example");
            assertThat(pattern.matches(coords("org.example", "lib", "1.0"))).isTrue();
            assertThat(pattern.matches(coords("org.other", "lib", "1.0"))).isFalse();
        }

        @Test
        void namespacePrefixWildcardMatchesSubNamespaces() {
            ArtifactPattern pattern = ArtifactPattern.parse("org.example.*");
            assertThat(pattern.matches(coords("org.example", "lib", "1.0"))).isTrue();
            assertThat(pattern.matches(coords("org.example.sub", "lib", "1.0"))).isTrue();
            assertThat(pattern.matches(coords("org.examplefoo", "lib", "1.0"))).isFalse();
        }

        @Test
        void nameWildcardMatchesAnyName() {
            ArtifactPattern pattern = ArtifactPattern.parse("org.example:*");
            assertThat(pattern.matches(coords("org.example", "anything", "1.0"))).isTrue();
        }

        @Test
        void versionIsMatchedWhenGiven() {
            ArtifactPattern pattern = ArtifactPattern.parse("org.example:lib:1.0");
            assertThat(pattern.matches(coords("org.example", "lib", "1.0"))).isTrue();
            assertThat(pattern.matches(coords("org.example", "lib", "2.0"))).isFalse();
        }

        @Test
        void classifierAndExtensionAreIgnored() {
            ArtifactPattern pattern = ArtifactPattern.parse("org.example:lib");
            ArtifactCoords sources = new ArtifactCoords("org.example", "lib", "sources", "jar", "1.0");
            ArtifactCoords pom = new ArtifactCoords("org.example", "lib", "", "pom", "1.0");
            assertThat(pattern.matches(sources)).isTrue();
            assertThat(pattern.matches(pom)).isTrue();
        }
    }

    @Nested
    class Specificity {

        @Test
        void longerNamespaceWinsOverShorter() {
            assertThat(ArtifactPattern.parse("org.example.sub").specificity())
                    .isGreaterThan(ArtifactPattern.parse("org.example").specificity());
        }

        @Test
        void exactNamespaceWinsOverPrefixWildcard() {
            assertThat(ArtifactPattern.parse("org.example").specificity())
                    .isGreaterThan(ArtifactPattern.parse("org.example.*").specificity());
        }

        @Test
        void namedArtifactWinsOverNameWildcard() {
            assertThat(ArtifactPattern.parse("org.example:lib").specificity())
                    .isGreaterThan(ArtifactPattern.parse("org.example:*").specificity());
        }

        @Test
        void versionedPatternWinsOverUnversioned() {
            assertThat(ArtifactPattern.parse("org.example:lib:1.0").specificity())
                    .isGreaterThan(ArtifactPattern.parse("org.example:lib").specificity());
        }

        @Test
        void catchAllIsLeastSpecific() {
            assertThat(ArtifactPattern.parse("*").specificity()).isZero();
        }
    }
}
