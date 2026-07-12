package io.github.aloubyansky.sigmund.plugin;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class VerifyMojoTest {

    @Nested
    class PomVerificationTests {

        private ArtifactCoords jarArtifact(String groupId, String artifactId, String version) {
            return new ArtifactCoords(groupId, artifactId, "", "jar", version);
        }

        @Test
        void addPomArtifactsCreatesPomForEachJar() {
            var mojo = new VerifyMojo();
            List<ArtifactCoords> artifacts = new ArrayList<>();
            artifacts.add(jarArtifact("com.example", "lib-a", "1.0"));
            artifacts.add(jarArtifact("com.example", "lib-b", "2.0"));

            mojo.addPomArtifacts(artifacts);

            assertEquals(4, artifacts.size());
            ArtifactCoords pomA = artifacts.get(2);
            assertEquals("com.example", pomA.groupId());
            assertEquals("lib-a", pomA.artifactId());
            assertEquals("pom", pomA.type());
            assertEquals("1.0", pomA.version());

            ArtifactCoords pomB = artifacts.get(3);
            assertEquals("lib-b", pomB.artifactId());
            assertEquals("pom", pomB.type());
        }

        @Test
        void addPomArtifactsDeduplicatesSameGav() {
            var mojo = new VerifyMojo();
            List<ArtifactCoords> artifacts = new ArrayList<>();
            artifacts.add(jarArtifact("com.example", "lib", "1.0"));
            artifacts.add(new ArtifactCoords("com.example", "lib", "sources", "jar", "1.0"));

            mojo.addPomArtifacts(artifacts);

            assertEquals(3, artifacts.size());
            assertEquals("pom", artifacts.get(2).type());
        }

        @Test
        void addPomArtifactsSkipsExistingPomArtifacts() {
            var mojo = new VerifyMojo();
            List<ArtifactCoords> artifacts = new ArrayList<>();
            artifacts.add(new ArtifactCoords(
                    "com.example", "parent", "", "pom", "1.0"));

            mojo.addPomArtifacts(artifacts);

            assertEquals(1, artifacts.size());
        }
    }
}
