package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * Every Sigmund version the documentation names is the same released version.
 *
 * <p>
 * The docs tell readers which version to put in their build: the plugin's coordinates, the
 * {@code sigmund-sigstore} dependency that must match the plugin, the {@code sigmund.version}
 * property that keeps the two in step, and the README's project status. {@code release:prepare}
 * updates them all through the {@code update-docs-version} profile of the root {@code pom.xml}; a
 * reference that profile does not reach would be left behind and have a reader pair modules of
 * different versions, so it fails here.
 */
class DocumentedVersionTest {

    private static final Path REPOSITORY = Path.of("..");
    private static final List<Pattern> VERSION_REFERENCES = List.of(
            Pattern.compile("sigmund-maven-plugin:([^:\\s]+):"),
            Pattern.compile("<sigmund\\.version>([^<]+)</sigmund\\.version>"),
            Pattern.compile("<artifactId>sigmund-[\\w-]+</artifactId>\\s*<version>([^<$]+)</version>"),
            Pattern.compile("\\*\\*Version:\\*\\* *(\\S+)"));

    @Test
    void everyDocumentedSigmundVersionIsTheSameRelease() throws IOException {
        Map<String, List<String>> locationsByVersion = new TreeMap<>();
        for (Path file : documentationFiles()) {
            String text = Files.readString(file);
            for (Pattern reference : VERSION_REFERENCES) {
                Matcher version = reference.matcher(text);
                while (version.find()) {
                    locationsByVersion.computeIfAbsent(version.group(1), v -> new ArrayList<>())
                            .add(REPOSITORY.relativize(file) + ":" + lineOf(text, version.start()));
                }
            }
        }

        assertThat(locationsByVersion).as("documented Sigmund versions").hasSize(1);
        assertThat(locationsByVersion.keySet().iterator().next())
                .as("the documented version is a release").doesNotEndWith("-SNAPSHOT");
    }

    private static List<Path> documentationFiles() throws IOException {
        List<Path> files = new ArrayList<>();
        try (Stream<Path> docs = Files.list(REPOSITORY.resolve("docs"))) {
            docs.filter(path -> path.toString().endsWith(".md")).sorted().forEach(files::add);
        }
        files.add(REPOSITORY.resolve("README.md"));
        return files;
    }

    private static int lineOf(String text, int offset) {
        return (int) text.substring(0, offset).chars().filter(c -> c == '\n').count() + 1;
    }
}
