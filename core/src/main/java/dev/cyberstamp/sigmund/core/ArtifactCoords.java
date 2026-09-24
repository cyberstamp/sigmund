package dev.cyberstamp.sigmund.core;

import java.util.ArrayList;
import java.util.List;

/**
 * The coordinate of a single file in a Maven repository: group, artifact, version,
 * classifier and extension.
 *
 * <p>
 * A coordinate names a file; it says nothing about the file's content. Anything that
 * identifies content — a verification result, a cache key, an attestation subject — uses
 * {@link ArtifactSubject}, which pairs a coordinate with a digest computed from the bytes.
 * Everything that only needs to name a file — policy matching, reporting, map keys — uses
 * this type.
 *
 * <p>
 * Coordinates are a repository concept, not a build-tool one, so this type carries no
 * Maven or Gradle API. Build-tool integrations map their own coordinate types into it.
 * Repositories address files by extension; Maven's "type" is a build-tool notion that
 * artifact handlers resolve into an extension and a classifier, so the field here is named
 * {@code extension}. The string form keeps Maven's familiar ordering
 * ({@code group:artifact:extension:classifier:version}), because that is what users read
 * and write.
 *
 * <p>
 * This shape is Maven's and is meant to stay that way. Ecosystems share namespace, name
 * and version, but their variant qualifiers do not line up — classifier and extension
 * here, wheel tags on PyPI, architecture for RPM and Debian, nothing at all for npm, Go
 * and NuGet — so a coordinate covering all of them would degenerate into a qualifier map.
 * That map is what purl already is, which is why the portable identity is the
 * {@link #purl()} emitted on output and never a generalization of this record. The
 * component names {@code namespace} and {@code name} are purl's vocabulary rather than
 * Maven's {@code groupId} and {@code artifactId}, so that projection stays a mapping
 * instead of a translation; they are not an invitation to make this type
 * ecosystem-neutral.
 *
 * @param namespace the group id, never blank
 * @param name the artifact id, never blank
 * @param classifier the classifier, empty when the artifact has none
 * @param extension the file extension, {@code jar} when unspecified
 * @param version the resolved version, never blank
 */
public record ArtifactCoords(
        String namespace,
        String name,
        String classifier,
        String extension,
        String version) implements Comparable<ArtifactCoords> {

    static final String DEFAULT_EXTENSION = "jar";

    /**
     * Normalizes the optional components and rejects incomplete coordinates.
     *
     * @throws IllegalArgumentException if the group, artifact or version is blank
     */
    public ArtifactCoords {
        namespace = required(namespace, "namespace");
        name = required(name, "name");
        version = required(version, "version");
        classifier = classifier == null ? "" : classifier.trim();
        extension = extension == null || extension.isBlank()
                ? DEFAULT_EXTENSION
                : extension.trim();
    }

    /**
     * Parses a coordinate string in the form produced by {@link #toString()}:
     * {@code group:artifact:version}, {@code group:artifact:extension:version} or
     * {@code group:artifact:extension:classifier:version}.
     *
     * @param coords the coordinate string
     * @return the parsed coordinates
     * @throws IllegalArgumentException if the string does not carry at least a group,
     *         artifact and version
     */
    public static ArtifactCoords parse(String coords) {
        String[] parts = coords == null ? new String[0] : coords.split(":", -1);
        return switch (parts.length) {
            case 3 -> new ArtifactCoords(parts[0], parts[1], "", DEFAULT_EXTENSION, parts[2]);
            case 4 -> new ArtifactCoords(parts[0], parts[1], "", parts[2], parts[3]);
            case 5 -> new ArtifactCoords(parts[0], parts[1], parts[3], parts[2], parts[4]);
            default -> throw new IllegalArgumentException(
                    "Not a resolved artifact coordinate: " + coords);
        };
    }

    /**
     * Projects this coordinate to a package URL, for attestation output and correlation
     * with purl-keyed data such as SBOM annotations and VEX.
     *
     * <p>
     * The projection is one-way. A purl is computed from a resolved coordinate on output
     * and is never parsed back into one for matching, which keeps the coordinate the single
     * source of identity and stops purl normalization from affecting verdicts. Qualifiers
     * are emitted in alphabetical order and only when they carry information: a classifier
     * when present, and a type when the extension is not {@code jar}.
     *
     * @return the package URL for this artifact
     */
    public String purl() {
        StringBuilder purl = new StringBuilder("pkg:maven/")
                .append(namespace)
                .append('/')
                .append(name)
                .append('@')
                .append(version);
        List<String> qualifiers = qualifiers();
        if (!qualifiers.isEmpty()) {
            purl.append('?').append(String.join("&", qualifiers));
        }
        return purl.toString();
    }

    private List<String> qualifiers() {
        List<String> qualifiers = new ArrayList<>(2);
        if (!classifier.isEmpty()) {
            qualifiers.add("classifier=" + classifier);
        }
        if (!DEFAULT_EXTENSION.equals(extension)) {
            qualifiers.add("type=" + extension);
        }
        return qualifiers;
    }

    /**
     * Renders the coordinate in Maven's familiar string form, omitting components that
     * carry no information.
     *
     * @return {@code group:artifact[:extension[:classifier]]:version}
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(namespace).append(':').append(name);
        boolean hasClassifier = !classifier.isEmpty();
        if (hasClassifier || !DEFAULT_EXTENSION.equals(extension)) {
            sb.append(':').append(extension);
        }
        if (hasClassifier) {
            sb.append(':').append(classifier);
        }
        sb.append(':').append(version);
        return sb.toString();
    }

    /**
     * Orders coordinates by group, artifact, version, extension and classifier, so that
     * reports group the files of one module together.
     *
     * @param other the coordinate to compare against
     * @return the comparison result
     */
    @Override
    public int compareTo(ArtifactCoords other) {
        int c = namespace.compareTo(other.namespace);
        if (c != 0) {
            return c;
        }
        c = name.compareTo(other.name);
        if (c != 0) {
            return c;
        }
        c = version.compareTo(other.version);
        if (c != 0) {
            return c;
        }
        c = extension.compareTo(other.extension);
        if (c != 0) {
            return c;
        }
        return classifier.compareTo(other.classifier);
    }

    private static String required(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be null or blank");
        }
        return value.trim();
    }
}
