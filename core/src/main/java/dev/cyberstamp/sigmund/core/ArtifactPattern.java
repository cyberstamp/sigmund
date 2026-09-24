package dev.cyberstamp.sigmund.core;

import java.util.Objects;

/**
 * A parsed policy target: the coordinate pattern a rule matches artifacts against.
 *
 * <p>
 * Patterns are written as {@code group}, {@code group:artifact} or
 * {@code group:artifact:version}, where an omitted component matches anything. A component
 * may be {@code *} to match anything explicitly, and a group may end in {@code .*} to match
 * a namespace and everything below it.
 *
 * <p>
 * Patterns stop at the version. Classifier and extension are deliberately not policy
 * dimensions: every file published under one coordinate — jar, pom, sources, javadoc —
 * comes from the same module build and shares its signer, so a rule that accepted a
 * classifier would suggest a distinction the trust model does not make. A pattern carrying
 * more than three components is a configuration error rather than a pattern that silently
 * matches nothing.
 *
 * <p>
 * Parsing happens once, when policy is loaded, so that malformed patterns surface as
 * configuration errors at load time instead of as silent mismatches during a build, and so
 * that matching an artifact costs no string splitting.
 */
public final class ArtifactPattern {

    private static final String ANY = "*";
    private static final String PREFIX_WILDCARD = ".*";

    private final String namespace;
    private final String name;
    private final String version;
    private final String text;

    private ArtifactPattern(String namespace, String name, String version, String text) {
        this.namespace = namespace;
        this.name = name;
        this.version = version;
        this.text = text;
    }

    /**
     * Parses a coordinate pattern.
     *
     * @param pattern the pattern text, one to three colon-separated components
     * @return the parsed pattern
     * @throws PolicyConfigException if the pattern is blank or carries more components than
     *         group, artifact and version
     */
    public static ArtifactPattern parse(String pattern) {
        if (pattern == null || pattern.isBlank()) {
            throw new PolicyConfigException("Artifact pattern must not be blank");
        }
        String text = pattern.trim();
        String[] parts = text.split(":", -1);
        return switch (parts.length) {
            case 1 -> new ArtifactPattern(parts[0], ANY, ANY, text);
            case 2 -> new ArtifactPattern(parts[0], parts[1], ANY, text);
            case 3 -> new ArtifactPattern(parts[0], parts[1], parts[2], text);
            default -> throw new PolicyConfigException(
                    "Artifact pattern '" + text + "' matches on group, artifact and version only;"
                            + " classifier and extension are not policy dimensions");
        };
    }

    /**
     * Builds the pattern covering every file published under an artifact's module.
     *
     * <p>
     * Version, classifier and extension are dropped, so the pattern matches the module's
     * jar, pom, sources and javadoc alike, and every version of them. This is the shape
     * bootstrap generates when it turns observed signers into policy: trust is stated per
     * module, not per released file.
     *
     * @param coords the artifact whose module should be covered
     * @return a pattern matching {@code group:artifact}
     */
    public static ArtifactPattern forModule(ArtifactCoords coords) {
        return new ArtifactPattern(coords.namespace(), coords.name(), ANY,
                coords.namespace() + ":" + coords.name());
    }

    /**
     * Indicates whether this pattern applies to an artifact.
     *
     * <p>
     * Only the group, artifact and version are considered. Classifier and extension are
     * ignored, so a rule written for a module covers every file published under it.
     *
     * @param coords the artifact's coordinate
     * @return {@code true} when the pattern applies
     */
    public boolean matches(ArtifactCoords coords) {
        return coords != null
                && matchesNamespace(coords.namespace())
                && matchesComponent(name, coords.name())
                && matchesComponent(version, coords.version());
    }

    /**
     * Scores how specific this pattern is, so that the most specific rule wins when several
     * apply.
     *
     * <p>
     * The group dominates: it scores ten per namespace segment, with an exact group
     * outranking the prefix wildcard that contains it. Artifact and version add two for an
     * exact match and one for a prefix wildcard, so a named artifact outranks a wildcard
     * within the same group and a versioned rule outranks an unversioned one. A pattern
     * that matches everything scores zero.
     *
     * @return the specificity score, never negative
     */
    public int specificity() {
        return namespaceSpecificity() + componentSpecificity(name) + componentSpecificity(version);
    }

    private boolean matchesNamespace(String value) {
        if (ANY.equals(namespace)) {
            return true;
        }
        if (namespace.endsWith(PREFIX_WILDCARD)) {
            String prefix = namespace.substring(0, namespace.length() - PREFIX_WILDCARD.length());
            return value.equals(prefix) || value.startsWith(prefix + ".");
        }
        return namespace.equals(value);
    }

    private static boolean matchesComponent(String pattern, String value) {
        if (ANY.equals(pattern)) {
            return true;
        }
        if (pattern.equals(value)) {
            return true;
        }
        if (pattern.endsWith(PREFIX_WILDCARD)) {
            return value.startsWith(
                    pattern.substring(0, pattern.length() - PREFIX_WILDCARD.length()));
        }
        if (pattern.endsWith(ANY)) {
            return value.startsWith(pattern.substring(0, pattern.length() - 1));
        }
        return false;
    }

    private int namespaceSpecificity() {
        if (ANY.equals(namespace)) {
            return 0;
        }
        if (namespace.endsWith(PREFIX_WILDCARD)) {
            String prefix = namespace.substring(0, namespace.length() - PREFIX_WILDCARD.length());
            return countSegments(prefix) * 10;
        }
        return (countSegments(namespace) + 1) * 10;
    }

    private static int componentSpecificity(String pattern) {
        if (ANY.equals(pattern)) {
            return 0;
        }
        return pattern.endsWith(ANY) ? 1 : 2;
    }

    private static int countSegments(String value) {
        int count = 1;
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) == '.') {
                count++;
            }
        }
        return count;
    }

    /**
     * Returns the pattern as it was written in the policy, so reports and errors quote the
     * user's own text.
     *
     * @return the original pattern text
     */
    @Override
    public String toString() {
        return text;
    }

    /**
     * Compares patterns by what they match, ignoring how they were written.
     *
     * @param o the object to compare with
     * @return {@code true} when both patterns match the same coordinates
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        return o instanceof ArtifactPattern other
                && namespace.equals(other.namespace)
                && name.equals(other.name)
                && version.equals(other.version);
    }

    @Override
    public int hashCode() {
        return Objects.hash(namespace, name, version);
    }
}
