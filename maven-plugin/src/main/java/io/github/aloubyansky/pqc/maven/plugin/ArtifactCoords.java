package io.github.aloubyansky.pqc.maven.plugin;

public record ArtifactCoords(
        String groupId,
        String artifactId,
        String classifier,
        String type,
        String version) implements Comparable<ArtifactCoords> {

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(groupId).append(':').append(artifactId);
        boolean hasClassifier = classifier != null && !classifier.isEmpty();
        if (hasClassifier || (type != null && !"jar".equals(type))) {
            sb.append(':').append(type != null ? type : "jar");
        }
        if (hasClassifier) {
            sb.append(':').append(classifier);
        }
        sb.append(':').append(version);
        return sb.toString();
    }

    @Override
    public int compareTo(ArtifactCoords other) {
        int c = groupId.compareTo(other.groupId);
        if (c != 0) {
            return c;
        }
        c = artifactId.compareTo(other.artifactId);
        if (c != 0) {
            return c;
        }
        c = version.compareTo(other.version);
        if (c != 0) {
            return c;
        }
        c = compareNullable(type, other.type);
        if (c != 0) {
            return c;
        }
        return compareNullable(classifier, other.classifier);
    }

    private static int compareNullable(String a, String b) {
        if (a == null && b == null) {
            return 0;
        }
        if (a == null) {
            return -1;
        }
        if (b == null) {
            return 1;
        }
        return a.compareTo(b);
    }
}
