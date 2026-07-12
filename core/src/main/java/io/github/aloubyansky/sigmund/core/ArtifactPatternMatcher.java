package io.github.aloubyansky.sigmund.core;

/**
 * Matches {@link ArtifactIdentity} instances against colon-separated patterns.
 * <p>
 * Patterns use 1–3 parts: {@code namespace}, {@code namespace:name}, or
 * {@code namespace:name:version}. Wildcards ({@code *}) match any value.
 * Namespace segments support prefix wildcards ({@code org.example.*}).
 * When multiple patterns match, the most specific one wins (exact matches
 * score higher than wildcards, and more segments score higher than fewer).
 */
public final class ArtifactPatternMatcher {

    private ArtifactPatternMatcher() {
    }

    /**
     * Finds the best matching pattern for the given artifact.
     *
     * @param artifact the artifact to match
     * @param patterns the candidate patterns
     * @return the most specific matching pattern, or {@code null} if none match
     */
    public static String findBestMatch(ArtifactIdentity artifact, Iterable<String> patterns) {
        String best = null;
        int bestScore = -1;
        for (String pattern : patterns) {
            int score = matchScore(artifact, pattern);
            if (score > bestScore) {
                bestScore = score;
                best = pattern;
            }
        }
        return best;
    }

    static int matchScore(ArtifactIdentity artifact, String pattern) {
        String[] parts = pattern.split(":", -1);
        return switch (parts.length) {
            case 1 -> scoreSegment(parts[0], artifact.namespace()) >= 0
                    ? scoreNamespace(parts[0], artifact.namespace())
                    : -1;
            case 2 -> scoreTwoParts(parts, artifact);
            case 3 -> scoreThreeParts(parts, artifact);
            default -> -1;
        };
    }

    private static int scoreTwoParts(String[] parts, ArtifactIdentity artifact) {
        int ns = scoreSegment(parts[0], artifact.namespace());
        int name = scoreSegment(parts[1], artifact.name());
        if (ns < 0 || name < 0) {
            return -1;
        }
        return scoreNamespace(parts[0], artifact.namespace()) + name;
    }

    private static int scoreThreeParts(String[] parts, ArtifactIdentity artifact) {
        int ns = scoreSegment(parts[0], artifact.namespace());
        int name = scoreSegment(parts[1], artifact.name());
        int ver = scoreSegment(parts[2], artifact.version());
        if (ns < 0 || name < 0 || ver < 0) {
            return -1;
        }
        return scoreNamespace(parts[0], artifact.namespace()) + name + ver;
    }

    /**
     * Namespace scoring: segment count × 10 to dominate other segments.
     * "com.example" (2 segments) scores 20, "com.example.sub" (3 segments) scores 30.
     */
    private static int scoreNamespace(String pattern, String value) {
        if ("*".equals(pattern)) {
            return 0;
        }
        if (pattern.endsWith(".*")) {
            String prefix = pattern.substring(0, pattern.length() - 2);
            if (value.equals(prefix) || value.startsWith(prefix + ".")) {
                return countSegments(prefix) * 10;
            }
            return -1;
        }
        if (pattern.equals(value)) {
            return (countSegments(pattern) + 1) * 10;
        }
        return -1;
    }

    private static int scoreSegment(String pattern, String value) {
        if ("*".equals(pattern)) {
            return 0;
        }
        if (pattern.equals(value)) {
            return 2;
        }
        if (pattern.endsWith(".*") || pattern.endsWith("*")) {
            String prefix = pattern.endsWith(".*")
                    ? pattern.substring(0, pattern.length() - 2)
                    : pattern.substring(0, pattern.length() - 1);
            if (value.startsWith(prefix)) {
                return 1;
            }
        }
        return -1;
    }

    private static int countSegments(String s) {
        int count = 1;
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '.') {
                count++;
            }
        }
        return count;
    }
}
