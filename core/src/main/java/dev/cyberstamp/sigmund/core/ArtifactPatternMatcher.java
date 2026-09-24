package dev.cyberstamp.sigmund.core;

/**
 * Selects the policy target that applies to an artifact when several match.
 *
 * <p>
 * The most specific pattern wins, so a rule for {@code org.example:lib} takes precedence
 * over one for {@code org.example.*} and a versioned rule over an unversioned one. One
 * pattern applies and nothing is merged across patterns, so the rule a result names fully
 * explains that result.
 *
 * @see ArtifactPattern#specificity()
 */
final class ArtifactPatternMatcher {

    private ArtifactPatternMatcher() {
    }

    /**
     * Finds the most specific pattern that applies to an artifact.
     *
     * @param coords the artifact's coordinate
     * @param patterns the parsed patterns to choose from
     * @return the most specific matching pattern, or {@code null} when none applies
     */
    public static ArtifactPattern findBestMatch(
            ArtifactCoords coords, Iterable<ArtifactPattern> patterns) {
        ArtifactPattern best = null;
        int bestSpecificity = -1;
        for (ArtifactPattern pattern : patterns) {
            if (!pattern.matches(coords)) {
                continue;
            }
            int specificity = pattern.specificity();
            if (specificity > bestSpecificity) {
                bestSpecificity = specificity;
                best = pattern;
            }
        }
        return best;
    }
}
