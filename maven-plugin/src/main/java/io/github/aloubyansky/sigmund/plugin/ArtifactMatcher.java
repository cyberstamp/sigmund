package io.github.aloubyansky.sigmund.plugin;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Matches Maven artifacts against a {@link TrustConfig}, resolving artifact group
 * references and applying specificity-based pattern matching.
 * <p>
 * Keys in the {@code trust} and {@code unsigned} sections are resolved as follows:
 * if a key matches a name defined in the {@code artifacts} section, it is expanded
 * to that group's coordinate patterns; otherwise it is treated as a Maven coordinate
 * pattern directly.
 */
class ArtifactMatcher {

    private final List<TrustEntry> trustEntries;
    private final List<PatternEntry> unsignedEntries;

    ArtifactMatcher(TrustConfig config) {
        this.trustEntries = expandTrustEntries(config);
        this.unsignedEntries = expandUnsignedEntries(config);
    }

    /**
     * Checks whether the given artifact is listed as unsigned (signature not expected).
     */
    boolean isUnsigned(ArtifactCoords artifact) {
        for (PatternEntry entry : unsignedEntries) {
            if (entry.matches(artifact)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks whether the given coordinates are listed as unsigned.
     */
    boolean isUnsigned(String groupId, String artifactId) {
        for (PatternEntry entry : unsignedEntries) {
            if (entry.matches(groupId, artifactId)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks whether the given coordinate string is listed as unsigned.
     * Parses groupId:artifactId[:type:classifier]:version from the coordinates.
     */
    boolean isUnsignedCoords(String coords) {
        String[] p = coords.split(":");
        for (PatternEntry entry : unsignedEntries) {
            if (matchCoordParts(entry, p) >= 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * Finds the trusted signer reference IDs for the given artifact by selecting
     * the narrowest (highest specificity) matching trust pattern.
     *
     * @return the list of signer reference IDs, or null if no pattern matches
     */
    List<String> findTrustedSignerRefs(ArtifactCoords artifact) {
        return findBestSignerRefs(
                entry -> entry.pattern.matchScore(artifact));
    }

    /**
     * Finds the trusted signer reference IDs for the given coordinates.
     *
     * @return the list of signer reference IDs, or null if no pattern matches
     */
    List<String> findTrustedSignerRefs(String groupId, String artifactId) {
        return findBestSignerRefs(
                entry -> entry.pattern.matchScore(groupId, artifactId));
    }

    /**
     * Finds the trusted signer reference IDs for the given coordinate string.
     * Parses groupId:artifactId[:type:classifier]:version from the coordinates.
     *
     * @return the list of signer reference IDs, or null if no pattern matches
     */
    List<String> findTrustedSignerRefsCoords(String coords) {
        String[] p = coords.split(":");
        return findBestSignerRefs(entry -> matchCoordParts(entry.pattern, p));
    }

    private static int matchCoordParts(PatternEntry pattern, String[] parts) {
        return switch (parts.length) {
            case 2 -> pattern.matchScore(parts[0], parts[1]);
            case 3 -> pattern.matchScore(parts[0], parts[1], null, null, parts[2]);
            case 4 -> pattern.matchScore(parts[0], parts[1], parts[2], null, parts[3]);
            case 5 -> pattern.matchScore(parts[0], parts[1], parts[2], parts[3], parts[4]);
            default -> parts.length >= 1 ? pattern.matchScore(parts[0], null) : -1;
        };
    }

    private List<String> findBestSignerRefs(java.util.function.ToIntFunction<TrustEntry> scorer) {
        int maxScore = -1;
        List<String> bestRefs = null;

        for (TrustEntry entry : trustEntries) {
            int score = scorer.applyAsInt(entry);
            if (score < 0) {
                continue;
            }
            if (score > maxScore) {
                maxScore = score;
                bestRefs = entry.signerRefs;
            } else if (score == maxScore && bestRefs != null) {
                List<String> combined = null;
                for (String ref : entry.signerRefs) {
                    if (!bestRefs.contains(ref)) {
                        if (combined == null) {
                            combined = new ArrayList<>(bestRefs);
                        }
                        combined.add(ref);
                    }
                }
                if (combined != null) {
                    bestRefs = combined;
                }
            }
        }
        return bestRefs;
    }

    /**
     * Expands trust mappings by resolving artifact group references. If a trust key
     * matches a name in the {@code artifacts} section, each pattern in that group
     * produces a separate {@link TrustEntry}; otherwise the key itself is used as
     * a coordinate pattern.
     */
    private List<TrustEntry> expandTrustEntries(TrustConfig config) {
        List<TrustEntry> result = new ArrayList<>();
        Map<String, List<String>> artifactGroups = config.artifacts();

        for (var entry : config.trust().entrySet()) {
            String key = entry.getKey();
            List<String> signerRefs = entry.getValue();

            List<String> patterns = artifactGroups.getOrDefault(key, List.of(key));
            for (String pattern : patterns) {
                result.add(new TrustEntry(PatternEntry.parse(pattern), signerRefs));
            }
        }
        return result;
    }

    private List<PatternEntry> expandUnsignedEntries(TrustConfig config) {
        List<PatternEntry> result = new ArrayList<>();
        Map<String, List<String>> artifactGroups = config.artifacts();

        for (String key : config.unsigned()) {
            List<String> patterns = artifactGroups.getOrDefault(key, List.of(key));
            for (String pattern : patterns) {
                result.add(PatternEntry.parse(pattern));
            }
        }
        return result;
    }

    private record TrustEntry(PatternEntry pattern, List<String> signerRefs) {
    }

    /**
     * A parsed Maven coordinate pattern with specificity-based matching.
     */
    static class PatternEntry {

        private final String groupPattern;
        private final String artifactPattern;
        private final String typePattern;
        private final String classifierPattern;
        private final String versionPattern;

        private PatternEntry(String groupPattern, String artifactPattern,
                String typePattern, String classifierPattern, String versionPattern) {
            this.groupPattern = groupPattern;
            this.artifactPattern = artifactPattern;
            this.typePattern = typePattern;
            this.classifierPattern = classifierPattern;
            this.versionPattern = versionPattern;
        }

        /**
         * Parses a coordinate pattern string into segments.
         * Supported formats: groupId, groupId:artifactId, groupId:artifactId:version,
         * groupId:artifactId:type:version, groupId:artifactId:type:classifier:version.
         */
        static PatternEntry parse(String pattern) {
            String[] segments = pattern.split(":");
            return switch (segments.length) {
                case 1 -> new PatternEntry(segments[0], null, null, null, null);
                case 2 -> new PatternEntry(segments[0], segments[1], null, null, null);
                case 3 -> new PatternEntry(segments[0], segments[1], null, null, segments[2]);
                case 4 -> new PatternEntry(segments[0], segments[1], segments[2], null, segments[3]);
                case 5 -> new PatternEntry(segments[0], segments[1], segments[2],
                        segments[3], segments[4]);
                default -> throw new IllegalArgumentException(
                        "Invalid pattern '" + pattern
                                + "': expected 1-5 colon-separated segments");
            };
        }

        /** @return true if this pattern matches the given artifact */
        boolean matches(ArtifactCoords artifact) {
            return matchScore(artifact) >= 0;
        }

        /** @return true if this pattern matches the given coordinates */
        boolean matches(String groupId, String artifactId) {
            return matchScore(groupId, artifactId) >= 0;
        }

        /** Returns the specificity score if this pattern matches, or -1 if not. */
        int matchScore(ArtifactCoords artifact) {
            return matchScore(artifact.groupId(), artifact.artifactId(),
                    artifact.type(), artifact.classifier(), artifact.version());
        }

        /** Returns the specificity score matching only groupId and artifactId. */
        int matchScore(String groupId, String artifactId) {
            return matchScore(groupId, artifactId, null, null, null);
        }

        int matchScore(String groupId, String artifactId,
                String type, String classifier, String version) {
            int score = matchGroup(groupPattern, groupId);
            if (score < 0) {
                return -1;
            }
            if (artifactPattern != null) {
                int s = matchSegment(artifactPattern, artifactId);
                if (s < 0) {
                    return -1;
                }
                score += s;
            }
            if (typePattern != null) {
                int s = matchSegment(typePattern, type != null ? type : "jar");
                if (s < 0) {
                    return -1;
                }
                score += s;
            }
            if (classifierPattern != null) {
                int s = matchSegment(classifierPattern,
                        classifier != null ? classifier : "");
                if (s < 0) {
                    return -1;
                }
                score += s;
            }
            if (versionPattern != null) {
                int s = matchSegment(versionPattern, version);
                if (s < 0) {
                    return -1;
                }
                score += s;
            }
            return score;
        }

        // Group scores use segment_count * 10 to ensure group specificity dominates
        // over non-group segment scores (max 4 segments * 2 = 8 < 10).
        private static int matchGroup(String pattern, String groupId) {
            if ("*".equals(pattern)) {
                return 0;
            }
            if (pattern.endsWith(".*")) {
                String prefix = pattern.substring(0, pattern.length() - 2);
                if (groupId.equals(prefix) || groupId.startsWith(prefix + ".")) {
                    return countSegments(prefix) * 10;
                }
                return -1;
            }
            return pattern.equals(groupId) ? (countSegments(pattern) + 1) * 10 : -1;
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

        private static int matchSegment(String pattern, String value) {
            if ("*".equals(pattern)) {
                return 0;
            }
            return pattern.equals(value) ? 2 : -1;
        }
    }
}
