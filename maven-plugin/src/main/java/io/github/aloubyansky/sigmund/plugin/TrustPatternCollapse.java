package io.github.aloubyansky.sigmund.plugin;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Collapses artifact-to-signers mappings into compact trust patterns.
 * <p>
 * Two levels of collapsing are applied:
 * <ol>
 * <li>Within each groupId: the majority signer set becomes a {@code groupId.*}
 * wildcard, exceptions are kept as individual entries.</li>
 * <li>Across groupIds: wildcards that share a common prefix and the same signer
 * set are merged into a single parent prefix wildcard (e.g. {@code io.quarkus.*}
 * absorbs {@code io.quarkus.arc.*}).</li>
 * </ol>
 */
class TrustPatternCollapse {

    private TrustPatternCollapse() {
    }

    /**
     * Collapses artifact-to-signers mappings into compact trust patterns.
     *
     * @param artifactSigners mapping from artifact pattern (e.g. {@code groupId:artifactId})
     *        to the set of signer IDs that signed that artifact
     * @return mapping from collapsed pattern to signer IDs
     */
    static Map<String, List<String>> collapse(Map<String, Set<String>> artifactSigners) {
        Map<String, List<String>> perGroup = collapseWithinGroups(artifactSigners);
        return collapseAcrossGroups(perGroup);
    }

    /**
     * First pass: for each groupId with 2+ artifacts, collapse the majority signer
     * set into a wildcard and keep exceptions as individual entries.
     */
    static Map<String, List<String>> collapseWithinGroups(
            Map<String, Set<String>> artifactSigners) {
        Map<String, List<String>> groupArtifacts = new LinkedHashMap<>();
        for (String pattern : artifactSigners.keySet()) {
            String groupId = pattern.split(":")[0];
            groupArtifacts.computeIfAbsent(groupId, k -> new ArrayList<>()).add(pattern);
        }

        Map<String, List<String>> result = new LinkedHashMap<>();
        for (var groupEntry : groupArtifacts.entrySet()) {
            String groupId = groupEntry.getKey();
            List<String> patterns = groupEntry.getValue();

            if (patterns.size() < 2) {
                for (String p : patterns) {
                    result.put(p, List.copyOf(artifactSigners.get(p)));
                }
                continue;
            }

            Set<String> majority = findMajoritySignerSet(patterns, artifactSigners);
            result.put(groupId + ".*", List.copyOf(majority));
            for (String p : patterns) {
                if (!artifactSigners.get(p).equals(majority)) {
                    result.put(p, List.copyOf(artifactSigners.get(p)));
                }
            }
        }
        return result;
    }

    /**
     * Second pass: merge wildcard entries that share a common groupId prefix and
     * the same signer set into a single parent wildcard. For example,
     * {@code io.quarkus.*}, {@code io.quarkus.arc.*}, and {@code io.quarkus.vertx.utils.*}
     * all with the same signers become just {@code io.quarkus.*}.
     * <p>
     * Individual exception entries from absorbed groups are preserved if their
     * signer set differs from the parent wildcard.
     */
    static Map<String, List<String>> collapseAcrossGroups(
            Map<String, List<String>> perGroup) {
        Map<String, List<String>> wildcards = new LinkedHashMap<>();
        for (var entry : perGroup.entrySet()) {
            if (entry.getKey().endsWith(".*")) {
                wildcards.put(entry.getKey(), entry.getValue());
            }
        }

        Set<String> absorbed = findAbsorbedWildcards(wildcards);

        Map<String, List<String>> result = new LinkedHashMap<>();
        for (var entry : perGroup.entrySet()) {
            String key = entry.getKey();
            if (absorbed.contains(key)) {
                continue;
            }
            if (!key.endsWith(".*")) {
                String groupId = key.split(":")[0];
                if (absorbed.contains(groupId + ".*")) {
                    String parentWildcard = findParentWildcard(groupId, wildcards, absorbed);
                    if (parentWildcard != null
                            && !entry.getValue().equals(wildcards.get(parentWildcard))) {
                        result.put(key, entry.getValue());
                    }
                    continue;
                }
            }
            result.put(key, entry.getValue());
        }
        return result;
    }

    /**
     * Finds wildcards that are covered by a parent prefix wildcard with the same signers.
     */
    private static Set<String> findAbsorbedWildcards(Map<String, List<String>> wildcards) {
        Set<String> absorbed = new LinkedHashSet<>();
        for (String wildcard : wildcards.keySet()) {
            String groupId = wildcard.substring(0, wildcard.length() - 2);
            for (String candidate : wildcards.keySet()) {
                if (candidate.equals(wildcard)) {
                    continue;
                }
                String candidatePrefix = candidate.substring(0, candidate.length() - 2);
                if (groupId.startsWith(candidatePrefix + ".")
                        && wildcards.get(candidate).equals(wildcards.get(wildcard))) {
                    absorbed.add(wildcard);
                    break;
                }
            }
        }
        return absorbed;
    }

    /**
     * Finds the parent wildcard that covers the given groupId.
     */
    private static String findParentWildcard(String groupId,
            Map<String, List<String>> wildcards, Set<String> absorbed) {
        for (String wildcard : wildcards.keySet()) {
            if (absorbed.contains(wildcard)) {
                continue;
            }
            String prefix = wildcard.substring(0, wildcard.length() - 2);
            if (groupId.equals(prefix) || groupId.startsWith(prefix + ".")) {
                return wildcard;
            }
        }
        return null;
    }

    /**
     * Finds the signer set shared by the most artifacts in the given list.
     */
    static Set<String> findMajoritySignerSet(List<String> patterns,
            Map<String, Set<String>> artifactSigners) {
        Map<Set<String>, Integer> counts = new HashMap<>();
        for (String p : patterns) {
            Set<String> signers = artifactSigners.get(p);
            counts.merge(signers, 1, Integer::sum);
        }
        return counts.entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .orElseThrow();
    }
}
