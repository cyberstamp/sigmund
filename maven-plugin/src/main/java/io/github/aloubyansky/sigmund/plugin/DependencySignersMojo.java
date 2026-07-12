package io.github.aloubyansky.sigmund.plugin;

import io.github.aloubyansky.sigmund.core.Algorithms;
import io.github.aloubyansky.sigmund.core.GpgRunner;
import io.github.aloubyansky.sigmund.core.OpenPgpVerifyResult;
import io.github.aloubyansky.sigmund.core.Verdict;
import io.github.aloubyansky.sigmund.core.VerifyResult;
import io.github.aloubyansky.sigmund.plugin.SignatureInspector.SignedArtifact;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

/**
 * Reports signer information for all project dependencies by downloading and
 * inspecting their signature files (.asc).
 * <p>
 * Each armored block in a signature file is reported separately, with its OpenPGP
 * version (v4 for classical, v6 for PQC). Classical (v4) signatures are verified
 * via GPG to extract the signer's key ID and user ID. PQC (v6) signatures are
 * detected but not yet verified.
 * <p>
 * The signature file is downloaded from the same remote repository that provided the
 * artifact itself, ensuring the reported signer matches the actual artifact in use.
 */
@Mojo(name = "dependency-signers", defaultPhase = LifecyclePhase.VALIDATE, threadSafe = true)
public class DependencySignersMojo extends AbstractDependencyMojo {

    /**
     * When {@code true}, generates a {@code trust-config.yaml} in the project root
     * in addition to the console report. The generated file can be used directly
     * with the {@code verify} goal. An explicit file path may be provided instead
     * of {@code true} to write to a custom location.
     */
    @Parameter(property = "sigmund.generateTrustConfig")
    private String generateTrustConfig;

    /**
     * When {@code true}, allows overwriting an existing trust config file.
     * By default, the generation fails if the file already exists.
     */
    @Parameter(property = "sigmund.overwrite", defaultValue = "false")
    private boolean overwrite;

    /**
     * When set, updates an existing {@code trust-config.yaml} by appending
     * any signers and artifacts not already configured. Provide {@code true}
     * to update the default location, or a file path for a custom location.
     */
    @Parameter(property = "sigmund.updateTrustConfig")
    private String updateTrustConfig;

    @Override
    public void execute() throws MojoExecutionException {
        if (skip) {
            getLog().info("Skipping dependency signers report");
            return;
        }

        TrustConfig config = loadTrustConfig();
        TrustConfig.Settings settings = resolveSettings(
                config != null ? config.settings() : TrustConfig.Settings.defaults());
        SignatureInspector inspector = buildInspector(settings);

        List<ArtifactCoords> artifacts = resolveDependencies();
        getLog().info("Inspecting signatures for " + artifacts.size() + " dependency(ies)...");
        getLog().info("");

        List<SignedArtifact> results = inspector.inspectAll(artifacts);

        logReport(results);

        if (generateTrustConfig != null && !generateTrustConfig.isEmpty()) {
            File configFile = resolveTrustConfigFile(generateTrustConfig);
            writeTrustConfigYaml(results, configFile);
        }

        if (updateTrustConfig != null && !updateTrustConfig.isEmpty()) {
            File configFile = resolveTrustConfigFile(updateTrustConfig);
            updateExistingTrustConfig(results, configFile);
        }
    }

    private static String profileKey(VerifyResult vr) {
        int pgpVersion = vr instanceof OpenPgpVerifyResult opvr ? opvr.version() : -1;
        String id = vr.signerIdentifier();
        return pgpVersion + ":" + (id != null ? id : "?");
    }

    private void logReport(List<SignedArtifact> results) {

        // Group entries by artifact coordinate
        Map<String, List<SignedArtifact>> byArtifact = new HashMap<>();
        for (SignedArtifact r : results) {
            byArtifact.computeIfAbsent(r.coordinates(), k -> new ArrayList<>(2)).add(r);
        }

        // Build signature profile for each artifact and group by shared key sets
        Map<String, List<String>> profileToCoords = new HashMap<>();
        List<String> unsignedCoords = new ArrayList<>();

        for (var entry : byArtifact.entrySet()) {
            String coords = entry.getKey();
            List<SignedArtifact> signers = entry.getValue();

            boolean allUnsigned = signers.stream()
                    .allMatch(s -> s.verdict() == Verdict.SKIPPED);
            if (allUnsigned) {
                unsignedCoords.add(coords);
                continue;
            }

            String profile = signers.stream()
                    .filter(s -> s.verdict() != Verdict.SKIPPED)
                    .map(s -> profileKey(s.verifyResult()))
                    .sorted()
                    .distinct()
                    .collect(Collectors.joining("|"));

            profileToCoords.computeIfAbsent(profile, k -> new ArrayList<>()).add(coords);
        }

        // Sort artifacts within each group alphabetically
        profileToCoords.values().forEach(list -> list.sort(Comparator.naturalOrder()));
        unsignedCoords.sort(Comparator.naturalOrder());

        // Sort groups alphabetically by signer name; unverified groups go last
        List<Map.Entry<String, List<String>>> sortedGroups = profileToCoords.entrySet().stream()
                .sorted((a, b) -> {
                    String signerA = firstSigner(a.getValue(), byArtifact);
                    String signerB = firstSigner(b.getValue(), byArtifact);
                    if (signerA != null && signerB != null) {
                        return signerA.compareToIgnoreCase(signerB);
                    }
                    if (signerA != null) {
                        return -1;
                    }
                    if (signerB != null) {
                        return 1;
                    }
                    return a.getKey().compareTo(b.getKey());
                })
                .toList();

        // Output signed groups
        boolean firstGroup = true;
        for (var groupEntry : sortedGroups) {
            if (!firstGroup) {
                getLog().info("");
            }
            firstGroup = false;

            List<String> coordsList = groupEntry.getValue();

            // Pick the richest VerifyResult per key (prefer one with a known signer)
            Map<String, VerifyResult> bestPerKey = new HashMap<>();
            for (String coords : coordsList) {
                for (SignedArtifact as : byArtifact.get(coords)) {
                    if (as.verdict() == Verdict.SKIPPED) {
                        continue;
                    }
                    bestPerKey.merge(profileKey(as.verifyResult()), as.verifyResult(),
                            (existing, incoming) -> existing.signerDisplayName() != null ? existing : incoming);
                }
            }

            // Sort key headers by profile key
            List<VerifyResult> sortedKeys = bestPerKey.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey())
                    .map(Map.Entry::getValue)
                    .toList();

            boolean groupHasIssue = sortedKeys.stream()
                    .noneMatch(vr -> vr.signerDisplayName() != null);

            // Print signer name once, then all key lines
            String signerName = sortedKeys.stream()
                    .map(VerifyResult::signerDisplayName)
                    .filter(n -> n != null)
                    .findFirst().orElse(null);
            if (signerName != null) {
                getLog().info("Signer: " + signerName);
            } else if (sortedKeys.stream().allMatch(vr -> vr.verdict() == Verdict.NO_KEY)) {
                getLog().warn("Signer: UNKNOWN (key not in keyring)");
            } else if (sortedKeys.stream().anyMatch(vr -> vr.verdict() == Verdict.FAIL)) {
                getLog().warn("Signer: VERIFICATION FAILED");
            } else {
                getLog().warn("Signer: NOT VERIFIED");
            }
            for (VerifyResult vr : sortedKeys) {
                int pgpVersion = vr instanceof OpenPgpVerifyResult opvr ? opvr.version() : -1;
                String ver = SignatureInspector.versionLabel(pgpVersion);
                String keyId = vr.signerIdentifier() != null ? vr.signerIdentifier() : "-";
                String keyLine = "   " + ver + formatAlgorithm(vr) + ": " + keyId;
                if (signerName != null) {
                    getLog().info(keyLine);
                } else {
                    getLog().warn(keyLine);
                }
            }

            // Print artifacts
            for (String coords : coordsList) {
                boolean hasFail = byArtifact.get(coords).stream()
                        .anyMatch(as -> as.verdict() == Verdict.FAIL);
                String line = "     " + coords;
                if (hasFail) {
                    getLog().error(line + "   (BAD SIGNATURE)");
                } else if (groupHasIssue) {
                    getLog().warn(line);
                } else {
                    getLog().info(line);
                }
            }
        }

        // Output unsigned group
        if (!unsignedCoords.isEmpty()) {
            if (!firstGroup) {
                getLog().info("");
            }
            getLog().warn("UNSIGNED");
            for (String coords : unsignedCoords) {
                getLog().warn("  " + coords);
            }
        }

        // Summary statistics
        long totalArtifacts = results.stream().map(SignedArtifact::coordinates).distinct().count();
        Map<Integer, Long> versionCounts = results.stream()
                .filter(r -> r.verifyResult() instanceof OpenPgpVerifyResult)
                .collect(Collectors.groupingBy(
                        r -> ((OpenPgpVerifyResult) r.verifyResult()).version(),
                        Collectors.counting()));
        long uniqueKeys = results.stream()
                .map(r -> r.verifyResult().signerIdentifier())
                .filter(Objects::nonNull)
                .distinct()
                .count();
        long untrusted = results.stream()
                .filter(r -> r.verdict() == Verdict.SKIPPED
                        || r.verdict() == Verdict.FAIL)
                .map(SignedArtifact::coordinates)
                .distinct()
                .count();
        Set<String> identifiedCoords = results.stream()
                .filter(r -> r.verifyResult().signerDisplayName() != null)
                .map(SignedArtifact::coordinates)
                .collect(Collectors.toSet());
        long unidentified = results.stream()
                .filter(r -> r.verdict() != Verdict.SKIPPED
                        && r.verdict() != Verdict.FAIL)
                .map(SignedArtifact::coordinates)
                .distinct()
                .filter(c -> !identifiedCoords.contains(c))
                .count();

        getLog().info("");
        StringBuilder summary = new StringBuilder();
        if (untrusted == 0 && unidentified == 0) {
            summary.append("All clear: ");
        } else {
            if (untrusted > 0) {
                summary.append(untrusted).append(" untrusted");
            }
            if (unidentified > 0) {
                if (untrusted > 0) {
                    summary.append(", ");
                }
                summary.append(unidentified).append(" unidentified");
            }
            summary.append(": ");
        }
        summary.append(totalArtifacts).append(" dependencies");
        versionCounts.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(e -> summary.append(", ").append(e.getValue()).append(" ")
                        .append(SignatureInspector.versionLabel(e.getKey())).append(" signature(s)"));
        summary.append(", ").append(uniqueKeys).append(" unique key(s)");
        getLog().info("Summary: " + summary);

        Set<String> pqCoords = results.stream()
                .filter(r -> Algorithms.isPqcAlgorithmName(r.verifyResult().algorithm()))
                .map(SignedArtifact::coordinates)
                .collect(Collectors.toSet());
        getLog().info("PQ coverage: " + pqCoords.size() + "/" + totalArtifacts
                + " dependencies have a post-quantum signature");
    }

    private static String formatAlgorithm(VerifyResult vr) {
        String algo = vr.algorithm();
        if (algo == null) {
            return "";
        }
        return " (" + algo + ")";
    }

    private static String firstSigner(List<String> coordsList,
            Map<String, List<SignedArtifact>> byArtifact) {
        for (String coords : coordsList) {
            for (SignedArtifact as : byArtifact.get(coords)) {
                if (as.verifyResult().signerDisplayName() != null) {
                    return as.verifyResult().signerDisplayName();
                }
            }
        }
        return null;
    }

    /**
     * Resolves the trust config output file. If the parameter value is {@code "true"},
     * defaults to {@code trust-config.yaml} in the project root; otherwise treats
     * the value as a file path.
     */
    private File resolveTrustConfigFile(String param) {
        if ("true".equalsIgnoreCase(param)) {
            return new File(project.getBasedir(), "trust-config.yaml");
        }
        return new File(param);
    }

    /**
     * Writes a {@code trust-config.yaml} file from the inspection results.
     * Artifacts are grouped by signer, with common groupId prefixes collapsed
     * into wildcard patterns. Versions are stripped from trust patterns.
     */
    private void writeTrustConfigYaml(List<SignedArtifact> results, File configFile)
            throws MojoExecutionException {
        if (configFile.exists() && !overwrite) {
            throw new MojoExecutionException(
                    "Trust config file already exists: " + configFile.getAbsolutePath()
                            + ". Use -Dsigmund.overwrite=true to overwrite.");
        }

        Map<String, List<SignedArtifact>> byArtifact = new HashMap<>();
        for (SignedArtifact r : results) {
            byArtifact.computeIfAbsent(r.coordinates(), k -> new ArrayList<>(2)).add(r);
        }

        Map<String, SignerInfo> signersByKey = new LinkedHashMap<>();
        Map<String, Set<String>> artifactSigners = new LinkedHashMap<>();
        List<String> unsignedCoords = new ArrayList<>();
        int signerCounter = 0;

        for (var entry : byArtifact.entrySet()) {
            String coords = entry.getKey();
            List<SignedArtifact> sigEntries = entry.getValue();

            boolean allUnsigned = sigEntries.stream()
                    .allMatch(s -> s.verdict() == Verdict.SKIPPED);
            if (allUnsigned) {
                unsignedCoords.add(stripVersion(coords));
                continue;
            }

            String strippedCoords = stripVersion(coords);
            for (SignedArtifact sa : sigEntries) {
                VerifyResult vr = sa.verifyResult();
                if (sa.verdict() == Verdict.SKIPPED
                        || vr.signerIdentifier() == null) {
                    continue;
                }
                String id = vr.signerIdentifier();
                SignerInfo info = signersByKey.get(id);
                if (info == null) {
                    signerCounter++;
                    info = new SignerInfo(
                            resolveUniqueSignerId(vr, signerCounter, signersByKey, Set.of()), vr);
                    signersByKey.put(id, info);
                } else {
                    info.merge(vr);
                }
                artifactSigners.computeIfAbsent(strippedCoords, k -> new LinkedHashSet<>())
                        .add(info.id);
            }
        }

        Map<String, List<String>> trustPatterns = TrustPatternCollapse.collapse(artifactSigners);

        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(configFile.toPath()))) {
            writeSignersSection(w, signersByKey);
            writeTrustSection(w, trustPatterns);
            writeUnsignedSection(w, unsignedCoords);
            if (w.checkError()) {
                throw new IOException("Error writing trust config");
            }
        } catch (IOException e) {
            throw new MojoExecutionException("Failed to write trust config to " + configFile, e);
        }

        getLog().info("");
        getLog().info("Trust configuration written to " + configFile.getPath());
    }

    /**
     * Strips the version (and type/classifier if default) from a coordinate string,
     * leaving just {@code groupId:artifactId}.
     */
    private static String stripVersion(String coords) {
        String[] parts = coords.split(":");
        if (parts.length >= 2) {
            return parts[0] + ":" + parts[1];
        }
        return coords;
    }

    /**
     * Updates an existing trust config by parsing it, finding artifacts not yet
     * configured, and appending their signers and trust entries.
     */
    private void updateExistingTrustConfig(List<SignedArtifact> results, File configFile)
            throws MojoExecutionException {
        if (!configFile.exists()) {
            throw new MojoExecutionException(
                    "Trust config file not found: " + configFile.getAbsolutePath()
                            + ". Use -Dsigmund.generateTrustConfig to create one first.");
        }

        TrustConfig existing;
        try {
            existing = TrustConfigParser.parse(configFile.toPath());
        } catch (IOException e) {
            throw new MojoExecutionException("Failed to parse trust config: " + configFile, e);
        } catch (IllegalArgumentException e) {
            throw new MojoExecutionException(e.getMessage(), e);
        }

        ArtifactMatcher matcher = new ArtifactMatcher(existing);

        Map<String, List<SignedArtifact>> byArtifact = new HashMap<>();
        for (SignedArtifact r : results) {
            byArtifact.computeIfAbsent(r.coordinates(), k -> new ArrayList<>(2)).add(r);
        }

        Map<String, SignerInfo> newSigners = new LinkedHashMap<>();
        Map<String, Set<String>> newArtifactSigners = new LinkedHashMap<>();
        List<String> newUnsigned = new ArrayList<>();
        int signerCounter = existing.signers().size();

        for (var entry : byArtifact.entrySet()) {
            String coords = entry.getKey();
            List<SignedArtifact> sigEntries = entry.getValue();

            if (matcher.isUnsignedCoords(coords)
                    || matcher.findTrustedSignerRefsCoords(coords) != null) {
                continue;
            }

            boolean allUnsigned = sigEntries.stream()
                    .allMatch(s -> s.verdict() == Verdict.SKIPPED);
            if (allUnsigned) {
                newUnsigned.add(stripVersion(coords));
                continue;
            }

            String strippedCoords = stripVersion(coords);
            for (SignedArtifact sa : sigEntries) {
                VerifyResult vr = sa.verifyResult();
                if (sa.verdict() == Verdict.SKIPPED
                        || vr.signerIdentifier() == null) {
                    continue;
                }
                String id = vr.signerIdentifier();
                SignerInfo info = newSigners.get(id);
                if (info == null) {
                    signerCounter++;
                    info = new SignerInfo(
                            resolveUniqueSignerId(vr, signerCounter, newSigners, existing.signers().keySet()),
                            vr);
                    newSigners.put(id, info);
                } else {
                    info.merge(vr);
                }
                newArtifactSigners.computeIfAbsent(strippedCoords, k -> new LinkedHashSet<>())
                        .add(info.id);
            }
        }

        if (newSigners.isEmpty() && newUnsigned.isEmpty()) {
            getLog().info("Trust configuration is already up to date.");
            return;
        }

        Map<String, List<String>> newTrustPatterns = TrustPatternCollapse.collapse(newArtifactSigners);

        spliceIntoConfigFile(configFile, newSigners, newTrustPatterns, newUnsigned);

        getLog().info("");
        getLog().info("Trust configuration updated: " + configFile.getPath());
        getLog().info("Review changes with: git diff " + configFile.getName());
    }

    /**
     * Splices new entries into the existing config file by inserting lines at the
     * end of each section. Preserves all existing content including comments and
     * formatting.
     */
    private void spliceIntoConfigFile(File configFile,
            Map<String, SignerInfo> newSigners,
            Map<String, List<String>> newTrustPatterns,
            List<String> newUnsigned) throws MojoExecutionException {
        List<String> lines;
        try {
            lines = new ArrayList<>(Files.readAllLines(configFile.toPath()));
        } catch (IOException e) {
            throw new MojoExecutionException("Failed to read trust config: " + configFile, e);
        }

        // Insert in reverse order (unsigned, trust, signers) so earlier
        // insertions don't shift the line numbers for later ones
        spliceUnsigned(lines, newUnsigned);
        spliceTrust(lines, newTrustPatterns);
        spliceSigners(lines, newSigners);

        try {
            Files.write(configFile.toPath(), lines);
        } catch (IOException e) {
            throw new MojoExecutionException(
                    "Failed to update trust config: " + configFile, e);
        }
    }

    /**
     * Finds the line index where a top-level YAML section ends (the line before
     * the next top-level key or EOF). Returns -1 if the section is not found.
     */
    private int findSectionEnd(List<String> lines, String sectionKey) {
        int sectionStart = -1;
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            String trimmed = line.stripLeading();
            if (isSectionHeader(trimmed, sectionKey)) {
                sectionStart = i;
            } else if (sectionStart >= 0 && !line.isEmpty() && !trimmed.startsWith("#")
                    && !line.startsWith(" ") && !trimmed.startsWith("-")) {
                return i;
            }
        }
        return sectionStart >= 0 ? lines.size() : -1;
    }

    private static boolean isSectionHeader(String trimmed, String sectionKey) {
        if (!trimmed.startsWith(sectionKey + ":")) {
            return false;
        }
        int afterColon = sectionKey.length() + 1;
        return afterColon >= trimmed.length()
                || trimmed.charAt(afterColon) == ' '
                || trimmed.charAt(afterColon) == '#';
    }

    private void spliceSigners(List<String> lines, Map<String, SignerInfo> newSigners) {
        if (newSigners.isEmpty()) {
            return;
        }
        List<String> newLines = new ArrayList<>();
        newSigners.values().stream()
                .sorted(Comparator.comparing(i -> i.id, String.CASE_INSENSITIVE_ORDER))
                .forEach(info -> appendSignerYaml(info, "  ", newLines::add));
        insertAtSectionEnd(lines, "signers", newLines);
    }

    private void spliceTrust(List<String> lines, Map<String, List<String>> newTrustPatterns) {
        if (newTrustPatterns.isEmpty()) {
            return;
        }
        List<String> newLines = new ArrayList<>();
        newTrustPatterns.entrySet().stream()
                .sorted(Map.Entry.comparingByKey(String.CASE_INSENSITIVE_ORDER))
                .forEach(entry -> {
                    String pattern = entry.getKey();
                    List<String> signerIds = entry.getValue();
                    if (signerIds.size() == 1) {
                        newLines.add("  " + pattern + ": " + signerIds.get(0));
                    } else {
                        newLines.add("  " + pattern + ": [" + String.join(", ", signerIds) + "]");
                    }
                });
        insertAtSectionEnd(lines, "trust", newLines);
    }

    private void spliceUnsigned(List<String> lines, List<String> newUnsigned) {
        if (newUnsigned.isEmpty()) {
            return;
        }
        List<String> newLines = newUnsigned.stream()
                .distinct().sorted()
                .map(c -> "  - " + c)
                .toList();
        insertAtSectionEnd(lines, "unsigned", newLines);
    }

    /**
     * Inserts new lines at the end of an existing section. If the section doesn't
     * exist, appends a new section at the end of the file.
     */
    private void insertAtSectionEnd(List<String> lines, String sectionKey,
            List<String> newLines) {
        int insertAt = findSectionEnd(lines, sectionKey);
        if (insertAt < 0) {
            lines.add("");
            lines.add(sectionKey + ":");
            lines.addAll(newLines);
        } else {
            lines.addAll(insertAt, newLines);
        }
    }

    private void writeSignersSection(PrintWriter w, Map<String, SignerInfo> signersByKey) {
        if (signersByKey.isEmpty()) {
            return;
        }
        w.println("signers:");
        List<SignerInfo> sorted = signersByKey.values().stream()
                .sorted(Comparator.comparing(i -> i.id, String.CASE_INSENSITIVE_ORDER))
                .toList();
        for (SignerInfo info : sorted) {
            appendSignerYaml(info, "  ", w::println);
        }
        w.println();
    }

    /**
     * Writes the trust section sorted by artifact pattern. When an artifact has
     * multiple signers, they are emitted as a YAML array.
     */
    private void writeTrustSection(PrintWriter w, Map<String, List<String>> trustPatterns) {
        if (trustPatterns.isEmpty()) {
            return;
        }
        w.println("trust:");
        trustPatterns.entrySet().stream()
                .sorted(Map.Entry.comparingByKey(String.CASE_INSENSITIVE_ORDER))
                .forEach(entry -> {
                    String pattern = entry.getKey();
                    List<String> signerIds = entry.getValue();
                    if (signerIds.size() == 1) {
                        w.println("  " + pattern + ": " + signerIds.get(0));
                    } else {
                        w.println("  " + pattern + ": [" + String.join(", ", signerIds) + "]");
                    }
                });
        w.println();
    }

    private static void appendSignerYaml(SignerInfo info, String indent, Consumer<String> out) {
        boolean hasFingerprint = info.pgp4Key != null || info.pgp6Key != null;
        if (!hasFingerprint && info.email == null) {
            return;
        }
        if (info.email != null && !hasFingerprint) {
            out.accept(indent + info.id + ": \"" + info.email + "\"");
            return;
        }
        out.accept(indent + info.id + ":");
        if (info.pgp4Key != null) {
            out.accept(indent + "  pgp4: \"" + info.pgp4Key + "\"");
        }
        if (info.pgp6Key != null) {
            out.accept(indent + "  pgp6: \"" + info.pgp6Key + "\"");
        }
        if (info.email != null) {
            out.accept(indent + "  email: \"" + info.email + "\"");
        }
    }

    private void writeUnsignedSection(PrintWriter w, List<String> unsignedCoords) {
        if (unsignedCoords.isEmpty()) {
            return;
        }
        w.println("unsigned:");
        unsignedCoords.stream().distinct().sorted().forEach(c -> w.println("  - " + c));
    }

    String generateSignerId(String signerDisplayName, int counter) {
        if (signerDisplayName != null) {
            int angleBracket = signerDisplayName.indexOf('<');
            String name = (angleBracket > 0 ? signerDisplayName.substring(0, angleBracket)
                    : signerDisplayName).trim();
            String id = name.toLowerCase().replaceAll("[^a-z0-9]+", "-")
                    .replaceAll("^-|-$", "");
            if (!id.isEmpty()) {
                return id;
            }
        }
        return "signer-" + counter;
    }

    String resolveUniqueSignerId(VerifyResult vr, int counter,
            Map<String, SignerInfo> existingSigners, Set<String> reservedIds) {
        String base = generateSignerId(vr.signerDisplayName(), counter);
        String candidate = base;
        int suffix = 2;
        Set<String> taken = new java.util.HashSet<>(reservedIds);
        existingSigners.values().forEach(i -> taken.add(i.id));
        while (taken.contains(candidate)) {
            candidate = base + "-" + suffix++;
        }
        return candidate;
    }

    static class SignerInfo {
        final String id;
        String pgp4Key;
        String pgp6Key;
        String email;

        SignerInfo(String id, VerifyResult vr) {
            this.id = id;
            if (vr instanceof OpenPgpVerifyResult opvr) {
                classifyKey(opvr);
            }
            this.email = GpgRunner.extractEmail(vr.signerDisplayName());
        }

        void merge(VerifyResult vr) {
            if (email == null && vr.signerDisplayName() != null) {
                email = GpgRunner.extractEmail(vr.signerDisplayName());
            }
            if (vr instanceof OpenPgpVerifyResult opvr) {
                classifyKey(opvr);
            }
        }

        private void classifyKey(OpenPgpVerifyResult opvr) {
            String keyId = opvr.preferredKeyId();
            if (keyId == null) {
                return;
            }
            if (opvr.version() >= 6 && pgp6Key == null) {
                pgp6Key = keyId;
            } else if (opvr.version() < 6 && pgp4Key == null) {
                pgp4Key = keyId;
            }
        }
    }
}
