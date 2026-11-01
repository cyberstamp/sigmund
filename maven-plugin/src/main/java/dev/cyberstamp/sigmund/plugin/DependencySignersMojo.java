package dev.cyberstamp.sigmund.plugin;

import dev.cyberstamp.sigmund.core.Algorithms;
import dev.cyberstamp.sigmund.core.ArtifactCoords;
import dev.cyberstamp.sigmund.core.ArtifactPattern;
import dev.cyberstamp.sigmund.core.ClaimSetMode;
import dev.cyberstamp.sigmund.core.Credential;
import dev.cyberstamp.sigmund.core.IdentityCredential;
import dev.cyberstamp.sigmund.core.IndeterminateReason;
import dev.cyberstamp.sigmund.core.IssuerKind;
import dev.cyberstamp.sigmund.core.KeyCredential;
import dev.cyberstamp.sigmund.core.MatchedRule;
import dev.cyberstamp.sigmund.core.OpenPgpVerifyResult;
import dev.cyberstamp.sigmund.core.PolicyConfigException;
import dev.cyberstamp.sigmund.core.Rule;
import dev.cyberstamp.sigmund.core.RulePolicy;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.SigmundSchema;
import dev.cyberstamp.sigmund.core.SignerIdentity;
import dev.cyberstamp.sigmund.core.SigstoreVerifyResult;
import dev.cyberstamp.sigmund.core.TrustPolicy;
import dev.cyberstamp.sigmund.core.VerificationConfig;
import dev.cyberstamp.sigmund.core.VerifyResult;
import dev.cyberstamp.sigmund.plugin.SignatureInspector.SignedArtifact;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringReader;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
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
     * When {@code true}, generates a {@code sigmund.yaml} in the project root
     * in addition to the console report. The generated file can be used directly
     * with the {@code verify} goal. An explicit file path may be provided instead
     * of {@code true} to write to a custom location.
     */
    @Parameter(property = "sigmund.generateTrustConfig")
    private String generateTrustConfig;

    /**
     * When {@code true}, allows overwriting an existing config file.
     * By default, the generation fails if the file already exists.
     */
    @Parameter(property = "sigmund.overwrite", defaultValue = "false")
    private boolean overwrite;

    /**
     * When set, updates an existing {@code sigmund.yaml} by appending
     * any signers and artifacts not already configured. Provide {@code true}
     * to update the default location, or a file path for a custom location.
     */
    @Parameter(property = "sigmund.updateTrustConfig")
    private String updateTrustConfig;

    /** The directory a generated config trusts for the addresses it names signers by. */
    private static final String DIRECTORY = "keys.openpgp.org";
    private static final String DIRECTORY_URL = IssuerKind.KEYS_OPENPGP_ORG;

    private DirectoryLookup directoryLookup;

    /**
     * Sets how an update asks directories for a key's verified addresses.
     *
     * @param lookup the lookup, or {@code null} when directories are not asked
     */
    void directoryLookup(DirectoryLookup lookup) {
        this.directoryLookup = lookup;
    }

    @Override
    public void execute() throws MojoExecutionException {
        if (skip) {
            getLog().info("Skipping dependency signers report");
            return;
        }

        SigmundConfig config = loadConfig();
        VerificationConfig verificationConfig = resolveVerificationConfig(
                config != null ? config.verificationConfig() : VerificationConfig.DEFAULT);
        try (SignatureInspector inspector = buildInspector(verificationConfig,
                mergeToolOverrides(config != null ? config.toolsConfig()
                        : dev.cyberstamp.sigmund.core.ToolsConfig.EMPTY))) {

            List<ArtifactCoords> artifacts = resolveDependencies();
            getLog().info("Inspecting signatures for " + artifacts.size() + " dependency(ies)...");
            getLog().info("");

            List<SignedArtifact> results = inspector.inspectAll(artifacts);
            directoryLookup = verificationConfig.resolveSigners() ? inspector::directoryIdentities : null;

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
    }

    private static String profileKey(VerifyResult vr) {
        int pgpVersion = vr instanceof OpenPgpVerifyResult opvr ? opvr.version() : -1;
        String id = vr.signerIdentifier();
        return pgpVersion + ":" + (id != null ? id : "?");
    }

    void logReport(List<SignedArtifact> results) {

        // Group entries by artifact coordinate
        Map<ArtifactCoords, List<SignedArtifact>> byArtifact = new HashMap<>();
        for (SignedArtifact r : results) {
            byArtifact.computeIfAbsent(r.coords(), k -> new ArrayList<>(2)).add(r);
        }

        // Build signature profile for each artifact and group by shared key sets
        Map<String, List<ArtifactCoords>> profileToCoords = new HashMap<>();
        List<ArtifactCoords> unsignedCoords = new ArrayList<>();

        for (var entry : byArtifact.entrySet()) {
            ArtifactCoords coords = entry.getKey();
            List<SignedArtifact> signers = entry.getValue();

            if (signers.stream().noneMatch(SignedArtifact::hasAttributableClaim)) {
                unsignedCoords.add(coords);
                continue;
            }

            String profile = signers.stream()
                    .filter(SignedArtifact::hasAttributableClaim)
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
        List<Map.Entry<String, List<ArtifactCoords>>> sortedGroups = profileToCoords.entrySet().stream()
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

            List<ArtifactCoords> coordsList = groupEntry.getValue();

            // Pick the richest VerifyResult per key (prefer one with a known signer)
            Map<String, VerifyResult> bestPerKey = new HashMap<>();
            for (ArtifactCoords coords : coordsList) {
                for (SignedArtifact as : byArtifact.get(coords)) {
                    if (!as.hasAttributableClaim()) {
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

            // Sub-group keys by signer: same display name = same signer,
            // no display name = each key is its own signer
            Map<String, List<VerifyResult>> signerSubGroups = new LinkedHashMap<>();
            for (VerifyResult vr : sortedKeys) {
                String key = vr.signerDisplayName() != null
                        ? "name:" + vr.signerDisplayName()
                        : "key:" + (vr.signerIdentifier() != null ? vr.signerIdentifier() : "?");
                signerSubGroups.computeIfAbsent(key, k -> new ArrayList<>(2)).add(vr);
            }

            boolean anyIdentified = false;
            for (var signerSub : signerSubGroups.values()) {
                VerifyResult first = signerSub.get(0);
                boolean identified;
                if (first.signerDisplayName() != null) {
                    getLog().info("Signer: " + first.signerDisplayName());
                    identified = true;
                } else if (signerSub.stream().allMatch(vr -> vr.isIndeterminate(IndeterminateReason.KEY_UNAVAILABLE))) {
                    getLog().warn("Signer: UNKNOWN (key unavailable)");
                    identified = false;
                } else if (signerSub.stream().anyMatch(VerifyResult::isFailed)) {
                    getLog().warn("Signer: VERIFICATION FAILED");
                    identified = false;
                } else {
                    getLog().warn("Signer: NOT VERIFIED");
                    identified = false;
                }
                anyIdentified |= identified;
                for (VerifyResult vr : signerSub) {
                    int pgpVersion = vr instanceof OpenPgpVerifyResult opvr ? opvr.version() : -1;
                    String ver = SignatureInspector.versionLabel(pgpVersion);
                    String keyId = vr.signerIdentifier() != null ? vr.signerIdentifier() : "-";
                    String keyLine = "   " + ver + formatAlgorithm(vr) + ": " + keyId;
                    if (identified) {
                        getLog().info(keyLine);
                    } else {
                        keyLine += formatOutcome(vr);
                        getLog().warn(keyLine);
                    }
                }
            }

            // Print artifacts
            for (ArtifactCoords coords : coordsList) {
                boolean hasFail = byArtifact.get(coords).stream()
                        .anyMatch(SignedArtifact::isFailed);
                String line = "     " + coords;
                if (hasFail) {
                    getLog().error(line + "   (BAD SIGNATURE)");
                } else if (!anyIdentified) {
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
            for (ArtifactCoords coords : unsignedCoords) {
                getLog().warn("  " + coords);
            }
        }

        // Summary statistics
        long totalArtifacts = results.stream().map(SignedArtifact::coords).distinct().count();
        Map<Integer, Long> versionCounts = results.stream()
                .filter(r -> r.verifyResult() instanceof OpenPgpVerifyResult)
                .collect(Collectors.groupingBy(
                        r -> ((OpenPgpVerifyResult) r.verifyResult()).version(),
                        Collectors.counting()));
        long uniqueKeys = results.stream()
                .filter(SignedArtifact::hasClaim)
                .map(r -> r.verifyResult().signerIdentifier())
                .filter(Objects::nonNull)
                .distinct()
                .count();
        long untrusted = results.stream()
                .filter(r -> r.isIndeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM)
                        || r.isFailed())
                .map(SignedArtifact::coords)
                .distinct()
                .count();
        Set<ArtifactCoords> identifiedCoords = results.stream()
                .filter(r -> r.hasClaim() && r.verifyResult().signerDisplayName() != null)
                .map(SignedArtifact::coords)
                .collect(Collectors.toSet());
        long unidentified = results.stream()
                .filter(r -> r.hasAttributableClaim() && !r.isFailed())
                .map(SignedArtifact::coords)
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

        Set<ArtifactCoords> pqCoords = results.stream()
                .filter(r -> r.hasClaim() && Algorithms.isPqcAlgorithmName(r.verifyResult().algorithm()))
                .map(SignedArtifact::coords)
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

    private static String formatOutcome(VerifyResult result) {
        if (result.isFailed()) {
            return " (bad signature)";
        }
        if (!result.isIndeterminate()) {
            return "";
        }
        return switch (result.reason()) {
            case KEY_UNAVAILABLE -> result.reasonDetail() != null
                    ? " (key unavailable: " + result.reasonDetail() + ")"
                    : " (key unavailable)";
            case TRUST_ROOT_UNAVAILABLE -> " (trust root unavailable)";
            case DISCOVERY_UNAVAILABLE -> " (evidence source unreachable)";
            case TOOL_UNAVAILABLE -> " (verification tool unavailable)";
            case UNSUPPORTED_ALGORITHM -> " (unsupported algorithm)";
            case EVIDENCE_MALFORMED -> " (malformed evidence)";
        };
    }

    private static String firstSigner(List<ArtifactCoords> coordsList,
            Map<ArtifactCoords, List<SignedArtifact>> byArtifact) {
        for (ArtifactCoords coords : coordsList) {
            for (SignedArtifact as : byArtifact.get(coords)) {
                if (as.hasClaim() && as.verifyResult().signerDisplayName() != null) {
                    return as.verifyResult().signerDisplayName();
                }
            }
        }
        return null;
    }

    /**
     * Resolves the config output file. If the parameter value is {@code "true"},
     * defaults to {@code sigmund.yaml} in the project root; otherwise treats
     * the value as a file path.
     */
    private File resolveTrustConfigFile(String param) {
        if ("true".equalsIgnoreCase(param)) {
            return new File(project.getBasedir(), "sigmund.yaml");
        }
        return new File(param);
    }

    /**
     * Writes a {@code sigmund.yaml} file from the inspection results.
     * Artifacts are grouped by signer, with common groupId prefixes collapsed
     * into wildcard patterns. Versions are stripped from trust patterns. The first line points
     * YAML editors at the schema of this Sigmund version, so the file is reviewed and edited
     * with completion and unknown-key errors. A signer whose key the directory has verified an
     * address for is named by that address too, and the directory is then listed under
     * {@code issuers} — trust stated in the file, where the review sees it.
     */
    void writeTrustConfigYaml(List<SignedArtifact> results, File configFile)
            throws MojoExecutionException {
        if (configFile.exists() && !overwrite) {
            throw new MojoExecutionException(
                    "Trust config file already exists: " + configFile.getAbsolutePath()
                            + ". Use -Dsigmund.overwrite=true to overwrite.");
        }

        Map<ArtifactCoords, List<SignedArtifact>> byArtifact = new HashMap<>();
        for (SignedArtifact r : results) {
            byArtifact.computeIfAbsent(r.coords(), k -> new ArrayList<>(2)).add(r);
        }

        Map<String, SignerInfo> signersByKey = new LinkedHashMap<>();
        Map<String, Set<String>> artifactSigners = new LinkedHashMap<>();
        List<String> unsignedModulePatterns = new ArrayList<>();
        int signerCounter = 0;

        for (var entry : byArtifact.entrySet()) {
            ArtifactCoords coords = entry.getKey();
            List<SignedArtifact> sigEntries = entry.getValue();

            boolean allUnsigned = sigEntries.stream()
                    .noneMatch(SignedArtifact::hasAttributableClaim);
            if (allUnsigned) {
                unsignedModulePatterns.add(ArtifactPattern.forModule(coords).toString());
                continue;
            }

            String strippedCoords = ArtifactPattern.forModule(coords).toString();
            for (SignedArtifact sa : sigEntries) {
                if (!sa.hasAttributableClaim()) {
                    continue;
                }
                VerifyResult vr = sa.verifyResult();
                if (vr.signerIdentifier() == null) {
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

        combineCoSigningKeys(signersByKey, List.of(artifactSigners));
        dropSignersWithoutCredentials(List.of(artifactSigners), signersByKey);
        attachDirectoryAddresses(signersByKey.values());
        boolean directoryTrusted = signersByKey.values().stream().anyMatch(info -> info.directoryAddress != null);
        Map<String, List<String>> trustPatterns = TrustPatternCollapse.collapse(artifactSigners);

        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(configFile.toPath()))) {
            w.println(SigmundSchema.modeline());
            if (directoryTrusted) {
                w.println("issuers: [" + DIRECTORY + "]");
                w.println();
            }
            writeSignersSection(w, signersByKey, directoryTrusted);
            writeRulesSection(w, trustPatterns, unsignedModulePatterns);
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
     * Updates an existing config from the inspection results, adding what it does not cover yet
     * and listing what only a person should change.
     *
     * <p>
     * An artifact is a candidate when no rule matches it or the rule that does names no signer —
     * a catch-all, or the rule that tolerated it unsigned. An unsigned candidate with no rule
     * joins the tolerant rule; a signed one gets a requirement on the signers that signed it, and
     * when the tolerant rule lists its module it is moved out of that list, since the identical
     * pattern in two rules would tie. An artifact under a rule with requirements is never
     * rewritten: a signature from a signer that rule does not name is exactly the change
     * verification exists to catch, so it is listed for review instead. The updated text is
     * parsed and compiled before it is written, and nothing is written if it would not load.
     *
     * @param results the inspection results
     * @param configFile the config to update in place
     * @throws MojoExecutionException when the config is missing, does not load, or would not
     *         load once updated
     */
    void updateExistingTrustConfig(List<SignedArtifact> results, File configFile)
            throws MojoExecutionException {
        if (!configFile.exists()) {
            throw new MojoExecutionException(
                    "Config file not found: " + configFile.getAbsolutePath()
                            + ". Use -Dsigmund.generateTrustConfig to create one first.");
        }
        List<String> lines = readConfigLines(configFile);
        SigmundConfig existing = loadUpdatable(configFile.getPath(), lines);
        TrustPolicy trustPolicy = compileUpdatable(configFile.getPath(), existing);

        UpdatePlan plan = new UpdatePlan(existing);
        groupByArtifact(results).forEach((coords, entries) -> plan.consider(coords, entries,
                trustPolicy.matchRule(coords), trustPolicy.issuers()));
        plan.moveOutOfTolerantRules(lines);
        plan.review.addAll(plan.rotationPins.apply(lines));
        combineCoSigningKeys(plan.newSigners,
                List.of(plan.newArtifactSigners, plan.movedArtifactSigners));
        dropSignersWithoutCredentials(
                List.of(plan.newArtifactSigners, plan.movedArtifactSigners), plan.newSigners);

        if (plan.isEmpty()) {
            logReview(plan.review);
            getLog().info("Trust configuration is already up to date.");
            return;
        }
        logPinned(plan.rotationPins.applied());

        spliceRules(lines, plan.newTrustPatterns(), plan.newUnsigned);
        Map<String, SignerInfo> addedSigners = plan.referencedSigners();
        attachDirectoryAddresses(addedSigners.values());
        spliceSigners(lines, addedSigners, existing.trustPolicySpec().issuers().contains(DIRECTORY_URL));
        compileUpdatable(configFile.getPath() + " (as updated)",
                loadUpdatable(configFile.getPath() + " (as updated)", lines));
        writeConfigLines(configFile, lines);

        logReview(plan.review);
        getLog().info("");
        getLog().info("Trust configuration updated: " + configFile.getPath());
        getLog().info("Review changes with: git diff " + configFile.getName());
    }

    private static Map<ArtifactCoords, List<SignedArtifact>> groupByArtifact(
            List<SignedArtifact> results) {
        Map<ArtifactCoords, List<SignedArtifact>> byArtifact = new LinkedHashMap<>();
        for (SignedArtifact r : results) {
            byArtifact.computeIfAbsent(r.coords(), k -> new ArrayList<>(2)).add(r);
        }
        return byArtifact;
    }

    private static List<String> readConfigLines(File configFile) throws MojoExecutionException {
        try {
            return new ArrayList<>(Files.readAllLines(configFile.toPath()));
        } catch (IOException e) {
            throw new MojoExecutionException("Failed to read trust config: " + configFile, e);
        }
    }

    private static void writeConfigLines(File configFile, List<String> lines)
            throws MojoExecutionException {
        try {
            Files.write(configFile.toPath(), lines);
        } catch (IOException e) {
            throw new MojoExecutionException("Failed to update trust config: " + configFile, e);
        }
    }

    private static SigmundConfig loadUpdatable(String source, List<String> lines)
            throws MojoExecutionException {
        try {
            return SigmundConfig.parse(source, new StringReader(String.join("\n", lines)));
        } catch (PolicyConfigException e) {
            throw new MojoExecutionException("Failed to parse config " + source + ": "
                    + e.getMessage(), e);
        }
    }

    private static TrustPolicy compileUpdatable(String source, SigmundConfig config)
            throws MojoExecutionException {
        try {
            return RulePolicy.compile(config.trustPolicySpec(), config.signers());
        } catch (PolicyConfigException e) {
            throw new MojoExecutionException("Config " + source + " does not load: "
                    + e.getMessage(), e);
        }
    }

    private void logPinned(List<RotationPins.Pin> pinned) {
        if (pinned.isEmpty()) {
            return;
        }
        getLog().info("");
        getLog().info("Rotated keys pinned (" + pinned.size() + "):");
        pinned.forEach(pin -> getLog().info("  " + pin.describe()));
    }

    private void logReview(List<String> review) {
        if (review.isEmpty()) {
            return;
        }
        getLog().warn("");
        getLog().warn("Needs review (" + review.size() + "), left unchanged:");
        review.forEach(line -> getLog().warn("  " + line));
    }

    /**
     * What one update adds to a config, and what it leaves for a person to decide.
     */
    private final class UpdatePlan {

        final Map<String, SignerInfo> newSigners = new LinkedHashMap<>();
        final Map<String, Set<String>> newArtifactSigners = new LinkedHashMap<>();
        final Map<String, Set<String>> movedArtifactSigners = new LinkedHashMap<>();
        final List<String> newUnsigned = new ArrayList<>();
        final List<String> review = new ArrayList<>();
        final RotationPins rotationPins = new RotationPins(directoryLookup);
        private final Map<Integer, Set<String>> leavingTolerantRule = new TreeMap<>(
                Comparator.reverseOrder());
        private final Map<Integer, String> tolerantRuleNames = new HashMap<>();
        private final SigmundConfig existing;
        private int signerCounter;

        UpdatePlan(SigmundConfig existing) {
            this.existing = existing;
            this.signerCounter = existing.signers().names().size();
        }

        void consider(ArtifactCoords coords, List<SignedArtifact> entries, Rule rule,
                List<String> issuers) {
            String module = ArtifactPattern.forModule(coords).toString();
            if (rule != null && !rule.requirement().clauses().isEmpty()) {
                reviewUnnamedSigner(coords, module, entries, rule, issuers);
                return;
            }
            if (entries.stream().noneMatch(SignedArtifact::hasAttributableClaim)) {
                if (rule == null) {
                    newUnsigned.add(module);
                }
                return;
            }
            if (rule == null) {
                recordSigners(entries, module, newArtifactSigners);
                return;
            }
            recordSigners(entries, module, movedArtifactSigners);
            if (rule.patterns().contains(ArtifactPattern.parse(module))) {
                int index = RuleListEditor.ruleIndex(rule.location());
                leavingTolerantRule.computeIfAbsent(index, i -> new LinkedHashSet<>()).add(module);
                tolerantRuleNames.put(index, rule.location());
            }
        }

        /**
         * Lists for review the credentials an artifact proved that its rule does not name, after
         * pinning those a directory confirms for a required signer. It mirrors the roll-up:
         * under {@code extra-claims: reject} every verified claim must be accepted, so each
         * unnamed credential is a change; under {@code ignore} one accepted claim is enough.
         */
        private void reviewUnnamedSigner(ArtifactCoords coords, String module,
                List<SignedArtifact> entries, Rule rule, List<String> issuers) {
            List<Credential> proven = provenCredentials(entries).stream().distinct().toList();
            List<Credential> unnamed = proven.stream()
                    .filter(credential -> !namesAny(rule, List.of(credential), issuers))
                    .toList();
            boolean anyAccepted = unnamed.size() < proven.size();
            if (unnamed.isEmpty() || anyAccepted && rule.extraClaims() == ClaimSetMode.ANY_CLAIM) {
                return;
            }
            List<Credential> left = new ArrayList<>();
            StringBuilder note = new StringBuilder();
            List<RotationPins.Pin> pinnedHere = new ArrayList<>();
            for (Credential credential : unnamed) {
                if (credential instanceof KeyCredential key) {
                    String pinNote = rotationPins.pin(module, key, rule, issuers);
                    if (pinNote == null) {
                        anyAccepted = true;
                        pinnedHere.add(rotationPins.pinned(key, rule));
                        continue;
                    }
                    if (note.indexOf(pinNote) < 0) {
                        note.append(pinNote);
                    }
                }
                left.add(credential);
            }
            if (left.isEmpty() || anyAccepted && rule.extraClaims() == ClaimSetMode.ANY_CLAIM) {
                return;
            }
            pinnedHere.forEach(pin -> note.append(pin.alongside()));
            String signers = rule.requirement().clauses().stream()
                    .flatMap(clause -> clause.signers().stream())
                    .map(SignerIdentity::id)
                    .distinct()
                    .collect(Collectors.joining(", "));
            String provenNames = left.stream()
                    .map(credential -> credential.type() + " " + credential.displayName())
                    .collect(Collectors.joining(", "));
            MatchedRule matched = rule.toMatchedRule(coords);
            review.add(module + " — signed by " + provenNames + ", but " + matched.location()
                    + " '" + matched.pattern() + "' requires [" + signers + "]" + note);
        }

        private void recordSigners(List<SignedArtifact> entries, String module,
                Map<String, Set<String>> target) {
            for (SignedArtifact sa : entries) {
                if (!sa.hasAttributableClaim() || sa.verifyResult().signerIdentifier() == null) {
                    continue;
                }
                target.computeIfAbsent(module, k -> new LinkedHashSet<>())
                        .add(signerIdFor(sa.verifyResult()));
            }
        }

        /**
         * Names the signer of a result: a signer the config already defines with the key or
         * identity it proved, otherwise a new one, so that an update never defines the same
         * signer twice.
         */
        private String signerIdFor(VerifyResult vr) {
            String existingId = existingSignerProving(provenCredentials(vr));
            if (existingId != null) {
                return existingId;
            }
            String key = vr.signerIdentifier();
            SignerInfo info = newSigners.get(key);
            if (info == null) {
                signerCounter++;
                info = new SignerInfo(resolveUniqueSignerId(vr, signerCounter, newSigners,
                        existing.signers().names()), vr);
                newSigners.put(key, info);
            } else {
                info.merge(vr);
            }
            return info.id;
        }

        private String existingSignerProving(List<Credential> proven) {
            for (String id : existing.signers().names()) {
                for (Credential expected : existing.signers().get(id).credentials()) {
                    if (proven.stream().anyMatch(expected::matches)) {
                        return id;
                    }
                }
            }
            return null;
        }

        /**
         * Moves modules that started being signed out of the rules that tolerated them unsigned.
         * A rule whose list cannot be edited is left as written, and its modules are listed for
         * review instead of gaining a requirement that would tie with it.
         */
        void moveOutOfTolerantRules(List<String> lines) {
            leavingTolerantRule.forEach((index, modules) -> {
                if (!RuleListEditor.removeFromMatch(lines, index, modules)) {
                    for (String module : modules) {
                        movedArtifactSigners.remove(module);
                        review.add(module + " — now signed, but listed in "
                                + tolerantRuleNames.get(index)
                                + ", which update cannot edit; move it out of that rule by hand");
                    }
                }
            });
        }

        Map<String, List<String>> newTrustPatterns() {
            Map<String, List<String>> patterns = new LinkedHashMap<>(
                    TrustPatternCollapse.collapse(newArtifactSigners));
            movedArtifactSigners.forEach((module, ids) -> patterns.put(module, List.copyOf(ids)));
            return patterns;
        }

        Map<String, SignerInfo> referencedSigners() {
            Set<String> referenced = new HashSet<>();
            newArtifactSigners.values().forEach(referenced::addAll);
            movedArtifactSigners.values().forEach(referenced::addAll);
            Map<String, SignerInfo> signers = new LinkedHashMap<>(newSigners);
            signers.values().removeIf(info -> !referenced.contains(info.id));
            return signers;
        }

        boolean isEmpty() {
            return newArtifactSigners.isEmpty() && movedArtifactSigners.isEmpty()
                    && newUnsigned.isEmpty() && rotationPins.applied().isEmpty();
        }
    }

    private static boolean namesAny(Rule rule, List<Credential> proven, List<String> issuers) {
        return rule.requirement().clauses().stream()
                .flatMap(clause -> clause.signers().stream())
                .flatMap(signer -> signer.credentials().stream())
                .anyMatch(expected -> proven.stream().anyMatch(credential -> expected instanceof IdentityCredential identity
                        ? identity.matches(credential, issuers)
                        : expected.matches(credential)));
    }

    private static List<Credential> provenCredentials(List<SignedArtifact> entries) {
        List<Credential> proven = new ArrayList<>();
        for (SignedArtifact sa : entries) {
            if (sa.isVerified()) {
                proven.addAll(provenCredentials(sa.verifyResult()));
            }
        }
        return proven;
    }

    /**
     * The credentials a verified result proves, as bootstrap would record them: the full
     * fingerprint of an OpenPGP key, or the identity in a Sigstore certificate.
     */
    private static List<Credential> provenCredentials(VerifyResult vr) {
        if (vr instanceof OpenPgpVerifyResult opvr) {
            String fingerprint = SignerInfo.fullFingerprint(opvr);
            return fingerprint == null ? List.of()
                    : List.of(new KeyCredential(
                            opvr.version() >= 6 ? Credential.TYPE_PGP6 : Credential.TYPE_PGP4,
                            fingerprint));
        }
        if (vr instanceof SigstoreVerifyResult svr && svr.identity() != null) {
            return List.of(svr.identity());
        }
        return List.of();
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

    /**
     * Appends new signers to the {@code signers} section. A directory address is written as
     * {@code email:} when the file already trusts the directory, and otherwise as an
     * {@code identities} entry naming it, so that adding a signer never widens what the file's
     * {@code issuers} vouch for.
     */
    private void spliceSigners(List<String> lines, Map<String, SignerInfo> newSigners,
            boolean directoryTrusted) {
        if (newSigners.isEmpty()) {
            return;
        }
        List<String> newLines = new ArrayList<>();
        newSigners.values().stream()
                .sorted(Comparator.comparing(i -> i.id, String.CASE_INSENSITIVE_ORDER))
                .forEach(info -> appendSignerYaml(info, "  ", newLines::add, directoryTrusted));
        insertAtSectionEnd(lines, "signers", newLines);
    }

    /**
     * Splices new rule items into the existing {@code rules} section.
     * <p>
     * Both the newly discovered signer requirements and the newly discovered unsigned modules are
     * expressed as {@code rules} items, matching the generate path's schema, so an updated config
     * round-trips through the parser. When the config has no {@code rules} section yet, one is
     * appended with these items.
     *
     * @param lines the config file lines, mutated in place
     * @param newTrustPatterns artifact patterns mapped to the signer ids that must sign them
     * @param newUnsigned module patterns tolerated via {@code on-no-claim: ignore}
     */
    private void spliceRules(List<String> lines, Map<String, List<String>> newTrustPatterns,
            List<String> newUnsigned) {
        List<String> newLines = buildRuleLines(newTrustPatterns, newUnsigned);
        if (newLines.isEmpty()) {
            return;
        }
        insertAtSectionEnd(lines, "rules", newLines);
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

    private void writeSignersSection(PrintWriter w, Map<String, SignerInfo> signersByKey,
            boolean directoryTrusted) {
        if (signersByKey.isEmpty()) {
            return;
        }
        w.println("signers:");
        List<SignerInfo> sorted = signersByKey.values().stream()
                .sorted(Comparator.comparing(i -> i.id, String.CASE_INSENSITIVE_ORDER))
                .toList();
        for (SignerInfo info : sorted) {
            appendSignerYaml(info, "  ", w::println, directoryTrusted);
        }
        w.println();
    }

    /**
     * Writes the {@code rules} section for a freshly generated config.
     * <p>
     * A single {@code rules:} header is emitted exactly once, followed by every rule item: first the
     * signer requirements derived from the trust patterns, then a tolerant rule for the unsigned
     * modules. When there is nothing to write — neither trust patterns nor unsigned modules — the
     * section is omitted entirely so the output never carries an orphaned header.
     *
     * @param w the writer
     * @param trustPatterns artifact patterns mapped to the signer ids that must sign them
     * @param unsignedCoords module patterns tolerated via {@code on-no-claim: ignore}
     */
    private void writeRulesSection(PrintWriter w, Map<String, List<String>> trustPatterns,
            List<String> unsignedCoords) {
        List<String> ruleLines = buildRuleLines(trustPatterns, unsignedCoords);
        if (ruleLines.isEmpty()) {
            return;
        }
        w.println("rules:");
        ruleLines.forEach(w::println);
        w.println();
    }

    /**
     * Builds the rule item lines shared by the generate and update paths.
     * <p>
     * The ordering is stable: trust requirements first (sorted by pattern), then a single tolerant
     * rule for the unsigned modules. Each item is a two-space-indented {@code - match:} entry, so the
     * lines slot directly under a {@code rules:} header. A requirement's single pattern, and a
     * single required signer, are written as strings; the unsigned modules' rule keeps a flow list
     * of any length, the shape {@link RuleListEditor} edits when one of them starts being signed.
     *
     * @param trustPatterns artifact patterns mapped to the signer ids that must sign them
     * @param unsignedCoords module patterns tolerated via {@code on-no-claim: ignore}
     * @return the rule item lines, empty when there is nothing to write
     */
    private static List<String> buildRuleLines(Map<String, List<String>> trustPatterns,
            List<String> unsignedCoords) {
        List<String> ruleLines = new ArrayList<>();
        trustPatterns.entrySet().stream()
                .sorted(Map.Entry.comparingByKey(String.CASE_INSENSITIVE_ORDER))
                .forEach(entry -> {
                    ruleLines.add("  - match: " + entry.getKey());
                    ruleLines.add("    requires: " + stringOrFlowList(entry.getValue()));
                });
        if (!unsignedCoords.isEmpty()) {
            ruleLines.add("  - match: [" + unsignedCoords.stream().distinct().sorted()
                    .collect(Collectors.joining(", ")) + "]");
            ruleLines.add("    on-no-claim: ignore");
        }
        return ruleLines;
    }

    /**
     * Writes a single value as a string and several as a flow list, the way a person would write
     * them.
     */
    private static String stringOrFlowList(List<String> values) {
        return values.size() == 1 ? values.get(0) : "[" + String.join(", ", values) + "]";
    }

    /**
     * Combines a publisher's classic and post-quantum keys into one signer.
     *
     * <p>
     * Two keys are one publisher's when they carry the same user ID, one is a v4 and the other
     * a v6 key, and they signed exactly the same artifacts — a hybrid {@code .asc} carries both
     * signatures. As one signer, either key's signature satisfies its rule, so a verifier that
     * cannot check the post-quantum signature still reaches a verdict on the classic one; every
     * signature that is present must still verify. User IDs are unverified, so a matching one
     * alone never combines keys: keys that sign different artifacts stay separate, or a stranger's
     * key carrying the same address would be accepted wherever the publisher is. Keys that sign
     * together under different user IDs are different parties, and stay separate signers that
     * are all required.
     *
     * @param signersByKey the signers observed, keyed by signing key; combined ones are removed
     * @param artifactSignerMaps module patterns mapped to the signer IDs that signed them,
     *        rewritten to name the combined signer
     */
    private static void combineCoSigningKeys(Map<String, SignerInfo> signersByKey,
            List<Map<String, Set<String>>> artifactSignerMaps) {
        Map<String, Set<String>> modulesBySigner = new HashMap<>();
        for (Map<String, Set<String>> artifactSigners : artifactSignerMaps) {
            artifactSigners.forEach((module, ids) -> ids.forEach(id -> modulesBySigner
                    .computeIfAbsent(id, k -> new HashSet<>()).add(module)));
        }
        List<SignerInfo> signers = new ArrayList<>(signersByKey.values());
        for (SignerInfo kept : signers) {
            for (SignerInfo other : signers) {
                if (kept != other && signersByKey.containsValue(kept) && signersByKey.containsValue(other)
                        && kept.complements(other)
                        && Objects.equals(modulesBySigner.get(kept.id), modulesBySigner.get(other.id))) {
                    kept.absorb(other);
                    signersByKey.values().remove(other);
                    renameSigner(artifactSignerMaps, other.id, kept.id);
                }
            }
        }
    }

    private static void renameSigner(List<Map<String, Set<String>>> artifactSignerMaps,
            String from, String to) {
        for (Map<String, Set<String>> artifactSigners : artifactSignerMaps) {
            for (Set<String> ids : artifactSigners.values()) {
                if (ids.remove(from)) {
                    ids.add(to);
                }
            }
        }
    }

    /**
     * Removes signers that proved no usable credential — only a key ID, or only a user ID —
     * from the trust mappings, so the generated config never names a signer it does not
     * define. Their artifacts are left without a mapping and are reported as not configured.
     * A signer an update reuses from the config is not among them and stays mapped.
     */
    private void dropSignersWithoutCredentials(List<Map<String, Set<String>>> artifactSignerMaps,
            Map<String, SignerInfo> signersByKey) {
        Set<String> unusable = new HashSet<>();
        for (SignerInfo info : signersByKey.values()) {
            if (!info.hasCredentials()) {
                unusable.add(info.id);
                getLog().warn("Signer " + info.id + " proved no full fingerprint or verified "
                        + "identity and is left out of the config");
            }
        }
        for (Map<String, Set<String>> artifactSigners : artifactSignerMaps) {
            artifactSigners.values().forEach(ids -> ids.removeAll(unusable));
            artifactSigners.values().removeIf(Set::isEmpty);
        }
    }

    private static void appendSignerYaml(SignerInfo info, String indent, Consumer<String> out,
            boolean directoryTrusted) {
        if (!info.hasCredentials()) {
            return;
        }
        out.accept(indent + info.id + ":");
        String comment = namedByAddressOnKey(info) ? "" : userIdComment(info.userId);
        if (info.pgp4Key != null) {
            out.accept(indent + "  pgp4: \"" + info.pgp4Key + "\"" + comment);
        }
        if (info.pgp6Key != null) {
            out.accept(indent + "  pgp6: \"" + info.pgp6Key + "\"" + comment);
        }
        List<IdentityCredential> identities = new ArrayList<>();
        if (info.emailIdentity != null) {
            identities.add(info.emailIdentity);
        }
        if (info.directoryAddress != null) {
            if (directoryTrusted) {
                out.accept(indent + "  email: \"" + info.directoryAddress + "\"");
            } else {
                identities.add(IdentityCredential.email(DIRECTORY_URL, info.directoryAddress));
            }
        }
        if (!identities.isEmpty()) {
            out.accept(indent + "  identities:");
            for (IdentityCredential identity : identities) {
                out.accept(indent + "    - issuer: \"" + identity.issuer() + "\"");
                out.accept(indent + "      email: \"" + identity.attribute(IdentityCredential.EMAIL) + "\"");
            }
        }
    }

    /**
     * Asks the directory which addresses it has verified for each signer's keys, and names the
     * signer by one of them: the address in the key's user ID when the directory verified it,
     * otherwise the first. The address accepts keys the publisher rotates to; the fingerprints
     * keep proving the keys already seen. Without directory lookups, or when the directory
     * cannot be reached, signers are named by fingerprint only.
     */
    private void attachDirectoryAddresses(Collection<SignerInfo> signers) {
        if (directoryLookup == null) {
            return;
        }
        for (SignerInfo info : signers) {
            List<String> addresses = new ArrayList<>();
            for (String fingerprint : info.keys()) {
                addresses.addAll(verifiedAddresses(info, fingerprint));
            }
            info.directoryAddress = preferredAddress(addresses.stream().distinct().toList(), info.userId);
        }
    }

    private List<String> verifiedAddresses(SignerInfo info, String fingerprint) {
        try {
            return directoryLookup.identities(KeyCredential.openPgp(fingerprint), List.of(DIRECTORY_URL))
                    .stream().map(identity -> identity.attribute(IdentityCredential.EMAIL)).toList();
        } catch (IOException e) {
            getLog().warn("Could not ask " + DIRECTORY + " for the addresses verified for " + fingerprint
                    + ": " + e.getMessage() + "; signer " + info.id + " is named by fingerprint only");
            return List.of();
        }
    }

    private static String preferredAddress(List<String> addresses, String userId) {
        if (addresses.isEmpty()) {
            return null;
        }
        String onKey = addressOnKey(userId);
        return addresses.stream().filter(address -> address.equalsIgnoreCase(onKey)).findFirst()
                .orElse(addresses.get(0));
    }

    /**
     * Whether the signer is named by the very address its key's user ID shows. Its
     * {@code email:} line then says what the user ID would, and verified, so the user ID comment
     * is left out rather than calling the same address unverified.
     */
    private static boolean namedByAddressOnKey(SignerInfo info) {
        return info.directoryAddress != null && info.directoryAddress.equalsIgnoreCase(addressOnKey(info.userId));
    }

    private static String addressOnKey(String userId) {
        return userId == null ? null : userId.replaceFirst("^.*<([^>]*)>.*$", "$1");
    }

    /**
     * Shows the user ID a key carries as a comment on its fingerprint, never as config: it is
     * self-certified, so it helps a reviewer recognize the key but proves nothing. It is left out
     * for a signer named by the address it shows, which the directory verified.
     */
    private static String userIdComment(String userId) {
        return userId == null ? "" : "  # user ID on the key, unverified: " + userId.replaceAll("\\R", " ");
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
        Set<String> taken = new HashSet<>(reservedIds);
        existingSigners.values().forEach(i -> taken.add(i.id));
        while (taken.contains(candidate)) {
            candidate = base + "-" + suffix++;
        }
        return candidate;
    }

    /**
     * What bootstrap records about one signer.
     *
     * <p>
     * Only what a verified signature proves becomes a credential: full key fingerprints —
     * the primary key's where known, since that is what stays stable across signing subkeys —
     * and an email identity together with the issuer that vouched for it, which today comes
     * from a Sigstore certificate. A user ID on an OpenPGP key is self-certified, so it is
     * written as a comment for the reviewer and nothing more.
     */
    static class SignerInfo {
        final String id;
        String pgp4Key;
        String pgp6Key;
        String userId;
        IdentityCredential emailIdentity;
        String directoryAddress;

        SignerInfo(String id, VerifyResult vr) {
            this.id = id;
            merge(vr);
        }

        void merge(VerifyResult vr) {
            if (userId == null && vr instanceof OpenPgpVerifyResult) {
                userId = vr.signerDisplayName();
            }
            if (vr instanceof OpenPgpVerifyResult opvr) {
                classifyKey(opvr);
            } else if (vr instanceof SigstoreVerifyResult svr && emailIdentity == null) {
                emailIdentity = emailOf(svr.identity());
            }
        }

        boolean hasCredentials() {
            return pgp4Key != null || pgp6Key != null || emailIdentity != null;
        }

        List<String> keys() {
            List<String> keys = new ArrayList<>(2);
            if (pgp4Key != null) {
                keys.add(pgp4Key);
            }
            if (pgp6Key != null) {
                keys.add(pgp6Key);
            }
            return keys;
        }

        /**
         * Whether this and another signer are one publisher's classic and post-quantum keys:
         * the same user ID, and one holding only a v4 key where the other holds only a v6 key.
         */
        boolean complements(SignerInfo other) {
            boolean versionsComplement = pgp4Key != null && pgp6Key == null
                    && other.pgp6Key != null && other.pgp4Key == null
                    || pgp6Key != null && pgp4Key == null
                            && other.pgp4Key != null && other.pgp6Key == null;
            return userId != null && userId.equals(other.userId) && versionsComplement
                    && emailIdentity == null && other.emailIdentity == null;
        }

        /**
         * Takes over the key another signer holds, which {@link #complements} has checked.
         */
        void absorb(SignerInfo other) {
            if (pgp4Key == null) {
                pgp4Key = other.pgp4Key;
            }
            if (pgp6Key == null) {
                pgp6Key = other.pgp6Key;
            }
        }

        private static IdentityCredential emailOf(IdentityCredential identity) {
            return identity != null && identity.attribute(IdentityCredential.EMAIL) != null
                    ? IdentityCredential.email(identity.issuer(),
                            identity.attribute(IdentityCredential.EMAIL))
                    : null;
        }

        private void classifyKey(OpenPgpVerifyResult opvr) {
            String fingerprint = fullFingerprint(opvr);
            if (fingerprint == null) {
                return;
            }
            if (opvr.version() >= 6 && pgp6Key == null) {
                pgp6Key = fingerprint;
            } else if (opvr.version() < 6 && pgp4Key == null) {
                pgp4Key = fingerprint;
            }
        }

        private static String fullFingerprint(OpenPgpVerifyResult opvr) {
            if (KeyCredential.isOpenPgpFingerprint(opvr.primaryFingerprint())) {
                return opvr.primaryFingerprint();
            }
            return KeyCredential.isOpenPgpFingerprint(opvr.fingerprint()) ? opvr.fingerprint() : null;
        }
    }
}
