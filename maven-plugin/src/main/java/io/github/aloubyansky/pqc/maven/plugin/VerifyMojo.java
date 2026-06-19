package io.github.aloubyansky.pqc.maven.plugin;

import io.github.aloubyansky.pqc.maven.core.SignatureInfo;
import io.github.aloubyansky.pqc.maven.core.VerificationResult;
import io.github.aloubyansky.pqc.maven.plugin.SignatureInspector.SignedArtifact;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

/**
 * Verifies that all project dependencies are signed by trusted signers as defined
 * in a {@code trust-config.yaml} file.
 * <p>
 * For each dependency, signatures are inspected and matched against the configured
 * trust mappings. Matching is done by GPG/PQC fingerprint when available, falling
 * back to signer user ID matching. Artifacts in the {@code unsigned} section are
 * skipped. Artifacts not matching any trust pattern cause the build to fail or warn,
 * depending on the configured policy.
 *
 * @see TrustConfig
 * @see TrustConfigParser
 * @see SignatureInspector
 */
@Mojo(name = "verify", defaultPhase = LifecyclePhase.VALIDATE, threadSafe = true)
public class VerifyMojo extends AbstractDependencyMojo {

    /**
     * Policy when an artifact is signed by an untrusted signer: {@code fail} or {@code warn}.
     * Overrides the {@code on-untrusted} setting in the trust config file.
     */
    @Parameter(property = "pqc.onUntrusted")
    private String onUntrusted;

    /**
     * When {@code true}, all present signatures must verify. When {@code false},
     * one verified trusted signature is sufficient.
     * Overrides the {@code verify-all-signatures} setting in the trust config file.
     */
    @Parameter(property = "pqc.verifyAllSignatures")
    private Boolean verifyAllSignatures;

    /**
     * When {@code true}, also verifies signatures on POM files for each dependency.
     */
    @Parameter(property = "pqc.verifyPomFiles", defaultValue = "false")
    private boolean verifyPomFiles;

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        if (skip) {
            getLog().info("Skipping signature verification");
            return;
        }

        TrustConfig config = loadConfig();
        TrustConfig.Settings settings = mergeSettings(config.settings());

        List<ArtifactCoords> artifacts = resolveDependencies();
        getLog().info("Verifying signers for " + artifacts.size() + " dependency(ies)...");

        ArtifactMatcher matcher = new ArtifactMatcher(config);

        List<ArtifactCoords> toInspect = new ArrayList<>();
        List<ArtifactCoords> unmatchedArtifacts = new ArrayList<>();
        List<String> skippedCoords = new ArrayList<>();
        Map<String, List<String>> matchedSignerRefs = new HashMap<>();

        classifyArtifacts(artifacts, matcher, toInspect, skippedCoords,
                unmatchedArtifacts, matchedSignerRefs);

        if (verifyPomFiles) {
            addPomArtifacts(toInspect, matchedSignerRefs);
            addPomArtifacts(unmatchedArtifacts, null);
        }

        VerificationState state = new VerificationState(
                "fail".equals(settings.onUntrusted()), settings.verifyAllSignatures(), config);

        SignatureInspector inspector = !toInspect.isEmpty() || !unmatchedArtifacts.isEmpty()
                ? buildInspector(settings)
                : null;

        if (inspector != null && !toInspect.isEmpty()) {
            List<SignedArtifact> inspected = inspector.inspectAll(toInspect);
            verifySignatures(inspected, matchedSignerRefs, config, state);
        }

        if (inspector != null && !unmatchedArtifacts.isEmpty()) {
            classifyUnmatched(inspector, unmatchedArtifacts, state);
        }

        reportResults(state, skippedCoords);
        failIfNeeded(state);
    }

    /**
     * Classifies each artifact as unsigned-allowed, trust-matched, or unmatched.
     */
    private void classifyArtifacts(List<ArtifactCoords> artifacts, ArtifactMatcher matcher,
            List<ArtifactCoords> toInspect, List<String> skippedCoords,
            List<ArtifactCoords> unmatchedArtifacts,
            Map<String, List<String>> matchedSignerRefs) {
        for (ArtifactCoords artifact : artifacts) {
            String coords = artifact.toString();

            if (matcher.isUnsigned(artifact)) {
                skippedCoords.add(coords);
                continue;
            }

            List<String> signerRefs = matcher.findTrustedSignerRefs(artifact);
            if (signerRefs == null) {
                unmatchedArtifacts.add(artifact);
            } else {
                matchedSignerRefs.put(coords, signerRefs);
                toInspect.add(artifact);
            }
        }
    }

    /**
     * For each artifact in the list, creates a corresponding POM artifact and adds it
     * to the same list. If matchedSignerRefs is provided, the POM inherits the same
     * signer refs as the original artifact.
     */
    void addPomArtifacts(List<ArtifactCoords> artifacts,
            Map<String, List<String>> matchedSignerRefs) {
        List<ArtifactCoords> poms = new ArrayList<>();
        for (ArtifactCoords artifact : artifacts) {
            if ("pom".equals(artifact.type())) {
                continue;
            }
            ArtifactCoords pom = new ArtifactCoords(
                    artifact.groupId(), artifact.artifactId(), "", "pom", artifact.version());
            poms.add(pom);
            if (matchedSignerRefs != null) {
                String origCoords = artifact.toString();
                List<String> refs = matchedSignerRefs.get(origCoords);
                if (refs != null) {
                    matchedSignerRefs.put(pom.toString(), refs);
                }
            }
        }
        artifacts.addAll(poms);
    }

    /**
     * Inspects unmatched artifacts and classifies them as unsigned (no signature
     * present) or signed but unconfigured (has a signature but no trust entry).
     * Signed artifacts are grouped by signer uid for consistent report output.
     */
    private void classifyUnmatched(SignatureInspector inspector,
            List<ArtifactCoords> unmatchedArtifacts, VerificationState state) {
        List<SignedArtifact> inspected = inspector.inspectAll(unmatchedArtifacts);
        Map<String, List<SignedArtifact>> byArtifact = groupByCoordinates(inspected);

        for (var entry : byArtifact.entrySet()) {
            String coords = entry.getKey();
            List<SignedArtifact> sigEntries = entry.getValue();

            boolean allNotPresent = sigEntries.stream()
                    .allMatch(s -> s.signatureInfo().result() == VerificationResult.NOT_PRESENT);

            if (allNotPresent) {
                state.unconfiguredUnsigned.add(coords);
                state.failures.add(coords + ": not configured, unsigned (add to 'unsigned')");
            } else {
                collectSignatureKeys(coords, sigEntries, state);

                List<String> signerIds = sigEntries.stream()
                        .map(s -> s.signatureInfo().signerUserId())
                        .filter(Objects::nonNull)
                        .distinct()
                        .toList();

                if (signerIds.isEmpty()) {
                    state.unconfiguredUnknownSigner.add(coords);
                    state.failures.add(coords + ": not configured, signer unknown");
                } else {
                    for (String uid : signerIds) {
                        state.unconfiguredBySigner
                                .computeIfAbsent(uid, k -> new ArrayList<>())
                                .add(coords);
                    }
                    state.failures.add(coords + ": not configured (add to 'trust')");
                }
            }
        }
    }

    /**
     * Verifies inspected signatures against the trust configuration.
     */
    private void verifySignatures(List<SignedArtifact> inspected,
            Map<String, List<String>> matchedSignerRefs,
            TrustConfig config, VerificationState state) {
        Map<String, List<SignedArtifact>> byArtifact = groupByCoordinates(inspected);

        for (var entry : byArtifact.entrySet()) {
            String coords = entry.getKey();
            List<SignedArtifact> sigEntries = entry.getValue();
            List<String> signerRefs = matchedSignerRefs.getOrDefault(coords, List.of());

            verifyArtifactSignatures(coords, sigEntries, signerRefs, config, state);
        }
    }

    /**
     * Verifies a single artifact's signatures against its trusted signer references.
     */
    private void verifyArtifactSignatures(String coords, List<SignedArtifact> sigEntries,
            List<String> signerRefs, TrustConfig config,
            VerificationState state) {
        collectSignatureKeys(coords, sigEntries, state);

        String matchedSignerRef = findMatchingSignerRef(sigEntries, signerRefs, config);

        if (matchedSignerRef != null) {
            state.trustedBySigner.computeIfAbsent(matchedSignerRef, k -> new ArrayList<>())
                    .add(coords);
            state.allTrustedSignerRefs.addAll(signerRefs);
            if (state.verifyAllSignatures) {
                collectUnverifiedSignatures(coords, sigEntries, state);
            }
        } else {
            handleUntrustedArtifact(coords, sigEntries, signerRefs, state);
        }
    }

    /**
     * Finds the first signer reference whose configured credentials match any signature
     * on the artifact. Checks fingerprints first, then falls back to uid matching.
     */
    private String findMatchingSignerRef(List<SignedArtifact> sigEntries,
            List<String> signerRefs, TrustConfig config) {
        for (String ref : signerRefs) {
            TrustConfig.Signer signer = config.signers().get(ref);
            if (signer == null) {
                continue;
            }
            if (matchesSigner(sigEntries, signer)) {
                return ref;
            }
        }
        return null;
    }

    /**
     * Checks whether any signature matches any member of the given signer definition.
     */
    private boolean matchesSigner(List<SignedArtifact> sigEntries, TrustConfig.Signer signer) {
        for (TrustConfig.Member member : signer.members()) {
            for (SignedArtifact sa : sigEntries) {
                if (memberMatchesSignature(member, sa.signatureInfo())) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Matches a single member credential against a single signature.
     * If the member has a fingerprint, it must match. If only uid, the uid must match.
     */
    static boolean memberMatchesSignature(TrustConfig.Member member, SignatureInfo sig) {
        if (sig.result() == VerificationResult.NOT_PRESENT
                || sig.result() == VerificationResult.FAIL) {
            return false;
        }
        if (member.gpg() != null && sig.keyId() != null && sig.version() < 6) {
            return fingerprintsMatch(member.gpg(), sig.keyId());
        }
        if (member.pqc() != null && sig.keyId() != null && sig.version() >= 6) {
            return fingerprintsMatch(member.pqc(), sig.keyId());
        }
        if (member.uid() != null && sig.signerUserId() != null) {
            return member.uid().equals(sig.signerUserId());
        }
        return false;
    }

    static final int MIN_FINGERPRINT_LENGTH = 16;

    /**
     * Matches fingerprints allowing suffix matching (the shorter must be at least 16 chars).
     */
    static boolean fingerprintsMatch(String expected, String actual) {
        if (expected.length() < MIN_FINGERPRINT_LENGTH
                || actual.length() < MIN_FINGERPRINT_LENGTH) {
            return false;
        }
        String e = expected.toUpperCase();
        String a = actual.toUpperCase();
        return e.length() >= a.length() ? e.endsWith(a) : a.endsWith(e);
    }

    private void collectSignatureKeys(String coords, List<SignedArtifact> sigEntries,
            VerificationState state) {
        for (SignedArtifact sa : sigEntries) {
            SignatureInfo sig = sa.signatureInfo();
            if (sig.result() == VerificationResult.NOT_PRESENT) {
                continue;
            }
            String ver = SignatureInspector.versionLabel(sig.version());
            String keyId = sig.keyId() != null ? sig.keyId() : "unknown";
            String keyLine = ver + ": " + keyId;
            state.artifactSignatures.computeIfAbsent(coords, k -> new ArrayList<>())
                    .add(new SignatureEntry(sig.signerUserId(), keyLine));
        }
    }

    /**
     * Collects unverified signatures for an artifact that has a trusted signer match.
     * These are reported as warnings but don't block the artifact from being trusted.
     */
    private void collectUnverifiedSignatures(String coords, List<SignedArtifact> sigEntries,
            VerificationState state) {
        List<SignedArtifact> unverified = sigEntries.stream()
                .filter(s -> s.signatureInfo().result() != VerificationResult.PASS
                        && s.signatureInfo().result() != VerificationResult.NOT_PRESENT)
                .toList();
        if (unverified.isEmpty()) {
            return;
        }
        for (SignedArtifact sa : unverified) {
            SignatureInfo sig = sa.signatureInfo();
            String ver = SignatureInspector.versionLabel(sig.version());
            String keyId = sig.keyId() != null ? sig.keyId() : "unknown";
            state.unverifiedSignatures.computeIfAbsent(coords, k -> new ArrayList<>())
                    .add(ver + ": " + keyId);
        }
    }

    private void handleUntrustedArtifact(String coords, List<SignedArtifact> sigEntries,
            List<String> signerRefs, VerificationState state) {
        state.allTrustedSignerRefs.addAll(signerRefs);

        List<String> signerIds = sigEntries.stream()
                .map(s -> s.signatureInfo().signerUserId())
                .filter(Objects::nonNull)
                .distinct()
                .toList();

        if (signerIds.isEmpty()) {
            boolean unsigned = sigEntries.stream()
                    .allMatch(s -> s.signatureInfo().result() == VerificationResult.NOT_PRESENT);
            if (unsigned) {
                state.unsignedCoords.add(coords);
                state.failures.add(coords + ": unsigned");
            } else {
                state.unknownSignerCoords.add(coords);
                state.failures.add(coords + ": signer unknown");
            }
        } else {
            for (String signerId : signerIds) {
                state.untrustedBySigner.computeIfAbsent(signerId, k -> new ArrayList<>())
                        .add(coords);
            }
            state.failures.add(coords + ": untrusted signer " + String.join(", ", signerIds));
        }
    }

    private Map<String, List<SignedArtifact>> groupByCoordinates(List<SignedArtifact> inspected) {
        Map<String, List<SignedArtifact>> result = new LinkedHashMap<>();
        for (SignedArtifact r : inspected) {
            result.computeIfAbsent(r.coordinates(), k -> new ArrayList<>(2)).add(r);
        }
        return result;
    }

    // ── Config loading ──────────────────────────────────────

    private TrustConfig loadConfig() throws MojoExecutionException {
        TrustConfig config = loadTrustConfig();
        if (config == null) {
            if (trustConfigFile == null) {
                throw new MojoExecutionException(
                        "trustConfig file is not configured. "
                                + "Create a trust-config.yaml in the project root or set -Dpqc.trustConfig=<path>");
            }
            throw new MojoExecutionException(
                    "trustConfig file not found at "
                            + Path.of("").toAbsolutePath()
                                    .relativize(trustConfigFile.toPath().toAbsolutePath()));
        }
        return config;
    }

    private TrustConfig.Settings mergeSettings(TrustConfig.Settings fileSettings)
            throws MojoExecutionException {
        TrustConfig.Settings resolved = resolveSettings(fileSettings);
        String effectiveOnUntrusted = onUntrusted != null
                ? onUntrusted
                : resolved.onUntrusted();
        if (!TrustConfig.Settings.isValidOnUntrusted(effectiveOnUntrusted)) {
            throw new MojoExecutionException(
                    "Invalid pqc.onUntrusted value '" + effectiveOnUntrusted
                            + "': must be 'fail' or 'warn'");
        }
        boolean effectiveVerifyAll = verifyAllSignatures != null
                ? verifyAllSignatures
                : resolved.verifyAllSignatures();
        return new TrustConfig.Settings(
                resolved.keyservers(), effectiveOnUntrusted,
                effectiveVerifyAll, resolved.fetchSignerInfo());
    }

    // ── Reporting ───────────────────────────────────────────

    private void reportResults(VerificationState state, List<String> skippedCoords) {
        boolean firstGroup = true;

        firstGroup = reportTrusted(state, firstGroup);
        firstGroup = reportUntrusted(state, firstGroup);
        reportSkipped(skippedCoords, firstGroup);

        int passed = state.trustedBySigner.values().stream().mapToInt(List::size).sum();
        int skipped = skippedCoords.size();
        int warnings = state.failPolicy ? 0 : state.failures.size();
        int failed = state.failPolicy ? state.failures.size() : 0;

        getLog().info("");
        StringBuilder summary = new StringBuilder("Summary: ").append(passed).append(" passed");
        if (warnings > 0) {
            summary.append(", ").append(warnings).append(" warning(s)");
        }
        if (skipped > 0) {
            summary.append(", ").append(skipped).append(" skipped");
        }
        if (failed > 0) {
            summary.append(", ").append(failed).append(" failed");
        }
        getLog().info(summary.toString());
    }

    private boolean reportTrusted(VerificationState state, boolean firstGroup) {
        List<Map.Entry<String, List<String>>> sortedTrusted = state.trustedBySigner.entrySet()
                .stream()
                .sorted(Map.Entry.comparingByKey(String.CASE_INSENSITIVE_ORDER))
                .toList();
        for (var group : sortedTrusted) {
            if (!firstGroup) {
                getLog().info("");
            }
            firstGroup = false;
            logSignerKeyLines(group.getKey(), false, group.getValue(), state, LOG_INFO);
        }
        return firstGroup;
    }

    private boolean reportUntrusted(VerificationState state, boolean firstGroup) {
        boolean hasAny = !state.untrustedBySigner.isEmpty()
                || !state.unsignedCoords.isEmpty() || !state.unknownSignerCoords.isEmpty()
                || !state.unconfiguredBySigner.isEmpty()
                || !state.unconfiguredUnknownSigner.isEmpty()
                || !state.unconfiguredUnsigned.isEmpty()
                || !state.unverifiedSignatures.isEmpty();
        if (!hasAny) {
            return firstGroup;
        }

        int level = state.failPolicy ? LOG_ERROR : LOG_WARN;
        boolean[] printed = { !firstGroup };
        reportUntrustedSigners(state, level, printed);
        reportUnconfigured(state, level, printed);
        reportUnknownSigners(state, level, printed);
        reportUnsigned(state, level, printed);
        return false;
    }

    private void reportUntrustedSigners(VerificationState state, int level, boolean[] printed) {
        if (state.untrustedBySigner.isEmpty()) {
            return;
        }
        blankLineSeparator(level, printed);
        logLine(level, "UNTRUSTED");
        List<Map.Entry<String, List<String>>> sorted = state.untrustedBySigner.entrySet()
                .stream()
                .sorted(Map.Entry.comparingByKey(String.CASE_INSENSITIVE_ORDER))
                .toList();
        for (var group : sorted) {
            boolean signerIsTrusted = state.isUidTrusted(group.getKey());
            logSignerKeyLines(group.getKey(), signerIsTrusted, group.getValue(), state, level);
        }
    }

    private void reportUnknownSigners(VerificationState state, int level, boolean[] printed) {
        Set<String> allUnknown = new LinkedHashSet<>(state.unknownSignerCoords);
        allUnknown.addAll(state.unverifiedSignatures.keySet());
        if (allUnknown.isEmpty()) {
            return;
        }
        blankLineSeparator(level, printed);
        logLine(level, "SIGNER UNKNOWN");
        allUnknown.stream().sorted().forEach(c -> {
            Set<String> keyLines = new LinkedHashSet<>();
            List<SignatureEntry> sigs = state.artifactSignatures.get(c);
            if (sigs != null) {
                sigs.stream()
                        .filter(s -> s.signer() == null)
                        .map(SignatureEntry::keyLine)
                        .forEach(keyLines::add);
            }
            List<String> unverified = state.unverifiedSignatures.get(c);
            if (unverified != null) {
                keyLines.addAll(unverified);
            }
            keyLines.forEach(k -> logLine(level, "   " + k));
            logLine(level, "     " + c);
        });
    }

    private void reportUnsigned(VerificationState state, int level, boolean[] printed) {
        if (state.unsignedCoords.isEmpty()) {
            return;
        }
        blankLineSeparator(level, printed);
        logLine(level, "UNSIGNED");
        state.unsignedCoords.stream().sorted().forEach(c -> logLine(level, "     " + c));
    }

    /**
     * Reports unconfigured artifacts using the same signer/key/artifact format
     * as the trusted section.
     */
    private void reportUnconfigured(VerificationState state, int level, boolean[] printed) {
        boolean hasAny = !state.unconfiguredBySigner.isEmpty()
                || !state.unconfiguredUnknownSigner.isEmpty()
                || !state.unconfiguredUnsigned.isEmpty();
        if (!hasAny) {
            return;
        }
        state.unconfiguredBySigner.entrySet().stream()
                .sorted(Map.Entry.comparingByKey(String.CASE_INSENSITIVE_ORDER))
                .forEach(e -> {
                    blankLineSeparator(level, printed);
                    logLine(level, "Signer: " + e.getKey());
                    List<SignatureEntry> sigs = e.getValue().stream()
                            .flatMap(c -> {
                                List<SignatureEntry> entries = state.artifactSignatures.get(c);
                                return entries != null ? entries.stream() : java.util.stream.Stream.empty();
                            })
                            .filter(s -> e.getKey().equals(s.signer()))
                            .toList();
                    sigs.stream().map(SignatureEntry::keyLine).distinct()
                            .forEach(k -> logLine(level, "   " + k));
                    e.getValue().stream().sorted()
                            .forEach(c -> logLine(level, "     " + c));
                });

        if (!state.unconfiguredUnknownSigner.isEmpty()) {
            blankLineSeparator(level, printed);
            logLine(level, "Signer: UNKNOWN");
            state.unconfiguredUnknownSigner.stream().sorted().forEach(c -> {
                List<SignatureEntry> sigs = state.artifactSignatures.get(c);
                if (sigs != null) {
                    sigs.stream().map(SignatureEntry::keyLine).distinct()
                            .forEach(k -> logLine(level, "   " + k));
                }
                logLine(level, "     " + c);
            });
        }

        if (!state.unconfiguredUnsigned.isEmpty()) {
            blankLineSeparator(level, printed);
            logLine(level, "UNSIGNED");
            state.unconfiguredUnsigned.stream().sorted()
                    .forEach(c -> logLine(level, "     " + c));
        }
    }

    private void reportSkipped(List<String> skippedCoords, boolean firstGroup) {
        if (skippedCoords.isEmpty()) {
            return;
        }
        if (!firstGroup) {
            getLog().info("");
        }
        getLog().info("TRUSTED UNSIGNED");
        skippedCoords.stream().sorted().forEach(c -> getLog().info("     " + c));
    }

    private void failIfNeeded(VerificationState state) throws MojoFailureException {
        if (state.failPolicy && !state.failures.isEmpty()) {
            throw new MojoFailureException(
                    state.failures.size() + " artifact(s) failed signer verification:\n"
                            + String.join("\n", state.failures));
        }
    }

    private void logSignerKeyLines(String signerRef, boolean annotateAsTrusted,
            List<String> coordsList, VerificationState state, int logLevel) {
        Set<String> mainSignerKeys = new LinkedHashSet<>();
        Map<String, Set<String>> otherSignerKeys = new HashMap<>();
        Set<String> unverifiedKeys = new LinkedHashSet<>();

        for (String coords : coordsList) {
            List<SignatureEntry> sigs = state.artifactSignatures.get(coords);
            if (sigs == null) {
                continue;
            }
            for (SignatureEntry s : sigs) {
                if (state.signerUidBelongsToRef(s.signer, signerRef)) {
                    mainSignerKeys.add(s.keyLine);
                } else if (s.signer != null) {
                    otherSignerKeys.computeIfAbsent(s.signer, k -> new LinkedHashSet<>())
                            .add(s.keyLine);
                } else {
                    unverifiedKeys.add(s.keyLine);
                }
            }
        }

        // Use the display name or first member uid if available, falling back to the ref ID
        TrustConfig.Signer signerDef = state.config.signers().get(signerRef);
        String displayName = signerRef;
        if (signerDef != null) {
            if (signerDef.name() != null) {
                displayName = signerDef.name();
            } else if (!signerDef.members().isEmpty() && signerDef.members().get(0).uid() != null) {
                displayName = signerDef.members().get(0).uid();
            }
        }
        String signerLabel = annotateAsTrusted
                ? "Signer: " + displayName + " (trusted for other artifacts)"
                : "Signer: " + displayName;

        logLine(logLevel, signerLabel);
        mainSignerKeys.forEach(k -> logLine(logLevel, "   " + k));

        otherSignerKeys.entrySet().stream()
                .sorted(Map.Entry.comparingByKey(String.CASE_INSENSITIVE_ORDER))
                .forEach(e -> {
                    String annotation = state.isUidTrusted(e.getKey())
                            ? " (trusted)"
                            : " (not trusted)";
                    logLine(logLevel, "Signer: " + e.getKey() + annotation);
                    e.getValue().forEach(k -> logLine(logLevel, "   " + k));
                });

        if (!unverifiedKeys.isEmpty()) {
            logLine(LOG_WARN, "Signer: NOT VERIFIED");
            unverifiedKeys.forEach(k -> logLine(LOG_WARN, "   " + k));
        }

        coordsList.stream().sorted().forEach(c -> logLine(logLevel, "     " + c));
    }

    private void blankLineSeparator(int level, boolean[] printed) {
        if (printed[0]) {
            logLine(level, "");
        }
        printed[0] = true;
    }

    private static final int LOG_INFO = 0;
    private static final int LOG_WARN = 1;
    private static final int LOG_ERROR = 2;

    private void logLine(int level, String line) {
        switch (level) {
            case LOG_ERROR -> getLog().error(line);
            case LOG_WARN -> getLog().warn(line);
            default -> getLog().info(line);
        }
    }

    record SignatureEntry(String signer, String keyLine) {
    }

    /**
     * Mutable state accumulated during verification.
     */
    static class VerificationState {
        final boolean failPolicy;
        final boolean verifyAllSignatures;
        final TrustConfig config;
        final Map<String, String> uidToSignerRef;
        final Map<String, List<String>> trustedBySigner = new HashMap<>();
        final Map<String, List<String>> untrustedBySigner = new HashMap<>();
        final Set<String> allTrustedSignerRefs = new LinkedHashSet<>();
        final Map<String, List<SignatureEntry>> artifactSignatures = new HashMap<>();
        final Map<String, List<String>> unverifiedSignatures = new HashMap<>();
        final List<String> unsignedCoords = new ArrayList<>();
        final List<String> unknownSignerCoords = new ArrayList<>();
        final List<String> unconfiguredUnsigned = new ArrayList<>();
        final Map<String, List<String>> unconfiguredBySigner = new HashMap<>();
        final List<String> unconfiguredUnknownSigner = new ArrayList<>();
        final List<String> failures = new ArrayList<>();

        VerificationState(boolean failPolicy, boolean verifyAllSignatures, TrustConfig config) {
            this.failPolicy = failPolicy;
            this.verifyAllSignatures = verifyAllSignatures;
            this.config = config;
            this.uidToSignerRef = buildUidIndex(config);
        }

        /** Builds a lookup from member uid to signer ref ID. */
        private static Map<String, String> buildUidIndex(TrustConfig config) {
            Map<String, String> index = new HashMap<>();
            for (var entry : config.signers().entrySet()) {
                String ref = entry.getKey();
                for (TrustConfig.Member member : entry.getValue().members()) {
                    if (member.uid() != null) {
                        index.put(member.uid(), ref);
                    }
                }
            }
            return index;
        }

        /** Returns the signer ref ID that owns the given uid, or null. */
        String findRefForUid(String signerUid) {
            if (signerUid == null) {
                return null;
            }
            String ref = uidToSignerRef.get(signerUid);
            if (ref != null) {
                return ref;
            }
            return config.signers().containsKey(signerUid) ? signerUid : null;
        }

        /** Checks whether a uid belongs to the given signer ref. */
        boolean signerUidBelongsToRef(String signerUid, String signerRef) {
            return signerRef.equals(findRefForUid(signerUid));
        }

        /** Checks whether a uid is associated with any trusted signer ref. */
        boolean isUidTrusted(String signerUid) {
            String ref = findRefForUid(signerUid);
            return ref != null && allTrustedSignerRefs.contains(ref);
        }
    }
}
