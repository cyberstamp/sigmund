package io.github.aloubyansky.sigmund.plugin;

import io.github.aloubyansky.sigmund.core.Algorithms;
import io.github.aloubyansky.sigmund.core.ArtifactIdentity;
import io.github.aloubyansky.sigmund.core.AssessmentRequest;
import io.github.aloubyansky.sigmund.core.Credential;
import io.github.aloubyansky.sigmund.core.EvidenceResult;
import io.github.aloubyansky.sigmund.core.FingerprintCredential;
import io.github.aloubyansky.sigmund.core.MatchedEvidence;
import io.github.aloubyansky.sigmund.core.OpenPgpVerifyResult;
import io.github.aloubyansky.sigmund.core.Sigmund;
import io.github.aloubyansky.sigmund.core.SignerIdentity;
import io.github.aloubyansky.sigmund.core.TrustPolicy;
import io.github.aloubyansky.sigmund.core.TrustResult;
import io.github.aloubyansky.sigmund.core.TrustVerdict;
import io.github.aloubyansky.sigmund.core.TrustVerifier;
import io.github.aloubyansky.sigmund.core.UnverifiedResult;
import io.github.aloubyansky.sigmund.core.Verdict;
import io.github.aloubyansky.sigmund.core.VerifyResult;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

@Mojo(name = "verify", defaultPhase = LifecyclePhase.VALIDATE, threadSafe = true)
public class VerifyMojo extends AbstractDependencyMojo {

    @Parameter(property = "sigmund.onUntrusted")
    private String onUntrusted;

    @Parameter(property = "sigmund.verifyAllSignatures")
    private Boolean verifyAllSignatures;

    @Parameter(property = "sigmund.verifyPomFiles", defaultValue = "false")
    private boolean verifyPomFiles;

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        if (skip) {
            getLog().info("Skipping signature verification");
            return;
        }

        TrustConfig config = loadConfig();
        TrustConfig.Settings settings = mergeSettings(config.settings());
        TrustConfigAdapter adapter = new TrustConfigAdapter(config, settings);
        TrustPolicy trustPolicy = adapter.trustPolicy();

        Sigmund sigmund = buildSigmund(settings);
        TrustVerifier verifier = sigmund.verifier(trustPolicy);

        List<ArtifactCoords> artifacts = resolveDependencies();
        getLog().info("Verifying signers for " + artifacts.size() + " dependency(ies)...");

        List<ArtifactCoords> toAssess = new ArrayList<>();
        List<String> skippedCoords = new ArrayList<>();
        for (ArtifactCoords artifact : artifacts) {
            ArtifactIdentity id = MavenArtifactIdentity.from(artifact);
            if (trustPolicy.isUnsignedAllowed(id)) {
                skippedCoords.add(artifact.toString());
            } else {
                toAssess.add(artifact);
            }
        }

        if (verifyPomFiles) {
            addPomArtifacts(toAssess);
        }

        ArtifactFileResolver resolver = new ArtifactFileResolver(repoSystem, repoSession, remoteRepos, getLog());

        List<AssessmentRequest> requests = new ArrayList<>(toAssess.size());
        List<ArtifactCoords> assessedCoords = new ArrayList<>(toAssess.size());

        for (ArtifactCoords coords : toAssess) {
            ArtifactFileResolver.ResolvedFiles resolved = resolver.resolve(coords);
            if (resolved == null) {
                throw new MojoFailureException("Could not resolve artifact " + coords);
            }
            ArtifactIdentity identity = MavenArtifactIdentity.from(coords);
            requests.add(new AssessmentRequest(identity, resolved.artifactFile(),
                    resolved.evidenceFiles()));
            assessedCoords.add(coords);
        }

        List<TrustResult> results = verifier.assessAll(requests);

        Map<Integer, List<EnrichedSignerInfo>> enriched = enrichResults(results);

        boolean failPolicy = "fail".equals(settings.onUntrusted());
        boolean verifyAll = settings.verifyAllSignatures();

        reportResults(results, assessedCoords, enriched, skippedCoords,
                failPolicy, verifyAll);
        failIfNeeded(results, assessedCoords, failPolicy, verifyAll);
    }

    /**
     * Adds POM artifacts for each unique GAV in the list, so their signatures
     * are also verified when {@code verifyPomFiles} is enabled.
     *
     * @param artifacts the mutable list to append POM coordinates to
     */
    void addPomArtifacts(List<ArtifactCoords> artifacts) {
        Set<String> seen = new LinkedHashSet<>();
        List<ArtifactCoords> poms = new ArrayList<>();
        for (ArtifactCoords artifact : artifacts) {
            if ("pom".equals(artifact.type())) {
                continue;
            }
            String key = artifact.groupId() + ":" + artifact.artifactId() + ":" + artifact.version();
            if (seen.add(key)) {
                poms.add(new ArtifactCoords(
                        artifact.groupId(), artifact.artifactId(), "", "pom", artifact.version()));
            }
        }
        artifacts.addAll(poms);
    }

    record EnrichedSignerInfo(String signerDisplayName, String keyLine, boolean fallback) {
        EnrichedSignerInfo(String signerDisplayName, String keyLine) {
            this(signerDisplayName, keyLine, false);
        }
    }

    /**
     * Extracts display-ready signer info from unmatched evidence in trust results.
     * Uses the {@link VerifyResult} already carried by {@link EvidenceResult},
     * avoiding re-verification.
     *
     * @return map from result index to the extracted signer info list
     */
    private Map<Integer, List<EnrichedSignerInfo>> enrichResults(List<TrustResult> results) {
        Map<Integer, List<EnrichedSignerInfo>> enriched = new HashMap<>();
        for (int i = 0; i < results.size(); i++) {
            TrustResult result = results.get(i);
            if (result.unmatchedEvidence().isEmpty()) {
                continue;
            }
            List<EnrichedSignerInfo> infos = new ArrayList<>();
            for (EvidenceResult evidence : result.unmatchedEvidence()) {
                EnrichedSignerInfo info = extractSignerInfo(evidence.verifyResult());
                if (info != null) {
                    infos.add(info);
                }
            }
            if (!infos.isEmpty()) {
                enriched.put(i, infos);
            }
        }
        return enriched;
    }

    /**
     * Extracts display-ready signer info from a {@link VerifyResult}.
     *
     * @return the enriched info, or {@code null} if the result has no useful identity data
     */
    private static EnrichedSignerInfo extractSignerInfo(VerifyResult vr) {
        if (vr instanceof OpenPgpVerifyResult opvr) {
            String label = Algorithms.versionLabel(opvr.version());
            String algo = vr.algorithm() != null ? " (" + vr.algorithm() + ")" : "";
            String keyId = opvr.preferredKeyId() != null ? opvr.preferredKeyId() : "unknown";
            String suffix = vr.verdict() != Verdict.PASS ? " (" + vr.verdict() + ")" : "";
            return new EnrichedSignerInfo(opvr.signerDisplayName(), label + algo + ": " + keyId + suffix);
        }
        if (vr.signerDisplayName() != null) {
            String keyLine = vr.algorithm() != null ? vr.algorithm() : "unknown";
            if (vr.verdict() != Verdict.PASS) {
                keyLine += " (" + vr.verdict() + ")";
            }
            return new EnrichedSignerInfo(vr.signerDisplayName(), keyLine);
        }
        if (vr instanceof UnverifiedResult) {
            return new EnrichedSignerInfo(null,
                    "signature present, verification failed", true);
        }
        return null;
    }

    /**
     * Loads and validates the trust config file, failing with a clear message
     * if not found.
     */
    private TrustConfig loadConfig() throws MojoExecutionException {
        TrustConfig config = loadTrustConfig();
        if (config == null) {
            if (trustConfigFile == null) {
                throw new MojoExecutionException(
                        "trustConfig file is not configured. "
                                + "Create a trust-config.yaml in the project root or set -Dsigmund.trustConfig=<path>");
            }
            throw new MojoExecutionException(
                    "trustConfig file not found at "
                            + Path.of("").toAbsolutePath()
                                    .relativize(trustConfigFile.toPath().toAbsolutePath()));
        }
        return config;
    }

    /**
     * Merges file-based settings with Mojo parameter overrides ({@code onUntrusted},
     * {@code verifyAllSignatures}).
     */
    private TrustConfig.Settings mergeSettings(TrustConfig.Settings fileSettings)
            throws MojoExecutionException {
        TrustConfig.Settings resolved = resolveSettings(fileSettings);
        String effectiveOnUntrusted = onUntrusted != null
                ? onUntrusted
                : resolved.onUntrusted();
        if (!TrustConfig.Settings.isValidOnUntrusted(effectiveOnUntrusted)) {
            throw new MojoExecutionException(
                    "Invalid sigmund.onUntrusted value '" + effectiveOnUntrusted
                            + "': must be 'fail' or 'warn'");
        }
        boolean effectiveVerifyAll = verifyAllSignatures != null
                ? verifyAllSignatures
                : resolved.verifyAllSignatures();
        return new TrustConfig.Settings(
                resolved.keyservers(), effectiveOnUntrusted,
                effectiveVerifyAll, resolved.fetchSignerInfo());
    }

    /**
     * Identifies untrusted signer keys that are trusted for other artifacts,
     * so the report can annotate them as "(trusted for other artifacts)".
     */
    private Set<String> buildTrustedAnnotations(
            Map<String, List<String>> untrustedBySigner,
            List<TrustResult> results,
            Map<Integer, List<EnrichedSignerInfo>> enriched,
            List<SignerIdentity> allTrustedSigners) {
        Set<String> annotated = new LinkedHashSet<>();
        for (String untrustedKey : untrustedBySigner.keySet()) {
            if (isKnownToTrustedSigner(untrustedKey, results, enriched, allTrustedSigners)) {
                annotated.add(untrustedKey);
            }
        }
        return annotated;
    }

    /**
     * Checks whether the given untrusted key matches any signer that is
     * trusted for at least one other artifact in this build.
     */
    private boolean isKnownToTrustedSigner(String untrustedKey,
            List<TrustResult> results,
            Map<Integer, List<EnrichedSignerInfo>> enriched,
            List<SignerIdentity> allTrustedSigners) {
        for (int i = 0; i < results.size(); i++) {
            TrustResult result = results.get(i);
            if (result.verdict() != TrustVerdict.UNTRUSTED) {
                continue;
            }
            for (EvidenceResult ue : result.unmatchedEvidence()) {
                for (Credential proven : ue.provenCredentials()) {
                    if (!formatCredentialKeyLine(proven).equals(untrustedKey)) {
                        continue;
                    }
                    for (SignerIdentity trusted : allTrustedSigners) {
                        for (Credential expected : trusted.credentials()) {
                            if (expected.matches(proven)) {
                                return true;
                            }
                        }
                    }
                }
            }
            List<EnrichedSignerInfo> infos = enriched.get(i);
            if (infos != null) {
                for (EnrichedSignerInfo info : infos) {
                    String name = info.signerDisplayName() != null
                            ? info.signerDisplayName()
                            : info.keyLine();
                    if (!name.equals(untrustedKey)) {
                        continue;
                    }
                    for (SignerIdentity trusted : allTrustedSigners) {
                        if (trusted.displayName() != null
                                && trusted.displayName().equals(info.signerDisplayName())) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    /**
     * Classifies trust results and prints the grouped console report:
     * trusted signers, untrusted/unsigned/not-configured sections, and summary.
     */
    private void reportResults(List<TrustResult> results, List<ArtifactCoords> coords,
            Map<Integer, List<EnrichedSignerInfo>> enriched, List<String> skippedCoords,
            boolean failPolicy, boolean verifyAll) {

        Map<String, List<String>> trustedBySigner = new LinkedHashMap<>();
        Map<String, String> trustedDisplayNames = new LinkedHashMap<>();
        Map<String, Set<String>> trustedKeyLines = new LinkedHashMap<>();
        List<SignerIdentity> allTrustedSigners = new ArrayList<>();

        Map<String, List<String>> untrustedBySigner = new LinkedHashMap<>();
        List<String> unsignedCoords = new ArrayList<>();
        List<String> verificationFailedCoords = new ArrayList<>();

        Map<String, List<String>> notConfiguredBySigner = new LinkedHashMap<>();
        List<String> notConfiguredUnsigned = new ArrayList<>();
        Map<String, Set<String>> notConfiguredUnknown = new LinkedHashMap<>();

        Map<String, List<String>> unverifiedWarnings = new LinkedHashMap<>();

        for (int i = 0; i < results.size(); i++) {
            TrustResult result = results.get(i);
            String coordStr = coords.get(i).toString();

            switch (result.verdict()) {
                case TRUSTED -> {
                    String signerRef = result.matchedEvidence().isEmpty()
                            ? "unknown"
                            : result.matchedEvidence().get(0).signer().id();
                    String displayName = result.matchedEvidence().isEmpty()
                            ? "unknown"
                            : result.matchedEvidence().get(0).signer().displayName();

                    trustedBySigner.computeIfAbsent(signerRef, k -> new ArrayList<>())
                            .add(coordStr);
                    trustedDisplayNames.putIfAbsent(signerRef, displayName);
                    for (MatchedEvidence me : result.matchedEvidence()) {
                        allTrustedSigners.add(me.signer());
                    }
                    Set<String> keyLines = trustedKeyLines.computeIfAbsent(
                            signerRef, k -> new LinkedHashSet<>());
                    for (MatchedEvidence me : result.matchedEvidence()) {
                        for (Credential cred : me.evidence().provenCredentials()) {
                            keyLines.add(formatCredentialKeyLine(cred));
                        }
                    }

                    if (verifyAll && !result.unmatchedEvidence().isEmpty()) {
                        for (EvidenceResult ue : result.unmatchedEvidence()) {
                            for (Credential cred : ue.provenCredentials()) {
                                unverifiedWarnings
                                        .computeIfAbsent(coordStr, k -> new ArrayList<>())
                                        .add(formatCredentialKeyLine(cred));
                            }
                        }
                    }
                }

                case UNTRUSTED -> {
                    List<String> signerNames = new ArrayList<>();
                    for (EvidenceResult ue : result.unmatchedEvidence()) {
                        for (Credential cred : ue.provenCredentials()) {
                            signerNames.add(formatCredentialKeyLine(cred));
                        }
                    }
                    if (signerNames.isEmpty()) {
                        List<EnrichedSignerInfo> infos = enriched.get(i);
                        if (infos != null) {
                            for (EnrichedSignerInfo info : infos) {
                                if (info.fallback()) {
                                    continue;
                                }
                                if (info.signerDisplayName() != null) {
                                    signerNames.add(info.signerDisplayName());
                                } else {
                                    signerNames.add(info.keyLine());
                                }
                            }
                        }
                    }
                    if (signerNames.isEmpty()) {
                        signerNames.add("unknown");
                    }
                    for (String signer : signerNames) {
                        untrustedBySigner.computeIfAbsent(signer, k -> new ArrayList<>())
                                .add(coordStr);
                    }
                }

                case UNSIGNED -> unsignedCoords.add(coordStr);

                case NOT_CONFIGURED -> {
                    List<EnrichedSignerInfo> infos = enriched.get(i);
                    if (infos == null || infos.isEmpty()) {
                        notConfiguredUnsigned.add(coordStr);
                    } else {
                        boolean hasSigner = infos.stream()
                                .anyMatch(info -> info.signerDisplayName() != null);
                        if (hasSigner) {
                            for (EnrichedSignerInfo info : infos) {
                                String signerName = info.signerDisplayName() != null
                                        ? info.signerDisplayName()
                                        : "unknown";
                                notConfiguredBySigner
                                        .computeIfAbsent(signerName, k -> new ArrayList<>())
                                        .add(coordStr);
                            }
                        } else {
                            Set<String> keyLines = notConfiguredUnknown
                                    .computeIfAbsent(coordStr, k -> new LinkedHashSet<>());
                            for (EnrichedSignerInfo info : infos) {
                                keyLines.add(info.keyLine());
                            }
                        }
                    }
                }

                case VERIFICATION_FAILED -> verificationFailedCoords.add(coordStr);
            }
        }

        Set<String> trustedForOtherArtifacts = buildTrustedAnnotations(
                untrustedBySigner, results, enriched, allTrustedSigners);

        boolean firstGroup = true;
        firstGroup = reportTrusted(trustedBySigner, trustedDisplayNames, trustedKeyLines,
                firstGroup);
        firstGroup = reportUntrusted(untrustedBySigner, unsignedCoords,
                notConfiguredBySigner, notConfiguredUnsigned, notConfiguredUnknown,
                verificationFailedCoords, unverifiedWarnings,
                trustedForOtherArtifacts, failPolicy, firstGroup);
        reportSkipped(skippedCoords, firstGroup);

        int passed = 0;
        int problems = 0;
        for (TrustResult r : results) {
            if (r.verdict() == TrustVerdict.TRUSTED
                    && !(verifyAll && !r.unmatchedEvidence().isEmpty())) {
                passed++;
            } else {
                problems++;
            }
        }
        int skipped = skippedCoords.size();

        getLog().info("");
        StringBuilder summary = new StringBuilder("Summary: ").append(passed).append(" passed");
        if (failPolicy && problems > 0) {
            summary.append(", ").append(problems).append(" failed");
        } else if (problems > 0) {
            summary.append(", ").append(problems).append(" warning(s)");
        }
        if (skipped > 0) {
            summary.append(", ").append(skipped).append(" skipped");
        }
        getLog().info(summary.toString());
    }

    /**
     * Prints the trusted signers section, grouped by signer with key lines
     * and artifact coordinates.
     *
     * @return updated {@code firstGroup} flag
     */
    private boolean reportTrusted(Map<String, List<String>> trustedBySigner,
            Map<String, String> displayNames, Map<String, Set<String>> trustedKeyLines,
            boolean firstGroup) {
        List<Map.Entry<String, List<String>>> sorted = trustedBySigner.entrySet()
                .stream()
                .sorted(Map.Entry.comparingByKey(String.CASE_INSENSITIVE_ORDER))
                .toList();
        for (var group : sorted) {
            if (!firstGroup) {
                getLog().info("");
            }
            firstGroup = false;
            String label = displayNames.getOrDefault(group.getKey(), group.getKey());
            getLog().info("Signer: " + label);
            Set<String> keyLines = trustedKeyLines.get(group.getKey());
            if (keyLines != null) {
                keyLines.forEach(k -> getLog().info("   " + k));
            }
            group.getValue().stream().sorted().forEach(c -> getLog().info("     " + c));
        }
        return firstGroup;
    }

    /**
     * Prints the untrusted/unsigned/not-configured/verification-failed sections.
     *
     * @return updated {@code firstGroup} flag
     */
    private boolean reportUntrusted(
            Map<String, List<String>> untrustedBySigner,
            List<String> unsignedCoords,
            Map<String, List<String>> notConfiguredBySigner,
            List<String> notConfiguredUnsigned,
            Map<String, Set<String>> notConfiguredUnknown,
            List<String> verificationFailedCoords,
            Map<String, List<String>> unverifiedWarnings,
            Set<String> trustedForOtherArtifacts,
            boolean failPolicy, boolean firstGroup) {
        boolean hasAny = !untrustedBySigner.isEmpty() || !unsignedCoords.isEmpty()
                || !notConfiguredBySigner.isEmpty() || !notConfiguredUnsigned.isEmpty()
                || !notConfiguredUnknown.isEmpty() || !verificationFailedCoords.isEmpty()
                || !unverifiedWarnings.isEmpty();
        if (!hasAny) {
            return firstGroup;
        }

        int level = failPolicy ? LOG_ERROR : LOG_WARN;

        if (!untrustedBySigner.isEmpty()) {
            if (!firstGroup) {
                logLine(level, "");
            }
            firstGroup = false;
            logLine(level, "UNTRUSTED");
            untrustedBySigner.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey(String.CASE_INSENSITIVE_ORDER))
                    .forEach(e -> {
                        String annotation = trustedForOtherArtifacts.contains(e.getKey())
                                ? " (trusted for other artifacts)"
                                : "";
                        logLine(level, "Signer: " + e.getKey() + annotation);
                        e.getValue().stream().sorted().forEach(c -> logLine(level, "     " + c));
                    });
        }

        if (!notConfiguredBySigner.isEmpty() || !notConfiguredUnknown.isEmpty()
                || !notConfiguredUnsigned.isEmpty()) {
            List<Map.Entry<String, List<String>>> sortedNotConfigured = notConfiguredBySigner.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey(String.CASE_INSENSITIVE_ORDER))
                    .toList();
            for (var e : sortedNotConfigured) {
                if (!firstGroup) {
                    logLine(level, "");
                }
                firstGroup = false;
                logLine(level, "Signer: " + e.getKey());
                e.getValue().stream().sorted().distinct()
                        .forEach(c -> logLine(level, "     " + c));
            }
            if (!notConfiguredUnknown.isEmpty()) {
                if (!firstGroup) {
                    logLine(level, "");
                }
                firstGroup = false;
                logLine(level, "SIGNER UNKNOWN");
                notConfiguredUnknown.entrySet().stream()
                        .sorted(Map.Entry.comparingByKey(String.CASE_INSENSITIVE_ORDER))
                        .forEach(entry -> {
                            entry.getValue().forEach(k -> logLine(level, "   " + k));
                            logLine(level, "     " + entry.getKey());
                        });
            }
            if (!notConfiguredUnsigned.isEmpty()) {
                if (!firstGroup) {
                    logLine(level, "");
                }
                firstGroup = false;
                logLine(level, "UNSIGNED (not configured)");
                notConfiguredUnsigned.stream().sorted()
                        .forEach(c -> logLine(level, "     " + c));
            }
        }

        if (!unsignedCoords.isEmpty()) {
            if (!firstGroup) {
                logLine(level, "");
            }
            firstGroup = false;
            logLine(level, "UNSIGNED");
            unsignedCoords.stream().sorted().forEach(c -> logLine(level, "     " + c));
        }

        if (!verificationFailedCoords.isEmpty()) {
            if (!firstGroup) {
                logLine(level, "");
            }
            firstGroup = false;
            logLine(level, "VERIFICATION FAILED");
            verificationFailedCoords.stream().sorted()
                    .forEach(c -> logLine(level, "     " + c));
        }

        if (!unverifiedWarnings.isEmpty()) {
            if (!firstGroup) {
                logLine(LOG_WARN, "");
            }
            firstGroup = false;
            logLine(LOG_WARN, "UNVERIFIED SIGNATURES");
            unverifiedWarnings.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey(String.CASE_INSENSITIVE_ORDER))
                    .forEach(e -> {
                        e.getValue().forEach(k -> logLine(LOG_WARN, "   " + k));
                        logLine(LOG_WARN, "     " + e.getKey());
                    });
        }

        return firstGroup;
    }

    /**
     * Prints the trusted-unsigned section (artifacts allowed to be unsigned
     * by the trust policy).
     */
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

    /**
     * Throws {@link MojoFailureException} if the fail policy is active and any
     * artifact has a non-trusted verdict.
     */
    private void failIfNeeded(List<TrustResult> results, List<ArtifactCoords> coords,
            boolean failPolicy, boolean verifyAll) throws MojoFailureException {
        if (!failPolicy) {
            return;
        }
        List<String> failures = new ArrayList<>();
        for (int i = 0; i < results.size(); i++) {
            TrustResult result = results.get(i);
            String artifactId = coords.get(i).toString();
            switch (result.verdict()) {
                case UNTRUSTED -> failures.add(artifactId + ": untrusted signer");
                case UNSIGNED -> failures.add(artifactId + ": unsigned");
                case NOT_CONFIGURED -> failures.add(artifactId + ": not configured");
                case VERIFICATION_FAILED -> failures.add(artifactId + ": verification failed");
                case TRUSTED -> {
                    if (verifyAll && !result.unmatchedEvidence().isEmpty()) {
                        failures.add(artifactId + ": unverified signatures");
                    }
                }
                default -> {
                }
            }
        }
        if (!failures.isEmpty()) {
            throw new MojoFailureException(
                    failures.size() + " artifact(s) failed signer verification:\n"
                            + String.join("\n", failures));
        }
    }

    /**
     * Formats a credential as a display line (e.g., {@code "PGP4: ABCD1234..."}).
     */
    private static String formatCredentialKeyLine(Credential cred) {
        if (cred instanceof FingerprintCredential fp) {
            String label = switch (fp.type()) {
                case Credential.TYPE_OPENPGP_V4 -> Algorithms.versionLabel(4);
                case Credential.TYPE_OPENPGP_V6 -> Algorithms.versionLabel(6);
                default -> fp.type();
            };
            return label + ": " + fp.fingerprint();
        }
        return cred.type() + ": " + cred.displayName();
    }

    private static final int LOG_WARN = 1;
    private static final int LOG_ERROR = 2;

    private void logLine(int level, String line) {
        switch (level) {
            case LOG_ERROR -> getLog().error(line);
            case LOG_WARN -> getLog().warn(line);
            default -> getLog().info(line);
        }
    }
}
