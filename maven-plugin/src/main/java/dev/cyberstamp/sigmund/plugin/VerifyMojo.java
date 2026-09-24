package dev.cyberstamp.sigmund.plugin;

import dev.cyberstamp.sigmund.core.ArtifactCoords;
import dev.cyberstamp.sigmund.core.ArtifactResult;
import dev.cyberstamp.sigmund.core.AssessmentRequest;
import dev.cyberstamp.sigmund.core.DiscoveryConfig;
import dev.cyberstamp.sigmund.core.ListedEvidencePolicy;
import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.SignerIdentity;
import dev.cyberstamp.sigmund.core.TrustPolicy;
import dev.cyberstamp.sigmund.core.TrustVerifier;
import dev.cyberstamp.sigmund.core.UnlistedEvidencePolicy;
import dev.cyberstamp.sigmund.core.UntrustedPolicy;
import dev.cyberstamp.sigmund.core.VerificationReport;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

@Mojo(name = "verify", defaultPhase = LifecyclePhase.VALIDATE, threadSafe = true)
public class VerifyMojo extends AbstractDependencyMojo {

    @Parameter(property = "sigmund.onUntrusted")
    private String onUntrusted;

    @Parameter(property = "sigmund.listedEvidence")
    private String listedEvidence;

    @Parameter(property = "sigmund.verifyPomFiles", defaultValue = "false")
    private boolean verifyPomFiles;

    /**
     * When {@code true}, the report explains every artifact claim by claim: the tool that
     * verified it, the algorithm, the credentials proven, the trust root, the evidence file
     * and when the claim was made. The grouped summary alone is the default.
     */
    @Parameter(property = "sigmund.detail", defaultValue = "false")
    boolean detail;

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        if (skip) {
            getLog().info("Skipping signature verification");
            return;
        }

        SigmundConfig config = loadAndValidateConfig();
        TrustPolicy trustPolicy = applyPolicyOverrides(config.trustPolicy());
        DiscoveryConfig discoveryConfig = resolveDiscoveryConfig(config.discoveryConfig());

        try (Sigmund sigmund = buildSigmund(discoveryConfig, mergeToolOverrides(config.toolsConfig()))) {
            TrustVerifier verifier = sigmund.verifier(trustPolicy);

            List<ArtifactCoords> artifacts = resolveDependencies();
            getLog().info("Verifying signers for " + artifacts.size() + " dependency(ies)...");

            List<ArtifactCoords> toAssess = new ArrayList<>(artifacts);

            if (verifyPomFiles) {
                addPomArtifacts(toAssess);
            }

            ArtifactFileResolver resolver = new ArtifactFileResolver(
                    repoSystem, repoSession, remoteRepos, getLog(),
                    sigmund.signatureFileExtensions());

            List<AssessmentRequest> requests = new ArrayList<>(toAssess.size());
            for (ArtifactCoords coords : toAssess) {
                ArtifactFileResolver.ResolvedFiles resolved = resolver.resolve(coords);
                if (resolved == null) {
                    throw new MojoFailureException("Could not resolve artifact " + coords);
                }
                requests.add(new AssessmentRequest(coords, resolved.artifactFile(),
                        resolved.evidenceFiles()));
            }

            List<ArtifactResult> results = verifier.assessAll(requests);

            VerificationReport report = VerificationReport.of(results, trustPolicy);
            reportResults(report);
            failIfNeeded(report);
        } catch (Exception e) {
            if (e instanceof MojoExecutionException mee) {
                throw mee;
            }
            if (e instanceof MojoFailureException mfe) {
                throw mfe;
            }
            throw new MojoExecutionException("Verification failed", e);
        }
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
            if ("pom".equals(artifact.extension())) {
                continue;
            }
            String key = artifact.namespace() + ":" + artifact.name() + ":" + artifact.version();
            if (seen.add(key)) {
                poms.add(new ArtifactCoords(
                        artifact.namespace(), artifact.name(), "", "pom", artifact.version()));
            }
        }
        artifacts.addAll(poms);
    }

    /**
     * Logs what verification established, at severities this build tool understands.
     *
     * <p>
     * What to say and what it means come from core, so that every insertion point reports
     * alike; only the mapping to Maven's log levels is decided here.
     *
     * @param report what the run found
     */
    void reportResults(VerificationReport report) {
        report.byOutcome().forEach((outcome, results) -> {
            int level = switch (outcome) {
                case SATISFIED, NOT_CONFIGURED -> LOG_INFO;
                case FAILED -> LOG_ERROR;
                case UNSATISFIED, NO_CLAIM, INDETERMINATE -> LOG_WARN;
            };
            logLine(level, "");
            logLine(level, outcome + " (" + results.size() + ")");
            for (VerificationReport.AttesterGroup group : VerificationReport.groupByAttester(results)) {
                for (String line : group.summary()) {
                    logLine(level, "  " + line);
                }
                if (detail) {
                    for (String line : group.detail()) {
                        logLine(level, "  " + line);
                    }
                }
                for (ArtifactResult result : group.artifacts()) {
                    logLine(level, "    " + result.subject().coords());
                    if (detail) {
                        // at the severity of the outcome being explained: detail about a
                        // failing artifact that an operator has to raise the log level to see
                        // is detail they will not read
                        for (String line : VerificationReport.explain(result)) {
                            logLine(level, "      " + line);
                        }
                    }
                }
            }
        });
    }

    /**
     * Fails the build when the policy does not tolerate what was found.
     *
     * @param report what the run found
     * @throws MojoFailureException when an artifact's outcome blocks
     */
    private void failIfNeeded(VerificationReport report) throws MojoFailureException {
        List<ArtifactResult> blocking = report.blocking();
        if (blocking.isEmpty()) {
            return;
        }
        String coords = blocking.stream()
                .map(result -> result.subject().coords() + " (" + result.outcome() + ")")
                .collect(Collectors.joining(", "));
        throw new MojoFailureException(
                "Verification blocked the build for " + blocking.size() + " artifact(s): "
                        + coords);
    }

    private SigmundConfig loadAndValidateConfig() throws MojoExecutionException {
        SigmundConfig config = super.loadConfig();
        if (config == null) {
            if (trustConfigFile == null) {
                throw new MojoExecutionException(
                        "Config file is not configured. "
                                + "Create a sigmund.yaml in the project root or set -Dsigmund.trustConfig=<path>");
            }
            throw new MojoExecutionException(
                    "Config file not found at "
                            + Path.of("").toAbsolutePath()
                                    .relativize(trustConfigFile.toPath().toAbsolutePath()));
        }
        return config;
    }

    /**
     * Applies Maven property overrides ({@code onUntrusted}, {@code listedEvidence})
     * to the trust policy from the config file. If no overrides are set, returns the
     * policy unchanged.
     */
    private TrustPolicy applyPolicyOverrides(TrustPolicy filePolicy)
            throws MojoExecutionException {
        UntrustedPolicy effectiveUntrusted = parseUntrustedOverride(filePolicy);
        ListedEvidencePolicy effectiveListed = parseListedEvidenceOverride(filePolicy);

        if (effectiveUntrusted == filePolicy.onUntrusted()
                && effectiveListed == filePolicy.listedEvidence()) {
            return filePolicy;
        }

        return new OverrideTrustPolicy(filePolicy, effectiveListed, filePolicy.unlistedEvidence(), effectiveUntrusted);
    }

    private UntrustedPolicy parseUntrustedOverride(TrustPolicy filePolicy)
            throws MojoExecutionException {
        if (onUntrusted == null) {
            return filePolicy.onUntrusted();
        }
        if ("fail".equalsIgnoreCase(onUntrusted)) {
            return UntrustedPolicy.FAIL;
        }
        if ("warn".equalsIgnoreCase(onUntrusted)) {
            return UntrustedPolicy.WARN;
        }
        throw new MojoExecutionException(
                "Invalid sigmund.onUntrusted value '" + onUntrusted
                        + "': must be 'fail' or 'warn'");
    }

    private ListedEvidencePolicy parseListedEvidenceOverride(TrustPolicy filePolicy)
            throws MojoExecutionException {
        if (listedEvidence == null) {
            return filePolicy.listedEvidence();
        }
        if ("all".equalsIgnoreCase(listedEvidence)) {
            return ListedEvidencePolicy.ALL;
        }
        if ("any".equalsIgnoreCase(listedEvidence)) {
            return ListedEvidencePolicy.ANY;
        }
        throw new MojoExecutionException(
                "Invalid sigmund.listedEvidence value '" + listedEvidence
                        + "': must be 'all' or 'any'");
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

    /**
     * A delegating {@link TrustPolicy} that overrides {@code listedEvidence}
     * and {@code onUntrusted} from Maven property settings while keeping the original
     * trust mappings and unsigned patterns.
     */
    private record OverrideTrustPolicy(
            TrustPolicy delegate,
            ListedEvidencePolicy listedEvidence,
            UnlistedEvidencePolicy unlistedEvidence,
            UntrustedPolicy onUntrusted) implements TrustPolicy {

        @Override
        public List<SignerIdentity> expectedSigners(ArtifactCoords artifact) {
            return delegate.expectedSigners(artifact);
        }

        @Override
        public boolean isUnsignedAllowed(ArtifactCoords artifact) {
            return delegate.isUnsignedAllowed(artifact);
        }
    }
}
