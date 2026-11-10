package dev.cyberstamp.sigmund.plugin;

import dev.cyberstamp.sigmund.core.ArtifactCoords;
import dev.cyberstamp.sigmund.core.ArtifactOutcome;
import dev.cyberstamp.sigmund.core.ArtifactResult;
import dev.cyberstamp.sigmund.core.AssessmentRequest;
import dev.cyberstamp.sigmund.core.RulePolicy;
import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.TrustPolicy;
import dev.cyberstamp.sigmund.core.TrustVerifier;
import dev.cyberstamp.sigmund.core.VerificationConfig;
import dev.cyberstamp.sigmund.core.VerificationReport;
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
        TrustPolicy trustPolicy = RulePolicy.compile(config.trustPolicySpec(), config.signers());
        VerificationConfig verificationConfig = resolveVerificationConfig(config.verificationConfig());

        try (Sigmund sigmund = buildSigmund(verificationConfig, mergeToolOverrides(config.toolsConfig()))) {
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
            int sectionLevel = Math.max(LOG_INFO, mostSevere(report, results));
            logLine(sectionLevel, "");
            logLine(sectionLevel, report.heading(outcome));
            for (VerificationReport.AttesterGroup group : VerificationReport.groupByAttester(results)) {
                reportGroup(report, group);
            }
        });
    }

    /**
     * Logs one attester group, its shared lines at the most severe level among its artifacts
     * and each artifact at its own.
     *
     * <p>
     * Detail is logged at the severity of the artifact it explains: detail about a failing
     * artifact that an operator has to raise the log level to see is detail they will not read.
     */
    private void reportGroup(VerificationReport report, VerificationReport.AttesterGroup group) {
        int groupLevel = mostSevere(report, group.artifacts());
        for (String line : group.summary()) {
            logLine(groupLevel, "  " + line);
        }
        if (detail) {
            for (String line : group.detail()) {
                logLine(groupLevel, "  " + line);
            }
        }
        for (ArtifactResult result : group.artifacts()) {
            int level = levelOf(report, result);
            logLine(level, "    " + report.describe(result));
            if (detail) {
                for (String line : VerificationReport.explain(result)) {
                    logLine(level, "      " + line);
                }
            }
        }
    }

    private int mostSevere(VerificationReport report, List<ArtifactResult> results) {
        int level = LOG_DEBUG;
        for (ArtifactResult result : results) {
            level = Math.max(level, levelOf(report, result));
        }
        return level;
    }

    /**
     * Maps what the policy does about an artifact to a log level.
     *
     * <p>
     * An ignored artifact is listed only at debug, or at info when detail is asked for: the
     * section heading already counts it, and a catch-all that ignores hundreds of unsigned
     * dependencies would otherwise bury the lines an operator has to act on.
     */
    private int levelOf(VerificationReport report, ArtifactResult result) {
        if (result.outcome() == ArtifactOutcome.SATISFIED) {
            return LOG_INFO;
        }
        return switch (report.enforcement(result)) {
            case FAIL -> LOG_ERROR;
            case WARN -> LOG_WARN;
            case IGNORE -> detail ? LOG_INFO : LOG_DEBUG;
        };
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

    /**
     * Loads the configuration, falling back to zero-config when none exists at the default
     * location.
     *
     * <p>
     * A missing file at the default location means the project has not written a policy, so
     * verification observes. A missing file at a location given explicitly is an error instead:
     * a mistyped path must not quietly turn an enforcing build into an observing one. Whenever
     * no policy is in force the log says so, so a green build is not mistaken for an enforced
     * one.
     *
     * @return the configuration to verify with
     * @throws MojoExecutionException when an explicitly given file does not exist or does not
     *         parse
     */
    SigmundConfig loadAndValidateConfig() throws MojoExecutionException {
        SigmundConfig config = super.loadConfig();
        if (config == null) {
            getLog().info("No sigmund.yaml found; " + OBSERVING);
            return SigmundConfig.EMPTY;
        }
        if (!config.trustPolicySpec().declared()) {
            getLog().info(trustConfigFile.getName() + " declares no policy (no rules); "
                    + OBSERVING);
        }
        return config;
    }

    private static final String OBSERVING = "observing only — every dependency is verified and "
            + "reported, and only a signature that fails verification blocks the build";

    private static final int LOG_DEBUG = 0;
    private static final int LOG_INFO = 1;
    private static final int LOG_WARN = 2;
    private static final int LOG_ERROR = 3;

    private void logLine(int level, String line) {
        switch (level) {
            case LOG_ERROR -> getLog().error(line);
            case LOG_WARN -> getLog().warn(line);
            case LOG_INFO -> getLog().info(line);
            default -> getLog().debug(line);
        }
    }
}
