package dev.cyberstamp.sigmund.resolver;

import static java.util.Objects.requireNonNull;

import dev.cyberstamp.sigmund.core.ArtifactCoords;
import dev.cyberstamp.sigmund.core.ArtifactOutcome;
import dev.cyberstamp.sigmund.core.ArtifactResult;
import dev.cyberstamp.sigmund.core.ConfigLoader;
import dev.cyberstamp.sigmund.core.EnforcementAction;
import dev.cyberstamp.sigmund.core.MatchedRule;
import dev.cyberstamp.sigmund.core.PolicyConfigException;
import dev.cyberstamp.sigmund.core.RulePolicy;
import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.TrustPolicy;
import dev.cyberstamp.sigmund.core.TrustVerifier;
import dev.cyberstamp.sigmund.core.VerificationReport;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import org.apache.maven.execution.MavenSession;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.util.ConfigUtils;
import org.eclipse.aether.util.artifact.SubArtifact;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Sigmund verification for one {@link RepositorySystemSession}: the configuration, the compiled trust policy and
 * the tools, built once per session and closed when the session ends.
 *
 * <p>
 * The configuration is the file named by {@link SigmundConfigurationKeys#CONFIG_PROP_CONFIG} or, when unset, the
 * {@code sigmund.yaml} in the build's root directory, else the user's {@code ~/.config/sigmund/sigmund.yaml}. A
 * configuration that cannot be loaded or compiled fails the session rather than disabling verification. When no
 * file is found, or the file has no {@code rules}, there is no policy: only a {@link ArtifactOutcome#FAILED}
 * artifact blocks, and a warning says so.
 *
 * <p>
 * Shared by the repository connector, which verifies downloads, and the artifact resolver post-processor, which
 * verifies artifacts served from the local repository: both ask {@link #check} with the signature files they
 * obtained their own way. A file that passed is not checked again in the session.
 */
public final class SigmundSessionVerifier implements AutoCloseable {

    private static final Logger LOGGER = LoggerFactory.getLogger(SigmundSessionVerifier.class);
    private static final String SESSION_KEY = SigmundSessionVerifier.class.getName();

    private final Sigmund sigmund;
    private final TrustPolicy policy;
    private final TrustVerifier verifier;
    private final Set<Path> passed = ConcurrentHashMap.newKeySet();

    private SigmundSessionVerifier(SigmundConfig config) {
        this.policy = RulePolicy.compile(config.trustPolicySpec(), config.signers());
        this.sigmund = Sigmund.builder().config(config).build();
        this.verifier = sigmund.verifier(policy);
    }

    /**
     * Returns the verifier of the session, creating it on first use and closing it when the session ends.
     *
     * @param session the session, whose config properties may name the configuration file
     * @param rootDirectory the build's root directory, searched for {@code sigmund.yaml} when no file is named;
     *        asked only when the verifier is created
     * @return the session's verifier
     * @throws PolicyConfigException if the configuration cannot be loaded or compiled
     */
    public static SigmundSessionVerifier get(RepositorySystemSession session, Supplier<Path> rootDirectory) {
        return (SigmundSessionVerifier) session.getData().computeIfAbsent(SESSION_KEY, () -> {
            SigmundSessionVerifier created = create(loadConfig(session, rootDirectory.get()));
            session.addOnSessionEndedHandler(created::close);
            return created;
        });
    }

    /**
     * Whether verification is enabled in the session ({@link SigmundConfigurationKeys#CONFIG_PROP_VERIFY_ENABLED}).
     *
     * @param session the session
     * @return {@code true} when artifacts are to be verified
     */
    public static boolean isEnabled(RepositorySystemSession session) {
        return ConfigUtils.getBoolean(
                session,
                SigmundConfigurationKeys.DEFAULT_VERIFY_ENABLED,
                SigmundConfigurationKeys.CONFIG_PROP_VERIFY_ENABLED);
    }

    /**
     * The build's root directory: the one Maven identifies by its {@code .mvn} directory, else the directory Maven
     * was started in.
     *
     * @param mavenSession the Maven session
     * @return the root directory
     */
    public static Path rootDirectory(MavenSession mavenSession) {
        try {
            return mavenSession.getRootDirectory();
        } catch (IllegalStateException noDotMvn) {
            // Maven finds no root without a .mvn directory, which loading this extension from .mvn/extensions.xml implies
            return mavenSession.getTopDirectory();
        }
    }

    /**
     * Creates a verifier from an explicit configuration file. The caller closes it.
     *
     * @param configFile the {@code sigmund.yaml} to load
     * @return a new verifier
     * @throws PolicyConfigException if the file is missing, cannot be parsed or its
     *         policy cannot be compiled
     */
    public static SigmundSessionVerifier create(Path configFile) {
        return create(ConfigLoader.load(requireNonNull(configFile)));
    }

    private static SigmundSessionVerifier create(SigmundConfig config) {
        return new SigmundSessionVerifier(config);
    }

    private static SigmundConfig loadConfig(RepositorySystemSession session, Path rootDirectory) {
        String explicit = ConfigUtils.getString(session, null, SigmundConfigurationKeys.CONFIG_PROP_CONFIG);
        Path located = ConfigLoader.locate(explicit == null ? null : Path.of(explicit), rootDirectory);
        if (located == null) {
            LOGGER.warn("Sigmund verification is enabled but no sigmund.yaml was found in {} or the user config;"
                    + " without a policy only signatures that do not match their artifact block", rootDirectory);
            return SigmundConfig.EMPTY;
        }
        LOGGER.info("Sigmund verifies artifacts with {}", located);
        return ConfigLoader.load(located);
    }

    /**
     * The file extensions of the signature sidecars the configured tools read, such as {@code .asc}.
     *
     * @return the signature file extensions, each starting with a dot
     */
    public Set<String> signatureExtensions() {
        return sigmund.signatureFileExtensions();
    }

    /**
     * Whether the artifact is itself a signature file of a configured format, which is evidence for another
     * artifact and is not verified in its own right.
     *
     * @param artifact the artifact
     * @return {@code true} for a signature, such as {@code lib-1.0.jar.asc}
     */
    public boolean isSignature(Artifact artifact) {
        String extension = "." + artifact.getExtension();
        return signatureExtensions().stream().anyMatch(extension::endsWith);
    }

    /**
     * The signature artifacts of an artifact, one per configured signature format.
     *
     * @param artifact the artifact
     * @return its signature artifacts, such as {@code lib-1.0.jar.asc}
     */
    public List<Artifact> signaturesOf(Artifact artifact) {
        List<Artifact> signatures = new ArrayList<>();
        for (String extension : signatureExtensions()) {
            signatures.add(new SubArtifact(artifact, "*", "*" + extension));
        }
        return signatures;
    }

    /**
     * Whether the file already passed {@link #check} in this session.
     *
     * @param artifactFile the artifact file
     * @return {@code true} when it passed
     */
    public boolean hasPassed(Path artifactFile) {
        return passed.contains(artifactFile);
    }

    /**
     * Decides whether an artifact may be used, given what became of its signature files.
     *
     * <p>
     * A signature that could not be obtained, an outcome the policy blocks, and a verification that throws all
     * refuse the artifact. Otherwise the artifact passes: an outcome the policy warns about is logged as a warning,
     * any other at debug, and the file is remembered as passed.
     *
     * @param artifact the artifact
     * @param artifactFile its file
     * @param sidecars what became of each of its signature files
     * @param repository the repository it came from, or {@code null} when not known
     * @return why the artifact must not be used, or {@code null} when it may
     */
    public SigmundVerificationException check(
            Artifact artifact, Path artifactFile, List<Sidecar> sidecars, RemoteRepository repository) {
        List<Path> evidence = new ArrayList<>(sidecars.size());
        for (Sidecar sidecar : sidecars) {
            if (sidecar.failure() != null) {
                return new SigmundVerificationException(artifact, repository,
                        "Could not fetch signature " + sidecar.signature() + " to verify it", sidecar.failure());
            }
            if (sidecar.path() != null) {
                evidence.add(sidecar.path());
            }
        }
        Verdict verdict;
        try {
            verdict = verify(artifact, artifactFile, evidence);
        } catch (RuntimeException e) {
            return new SigmundVerificationException(
                    artifact, repository, "Could not verify " + artifact + ": " + e.getMessage(), e);
        }
        if (verdict.blocks()) {
            return new SigmundVerificationException(artifact, repository, verdict.message());
        }
        if (verdict.action() == EnforcementAction.WARN) {
            LOGGER.warn(verdict.message());
        } else {
            LOGGER.debug(verdict.message());
        }
        passed.add(artifactFile);
        return null;
    }

    /**
     * Assesses one artifact against the policy and resolves whether its outcome blocks.
     *
     * <p>
     * Calls are serialized: the resolver downloads in parallel, and Sigmund's tools make no thread-safety promise.
     *
     * @param artifact the artifact, whose coordinates select the applicable rule
     * @param artifactFile the downloaded file
     * @param evidenceFiles the signature sidecars downloaded alongside it, possibly none
     * @return the outcome, the policy's action for it, and a description for the user
     */
    public synchronized Verdict verify(Artifact artifact, Path artifactFile, List<Path> evidenceFiles) {
        ArtifactResult result = verifier.assess(coords(artifact), artifactFile, evidenceFiles);
        EnforcementAction action = VerificationReport.of(List.of(result), policy).enforcement(result);
        return new Verdict(result.outcome(), action, message(result, action));
    }

    private static String message(ArtifactResult result, EnforcementAction action) {
        StringBuilder message = new StringBuilder(result.subject().coords().toString())
                .append(' ')
                .append(result.outcome());
        if (result.reason() != null) {
            message.append(" (").append(result.reason()).append(')');
        }
        message.append(", action ").append(action);
        MatchedRule rule = result.matchedRule();
        message.append(rule == null ? ", no rule matched" : ", " + rule.location() + " '" + rule.pattern() + "'");
        VerificationReport.explain(result).forEach(line -> message.append("; ").append(line));
        return message.toString();
    }

    private static ArtifactCoords coords(Artifact a) {
        return new ArtifactCoords(a.getGroupId(), a.getArtifactId(), a.getClassifier(), a.getExtension(), a.getVersion());
    }

    /**
     * Closes the tools.
     */
    @Override
    public void close() {
        sigmund.close();
    }

    /**
     * What verification established about one artifact.
     *
     * @param outcome the rolled-up outcome
     * @param action what the policy does with the outcome: fail resolution, warn, or ignore it
     * @param message the outcome, its reason, the rule that decided and the evidence read, for the user
     */
    public record Verdict(ArtifactOutcome outcome, EnforcementAction action, String message) {

        /**
         * Whether the artifact fails resolution.
         *
         * @return {@code true} when the action is {@link EnforcementAction#FAIL}
         */
        public boolean blocks() {
            return action.blocks();
        }
    }
}
