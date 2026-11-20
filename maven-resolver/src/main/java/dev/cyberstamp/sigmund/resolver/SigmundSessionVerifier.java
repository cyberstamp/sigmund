package dev.cyberstamp.sigmund.resolver;

import static java.util.Objects.requireNonNull;

import dev.cyberstamp.sigmund.core.ArtifactCoords;
import dev.cyberstamp.sigmund.core.ArtifactOutcome;
import dev.cyberstamp.sigmund.core.ArtifactResult;
import dev.cyberstamp.sigmund.core.ConfigLoader;
import dev.cyberstamp.sigmund.core.PolicyConfigException;
import dev.cyberstamp.sigmund.core.RulePolicy;
import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.TrustPolicy;
import dev.cyberstamp.sigmund.core.TrustVerifier;
import dev.cyberstamp.sigmund.core.VerificationReport;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.util.ConfigUtils;

/**
 * Sigmund verification for one {@link RepositorySystemSession}: the configuration, the compiled trust policy and
 * the tools, built once per session and closed when the session ends.
 *
 * <p>
 * The configuration is the file named by {@link SigmundConfigurationKeys#CONFIG_PROP_CONFIG} or, when unset, the
 * {@code sigmund.yaml} located from the {@code maven.multiModuleProjectDirectory} config property (or the current
 * directory). A configuration that cannot be loaded or compiled fails the session rather than disabling
 * verification. Without {@code rules} there is no policy, and only a {@link ArtifactOutcome#FAILED} artifact
 * blocks.
 */
public final class SigmundSessionVerifier implements AutoCloseable {

    private static final String SESSION_KEY = SigmundSessionVerifier.class.getName();

    private final Sigmund sigmund;
    private final TrustPolicy policy;
    private final TrustVerifier verifier;

    private SigmundSessionVerifier(SigmundConfig config) {
        this.policy = RulePolicy.compile(config.trustPolicySpec(), config.signers());
        this.sigmund = Sigmund.builder().config(config).build();
        this.verifier = sigmund.verifier(policy);
    }

    /**
     * Returns the verifier of the session, creating it on first use and closing it when the session ends.
     *
     * @param session the session whose config properties locate the configuration
     * @return the session's verifier
     * @throws PolicyConfigException if the configuration cannot be loaded or compiled
     */
    public static SigmundSessionVerifier get(RepositorySystemSession session) {
        return (SigmundSessionVerifier) session.getData().computeIfAbsent(SESSION_KEY, () -> {
            SigmundSessionVerifier created = create(loadConfig(session));
            session.addOnSessionEndedHandler(created::close);
            return created;
        });
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

    private static SigmundConfig loadConfig(RepositorySystemSession session) {
        String explicit = ConfigUtils.getString(session, null, SigmundConfigurationKeys.CONFIG_PROP_CONFIG);
        String baseDir = ConfigUtils.getString(session, ".", "maven.multiModuleProjectDirectory");
        return ConfigLoader.load(explicit == null ? null : Path.of(explicit), Path.of(baseDir));
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
     * Assesses one artifact against the policy and resolves whether its outcome blocks.
     *
     * <p>
     * Calls are serialized: the resolver downloads in parallel, and Sigmund's tools make no thread-safety promise.
     *
     * @param artifact the artifact, whose coordinates select the applicable rule
     * @param artifactFile the downloaded file
     * @param evidenceFiles the signature sidecars downloaded alongside it, possibly none
     * @return the outcome, whether it blocks, and a description for the user
     */
    public synchronized Verdict verify(Artifact artifact, Path artifactFile, List<Path> evidenceFiles) {
        ArtifactResult result = verifier.assess(coords(artifact), artifactFile, evidenceFiles);
        VerificationReport report = VerificationReport.of(List.of(result), policy);
        return new Verdict(result.outcome(), report.enforcement(result).blocks(), report.describe(result));
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
     * @param blocks whether the policy's enforcement makes the outcome fail resolution
     * @param message the description of the result, for the user
     */
    public record Verdict(ArtifactOutcome outcome, boolean blocks, String message) {
    }
}
