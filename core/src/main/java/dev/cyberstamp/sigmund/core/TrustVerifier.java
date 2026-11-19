package dev.cyberstamp.sigmund.core;

import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Consumer use case — identity-based trust assessment.
 * <p>
 * Answers "is this artifact from someone I trust?" by combining evidence verification
 * with trust policy matching.
 *
 * <h2>Assessment flow</h2>
 * <ol>
 * <li><strong>Verify evidence</strong> — every evidence file is read once and each provider that
 * handles it verifies its claims, so a {@link ClaimResult} is recorded for every claim found,
 * whether or not it ends up mattering.</li>
 * <li><strong>Resolve identities</strong> — where the matched rule names a directory-backed
 * identity, the directory is asked about the keys the claims proved.</li>
 * <li><strong>Match the rule</strong> — the most specific {@link Rule} for the artifact is
 * selected once and recorded on the result as a {@link MatchedRule}.</li>
 * <li><strong>Roll up</strong> — the shared roll-up evaluates the rule's {@link Requirement}
 * over the verified claims and derives the {@link ArtifactOutcome}; no rule means
 * {@link ArtifactOutcome#NOT_CONFIGURED}.</li>
 * </ol>
 * What the outcome does to the build is not decided here: enforcement is resolved from the
 * recorded rule by {@link VerificationReport}, so that observing and enforcing runs report the
 * same results.
 *
 * <h2>Usage</h2>
 *
 * <pre>{@code
 * TrustVerifier verifier = sigmund.verifier(
 *         RulePolicy.compile(config.trustPolicySpec(), config.signers()));
 * ArtifactResult result = verifier.assess(coords, artifactFile, evidenceFiles);
 * if (result.outcome() == ArtifactOutcome.SATISFIED) { ... }
 * }</pre>
 *
 * @see ArtifactResult
 * @see ArtifactOutcome
 */
public class TrustVerifier {

    private final TrustPolicy policy;
    private final List<EvidenceProvider> providers;
    private final ClaimIdentityResolver identityResolver;

    /**
     * Creates a new trust verifier.
     *
     * @param policy the trust policy to apply
     * @param providers the evidence providers to use for verification
     * @param identityResolver adds directory-verified identities to claims where policy
     *        needs them
     */
    TrustVerifier(TrustPolicy policy, List<EvidenceProvider> providers,
            ClaimIdentityResolver identityResolver) {
        this.policy = policy;
        this.providers = List.copyOf(providers);
        this.identityResolver = identityResolver;
    }

    /**
     * Assesses one artifact against the policy.
     *
     * <p>
     * Every claim found in the evidence is verified and recorded, then the outcome is derived
     * from them by the shared roll-up (§3.2.1) rather than here, so that a goal and a
     * resolver-level extension cannot disagree given the same policy and the same evidence.
     *
     * @param coords the artifact being assessed, which selects the applicable rule
     * @param artifactFile the resolved file, whose bytes identify the subject
     * @param evidenceFiles the evidence resolved alongside it
     * @return what verification established about the artifact
     */
    public ArtifactResult assess(ArtifactCoords coords, Path artifactFile,
            List<Path> evidenceFiles) {
        Instant verifiedAt = Instant.now();
        List<ClaimResult> claims = identityResolver.resolve(coords,
                identityResolver.vouchForDisplayNames(policy.issuers(),
                        collectClaims(artifactFile, evidenceFiles)));
        Rule matched = policy.matchRule(coords);
        OutcomeRollup.Result rollup = OutcomeRollup.derive(claims,
                matched == null ? null : matched.requirement(),
                matched == null ? policy.claimSetMode() : matched.extraClaims());
        return new ArtifactResult(ArtifactSubject.of(coords, artifactFile), rollup.outcome(),
                rollup.reason(), matched == null ? null : matched.toMatchedRule(coords), claims,
                verifiedAt);
    }

    /**
     * Assesses several artifacts.
     *
     * @param requests the artifacts to assess
     * @return one result per request, in the same order
     */
    public List<ArtifactResult> assessAll(List<AssessmentRequest> requests) {
        List<ArtifactResult> results = new ArrayList<>(requests.size());
        for (AssessmentRequest request : requests) {
            results.add(assess(request.artifact(), request.artifactFile(),
                    request.evidenceFiles()));
        }
        return results;
    }

    private List<ClaimResult> collectClaims(Path artifactFile, List<Path> evidenceFiles) {
        if (evidenceFiles == null || evidenceFiles.isEmpty()) {
            return List.of();
        }
        List<ClaimResult> claims = new ArrayList<>();
        for (Path evidenceFile : evidenceFiles) {
            Evidence evidence = Evidence.read(evidenceFile, Evidence.SOURCE_SIDECAR);
            for (EvidenceProvider provider : providers) {
                if (provider.canHandle(evidence)) {
                    claims.addAll(provider.verify(artifactFile, evidence));
                }
            }
        }
        return claims;
    }

}
