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
 * <li><strong>Resolve policy</strong> — look up expected signers. Empty list → NOT_CONFIGURED.</li>
 * <li><strong>Check unsigned</strong> — if unsigned-ok and no evidence → TRUSTED.</li>
 * <li><strong>Verify evidence</strong> — each provider verifies matching files → EvidenceResults.</li>
 * <li><strong>Match identity</strong> — check credential bag overlap between signers and evidence.</li>
 * <li><strong>Apply policy</strong> — produce verdict based on matches and policy settings.</li>
 * </ol>
 *
 * <h2>Usage</h2>
 *
 * <pre>{@code
 * TrustVerifier verifier = sigmund.verifier(trustPolicy);
 * TrustResult result = verifier.assess(artifact, artifactFile, evidenceFiles);
 * if (result.verdict() == TrustVerdict.TRUSTED) { ... }
 * }</pre>
 *
 * @see ArtifactResult
 * @see ArtifactOutcome
 */
public class TrustVerifier {

    private final TrustPolicy policy;
    private final List<EvidenceProvider> providers;

    /**
     * Creates a new trust verifier.
     *
     * @param policy the trust policy to apply
     * @param providers the evidence providers to use for verification
     */
    TrustVerifier(TrustPolicy policy, List<EvidenceProvider> providers) {
        this.policy = policy;
        this.providers = List.copyOf(providers);
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
        List<ClaimResult> claims = collectClaims(artifactFile, evidenceFiles);
        OutcomeRollup.Result rollup = OutcomeRollup.derive(coords, claims, policy.requirements(),
                null, policy.claimSetMode());
        return new ArtifactResult(ArtifactSubject.of(coords, artifactFile), rollup.outcome(),
                rollup.reason(), claims, verifiedAt);
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
