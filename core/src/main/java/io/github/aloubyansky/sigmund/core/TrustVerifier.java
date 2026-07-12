package io.github.aloubyansky.sigmund.core;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Consumer use case — identity-based trust assessment.
 * <p>
 * Answers "is this artifact from someone I trust?" by combining evidence verification
 * with trust policy matching.
 *
 * <h3>Assessment flow</h3>
 * <ol>
 * <li><strong>Resolve policy</strong> — look up expected signers. Empty list → NOT_CONFIGURED.</li>
 * <li><strong>Check unsigned</strong> — if unsigned-ok and no evidence → TRUSTED.</li>
 * <li><strong>Verify evidence</strong> — each provider verifies matching files → EvidenceResults.</li>
 * <li><strong>Match identity</strong> — check credential bag overlap between signers and evidence.</li>
 * <li><strong>Apply policy</strong> — produce verdict based on matches and policy settings.</li>
 * </ol>
 *
 * <h3>Usage</h3>
 *
 * <pre>{@code
 * TrustVerifier verifier = sigmund.verifier(trustPolicy);
 * TrustResult result = verifier.assess(artifact, artifactFile, evidenceFiles);
 * if (result.verdict() == TrustVerdict.TRUSTED) { ... }
 * }</pre>
 *
 * @see TrustResult
 * @see TrustVerdict
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
     * Assesses the trust status of a single artifact.
     *
     * @param artifact the artifact identity
     * @param artifactFile the artifact file on disk
     * @param evidenceFiles the evidence files to verify
     * @return the trust assessment result
     */
    public TrustResult assess(ArtifactIdentity artifact, Path artifactFile,
            List<Path> evidenceFiles) {
        List<SignerIdentity> expectedSigners = resolveExpectedSigners(artifact);
        List<EvidenceResult> allEvidence = collectEvidence(artifactFile, evidenceFiles);

        if (expectedSigners.isEmpty()) {
            return checkUnsignedOrNotConfigured(artifact, evidenceFiles, allEvidence);
        }

        if (allEvidence.isEmpty()) {
            return new TrustResult(artifact, TrustVerdict.UNSIGNED, List.of(), List.of());
        }

        if (hasVerificationFailure(allEvidence)) {
            return new TrustResult(artifact, TrustVerdict.VERIFICATION_FAILED,
                    List.of(), allEvidence);
        }

        return matchCredentials(artifact, expectedSigners, allEvidence);
    }

    /**
     * Assesses the trust status of multiple artifacts in batch.
     *
     * @param requests the assessment requests
     * @return a list of trust results, one per request
     */
    public List<TrustResult> assessAll(List<AssessmentRequest> requests) {
        List<TrustResult> results = new ArrayList<>(requests.size());
        for (AssessmentRequest req : requests) {
            results.add(assess(req.artifact(), req.artifactFile(), req.evidenceFiles()));
        }
        return results;
    }

    private List<SignerIdentity> resolveExpectedSigners(ArtifactIdentity artifact) {
        return policy.expectedSigners(artifact);
    }

    private TrustResult checkUnsignedOrNotConfigured(ArtifactIdentity artifact,
            List<Path> evidenceFiles, List<EvidenceResult> allEvidence) {
        if (policy.isUnsignedAllowed(artifact) && (evidenceFiles == null || evidenceFiles.isEmpty())) {
            return new TrustResult(artifact, TrustVerdict.TRUSTED, List.of(), List.of());
        }
        return new TrustResult(artifact, TrustVerdict.NOT_CONFIGURED, List.of(), allEvidence);
    }

    private List<EvidenceResult> collectEvidence(Path artifactFile, List<Path> evidenceFiles) {
        if (evidenceFiles == null || evidenceFiles.isEmpty()) {
            return List.of();
        }
        List<EvidenceResult> results = new ArrayList<>();
        for (Path evidenceFile : evidenceFiles) {
            for (EvidenceProvider provider : providers) {
                if (provider.canHandle(evidenceFile)) {
                    results.addAll(provider.verify(artifactFile, evidenceFile));
                }
            }
        }
        return results;
    }

    private boolean hasVerificationFailure(List<EvidenceResult> evidence) {
        return evidence.stream()
                .anyMatch(e -> e.verdict() == Verdict.FAIL);
    }

    private TrustResult matchCredentials(ArtifactIdentity artifact,
            List<SignerIdentity> expectedSigners, List<EvidenceResult> allEvidence) {
        List<MatchedEvidence> matched = new ArrayList<>();
        List<EvidenceResult> unmatched = new ArrayList<>();

        for (EvidenceResult evidence : allEvidence) {
            if (evidence.verdict() != Verdict.PASS) {
                unmatched.add(evidence);
                continue;
            }
            SignerIdentity matchedSigner = findMatchingSigner(expectedSigners, evidence);
            if (matchedSigner != null) {
                matched.add(new MatchedEvidence(matchedSigner, evidence));
            } else {
                unmatched.add(evidence);
            }
        }

        TrustVerdict verdict = applyPolicy(matched, unmatched);
        return new TrustResult(artifact, verdict, matched, unmatched);
    }

    private SignerIdentity findMatchingSigner(List<SignerIdentity> signers, EvidenceResult evidence) {
        for (SignerIdentity signer : signers) {
            if (credentialOverlap(signer, evidence)) {
                return signer;
            }
        }
        return null;
    }

    private boolean credentialOverlap(SignerIdentity signer, EvidenceResult evidence) {
        for (Credential proven : evidence.provenCredentials()) {
            for (Credential expected : signer.credentials()) {
                if (expected.matches(proven)) {
                    return true;
                }
            }
        }
        return false;
    }

    private TrustVerdict applyPolicy(List<MatchedEvidence> matched, List<EvidenceResult> unmatched) {
        if (matched.isEmpty()) {
            return TrustVerdict.UNTRUSTED;
        }
        if (policy.requireAllEvidenceMatch() && !unmatched.isEmpty()) {
            return TrustVerdict.UNTRUSTED;
        }
        return TrustVerdict.TRUSTED;
    }
}
