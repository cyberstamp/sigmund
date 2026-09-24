package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class ArtifactResultTest {

    private static final ArtifactSubject SUBJECT = new ArtifactSubject(
            new ArtifactCoords("org.example", "lib", "", "jar", "1.0"),
            DigestSet.sha256("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));

    private static final EvidenceRef REF = new EvidenceRef(Path.of("lib.jar.asc"),
            DigestSet.sha256("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"),
            Evidence.SOURCE_SIDECAR);

    private static ClaimResult claim(ClaimOutcome outcome, IndeterminateReason reason) {
        return new ClaimResult("openpgp", outcome, reason, List.of(), null,
                AttesterRole.UNKNOWN, TrustRootRef.unknown(), REF, null,
                ClaimTimeSource.SIGNER, Instant.EPOCH, "RSA", "bc");
    }

    @Nested
    class Construction {

        @Test
        void carriesTheSubjectOutcomeAndClaims() {
            ClaimResult verified = claim(ClaimOutcome.VERIFIED, null);

            ArtifactResult result = new ArtifactResult(SUBJECT, ArtifactOutcome.SATISFIED, null,
                    List.of(verified), Instant.ofEpochSecond(1_700_000_100L));

            assertThat(result.subject()).isEqualTo(SUBJECT);
            assertThat(result.outcome()).isEqualTo(ArtifactOutcome.SATISFIED);
            assertThat(result.claims()).containsExactly(verified);
        }

        @Test
        void keepsClaimsThatDidNotContribute() {
            ClaimResult verified = claim(ClaimOutcome.VERIFIED, null);
            ClaimResult unsupported = claim(ClaimOutcome.INDETERMINATE, IndeterminateReason.UNSUPPORTED_ALGORITHM);

            ArtifactResult result = new ArtifactResult(SUBJECT, ArtifactOutcome.SATISFIED, null,
                    List.of(verified, unsupported), Instant.EPOCH);

            assertThat(result.claims()).hasSize(2);
        }

        @Test
        void anIndeterminateOutcomeNeedsAReason() {
            assertThatThrownBy(() -> new ArtifactResult(SUBJECT, ArtifactOutcome.INDETERMINATE, null,
                    List.of(), Instant.EPOCH))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void aDecidedOutcomeCarriesNoReason() {
            assertThatThrownBy(() -> new ArtifactResult(SUBJECT, ArtifactOutcome.SATISFIED,
                    IndeterminateReason.KEY_UNAVAILABLE, List.of(), Instant.EPOCH))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void theSubjectIsRequired() {
            assertThatThrownBy(() -> new ArtifactResult(null, ArtifactOutcome.NO_CLAIM, null,
                    List.of(), Instant.EPOCH))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void claimsAreDefensivelyCopied() {
            List<ClaimResult> claims = new ArrayList<>();
            claims.add(claim(ClaimOutcome.VERIFIED, null));
            ArtifactResult result = new ArtifactResult(SUBJECT, ArtifactOutcome.SATISFIED, null, claims,
                    Instant.EPOCH);

            claims.clear();

            assertThat(result.claims()).hasSize(1);
        }
    }

}
