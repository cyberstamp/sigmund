package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class ClaimResultTest {

    private static final String FP = "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12";

    private static final EvidenceRef REF = new EvidenceRef(Path.of("lib.jar.asc"),
            DigestSet.sha256("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            Evidence.SOURCE_SIDECAR);

    private static ClaimResult verified(ClaimOutcome outcome, IndeterminateReason reason,
            EvidenceRef evidence, List<Credential> credentials) {
        return new ClaimResult("openpgp", outcome, reason, credentials, null,
                AttesterRole.UNKNOWN, TrustRootRef.unknown(), evidence, null,
                ClaimTimeSource.SIGNER, Instant.ofEpochSecond(1_700_000_100L), "RSA", "bc");
    }

    @Nested
    class FromAClaimAndResult {

        @Test
        void carriesTheClaimsTimeAndItsSource() {
            OpenPgpClaim claim = new OpenPgpClaim("armored", 4, FP, 1,
                    Instant.ofEpochSecond(1_700_000_000L));
            VerifyResult result = OpenPgpVerifyResult.verified("Alice", "RSA", 4, FP, FP);

            ClaimResult claimResult = ClaimResult.of(claim, "openpgp", result, OpenPgpCredentials.from(result), REF,
                    TrustRootRef.unknown(), "bc", Instant.ofEpochSecond(1_700_000_100L));

            assertThat(claimResult.kind()).isEqualTo("openpgp");
            assertThat(claimResult.outcome()).isEqualTo(ClaimOutcome.VERIFIED);
            assertThat(claimResult.claimTime()).isEqualTo(Instant.ofEpochSecond(1_700_000_000L));
            assertThat(claimResult.claimTimeSource()).isEqualTo(ClaimTimeSource.SIGNER);
            assertThat(claimResult.verifiedBy()).isEqualTo("bc");
        }

        @Test
        void aVerifiedClaimCarriesTheCredentialsItProves() {
            OpenPgpClaim claim = new OpenPgpClaim("armored", 4, FP, 1, null);
            VerifyResult result = OpenPgpVerifyResult.verified("Alice <alice@example.com>", "RSA", 4, FP, FP);

            ClaimResult claimResult = ClaimResult.of(claim, "openpgp", result, OpenPgpCredentials.from(result), REF,
                    TrustRootRef.unknown(), "bc", Instant.now());

            assertThat(claimResult.attesterCredentials()).containsExactly(
                    new FingerprintCredential(Credential.TYPE_OPENPGP_V4, FP),
                    new EmailCredential("alice@example.com"));
        }

        @Test
        void anIndeterminateClaimKeepsItsReason() {
            OpenPgpClaim claim = new OpenPgpClaim("armored", 4, FP, 1, null);
            VerifyResult result = OpenPgpVerifyResult.indeterminate(
                    IndeterminateReason.KEY_UNAVAILABLE, null, "RSA", 4, FP, FP);

            ClaimResult claimResult = ClaimResult.of(claim, "openpgp", result, OpenPgpCredentials.from(result), REF,
                    TrustRootRef.unknown(), "bc", Instant.now());

            assertThat(claimResult.outcome()).isEqualTo(ClaimOutcome.INDETERMINATE);
            assertThat(claimResult.reason()).isEqualTo(IndeterminateReason.KEY_UNAVAILABLE);
            assertThat(claimResult.attesterCredentials()).isEmpty();
        }

        @Test
        void aSigstoreClaimsTimeIsAssertedByTheLog() {
            SigstoreClaim claim = new SigstoreClaim("{}", Instant.ofEpochSecond(1_700_000_000L));
            VerifyResult result = SigstoreVerifyResult.indeterminate(IndeterminateReason.EVIDENCE_MALFORMED);

            ClaimResult claimResult = ClaimResult.of(claim, "sigstore", result, List.of(), REF,
                    TrustRootRef.sigstore("public-good"), "sigstore", Instant.now());

            assertThat(claimResult.kind()).isEqualTo("sigstore");
            assertThat(claimResult.claimTimeSource())
                    .isEqualTo(ClaimTimeSource.TRANSPARENCY_LOG);
        }
    }

    @Nested
    class Invariants {

        @Test
        void roleDefaultsToUnknownRatherThanPublisher() {
            ClaimResult result = new ClaimResult("openpgp", ClaimOutcome.VERIFIED, null,
                    List.of(), null, null, TrustRootRef.unknown(), REF, null,
                    ClaimTimeSource.SIGNER, Instant.EPOCH, "RSA", "bc");

            assertThat(result.role()).isEqualTo(AttesterRole.UNKNOWN);
        }

        @Test
        void evidenceIsRequired() {
            assertThatThrownBy(() -> verified(ClaimOutcome.VERIFIED, null, null, List.of()))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void anIndeterminateOutcomeNeedsAReason() {
            assertThatThrownBy(
                    () -> verified(ClaimOutcome.INDETERMINATE, null, REF, List.of()))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void aBlankKindIsRejected() {
            assertThatThrownBy(() -> new ClaimResult(" ", ClaimOutcome.VERIFIED, null,
                    List.of(), null, AttesterRole.UNKNOWN, TrustRootRef.unknown(), REF, null,
                    ClaimTimeSource.SIGNER, Instant.EPOCH, "RSA", "bc"))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void credentialsAreDefensivelyCopied() {
            List<Credential> credentials = new java.util.ArrayList<>();
            credentials.add(new FingerprintCredential(Credential.TYPE_OPENPGP_V4, FP));
            ClaimResult result = verified(ClaimOutcome.VERIFIED, null, REF, credentials);

            credentials.clear();

            assertThat(result.attesterCredentials()).hasSize(1);
        }
    }
}
