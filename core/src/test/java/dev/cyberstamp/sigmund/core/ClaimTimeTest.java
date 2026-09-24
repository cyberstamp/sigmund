package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class ClaimTimeTest {

    @Nested
    class OpenPgp {

        @Test
        void claimTimeIsTheSignatureCreationTime() {
            Instant made = Instant.ofEpochSecond(1_700_000_000L);
            OpenPgpClaim claim = new OpenPgpClaim("block", 4, "ABCD", 22, made);

            assertThat(claim.claimTime()).isEqualTo(made);
        }

        @Test
        void theSignerAssertsTheTime() {
            OpenPgpClaim claim = new OpenPgpClaim("block", 4, "ABCD", 22, Instant.EPOCH);

            assertThat(claim.claimTimeSource()).isEqualTo(ClaimTimeSource.SIGNER);
        }

        @Test
        void claimTimeMayBeAbsent() {
            OpenPgpClaim claim = new OpenPgpClaim("block", 4, "ABCD", 22, null);

            assertThat(claim.claimTime()).isNull();
            assertThat(claim.claimTimeSource()).isEqualTo(ClaimTimeSource.SIGNER);
        }
    }

    @Nested
    class Sigstore {

        @Test
        void claimTimeIsTheLogsIntegratedTime() {
            Instant logged = Instant.ofEpochSecond(1_700_000_500L);
            SigstoreClaim claim = new SigstoreClaim("{}", logged);

            assertThat(claim.claimTime()).isEqualTo(logged);
        }

        @Test
        void theTransparencyLogAssertsTheTime() {
            SigstoreClaim claim = new SigstoreClaim("{}", Instant.EPOCH);

            assertThat(claim.claimTimeSource()).isEqualTo(ClaimTimeSource.TRANSPARENCY_LOG);
        }
    }
}
