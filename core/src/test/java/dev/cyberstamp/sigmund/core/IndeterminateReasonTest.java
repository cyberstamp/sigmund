package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class IndeterminateReasonTest {

    @Nested
    class Transience {

        @Test
        void keyUnavailableIsTransient() {
            assertThat(IndeterminateReason.KEY_UNAVAILABLE.isTransient()).isTrue();
        }

        @Test
        void trustRootUnavailableIsTransient() {
            assertThat(IndeterminateReason.TRUST_ROOT_UNAVAILABLE.isTransient()).isTrue();
        }

        @Test
        void discoveryUnavailableIsTransient() {
            assertThat(IndeterminateReason.DISCOVERY_UNAVAILABLE.isTransient()).isTrue();
        }

        @Test
        void unsupportedAlgorithmIsPermanent() {
            assertThat(IndeterminateReason.UNSUPPORTED_ALGORITHM.isTransient()).isFalse();
        }

        @Test
        void evidenceMalformedIsPermanent() {
            assertThat(IndeterminateReason.EVIDENCE_MALFORMED.isTransient()).isFalse();
        }
    }

    @Nested
    class Ranking {

        @Test
        void verifiedOutranksEverything() {
            assertThat(ClaimOutcome.VERIFIED.outranks(ClaimOutcome.FAILED)).isTrue();
            assertThat(ClaimOutcome.VERIFIED.outranks(ClaimOutcome.INDETERMINATE)).isTrue();
        }

        @Test
        void failedOutranksIndeterminate() {
            assertThat(ClaimOutcome.FAILED.outranks(ClaimOutcome.INDETERMINATE)).isTrue();
            assertThat(ClaimOutcome.INDETERMINATE.outranks(ClaimOutcome.FAILED)).isFalse();
        }

        @Test
        void anOutcomeDoesNotOutrankItself() {
            assertThat(ClaimOutcome.FAILED.outranks(ClaimOutcome.FAILED)).isFalse();
        }
    }
}
