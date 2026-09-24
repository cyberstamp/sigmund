package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class KeyValidityTest {

    private static final Instant CREATED = Instant.ofEpochSecond(1_600_000_000L);
    private static final long ONE_YEAR = 365L * 24 * 60 * 60;

    @Nested
    class WithinValidity {

        @Test
        void signatureMadeWhileTheKeyWasValid() {
            assertThat(KeyValidity.isWithinValidity(CREATED, ONE_YEAR, CREATED.plusSeconds(10)))
                    .isTrue();
        }

        @Test
        void signatureMadeAfterExpiry() {
            assertThat(KeyValidity.isWithinValidity(
                    CREATED, ONE_YEAR, CREATED.plusSeconds(ONE_YEAR + 1))).isFalse();
        }

        @Test
        void signatureMadeBeforeTheKeyExisted() {
            assertThat(KeyValidity.isWithinValidity(CREATED, ONE_YEAR, CREATED.minusSeconds(1)))
                    .isFalse();
        }

        @Test
        void keyThatNeverExpires() {
            assertThat(KeyValidity.isWithinValidity(CREATED, 0, CREATED.plusSeconds(ONE_YEAR * 50)))
                    .isTrue();
        }

        @Test
        void expiryIsJudgedAtClaimTimeNotNow() {
            // the key expired long ago, but the signature was made while it was valid
            Instant madeWhileValid = CREATED.plusSeconds(ONE_YEAR / 2);
            assertThat(KeyValidity.isWithinValidity(CREATED, ONE_YEAR, madeWhileValid)).isTrue();
        }

        @Test
        void withoutAClaimTimeValidityCannotBeJudged() {
            assertThat(KeyValidity.isWithinValidity(CREATED, ONE_YEAR, null)).isTrue();
        }
    }
}
