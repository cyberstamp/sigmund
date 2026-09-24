package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class DigestSetTest {

    private static final String HEX = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    private static final String OTHER_HEX = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752";

    @Nested
    class Construction {

        @Test
        void sha256FactoryStoresUnderSha256() {
            DigestSet digests = DigestSet.sha256(HEX);
            assertThat(digests.sha256()).isEqualTo(HEX);
            assertThat(digests.values()).containsExactly(Map.entry(DigestSet.SHA_256, HEX));
        }

        @Test
        void hexValuesAreNormalizedToLowerCase() {
            DigestSet digests = DigestSet.sha256(HEX.toUpperCase());
            assertThat(digests.sha256()).isEqualTo(HEX);
        }

        @Test
        void sha256ReturnsNullWhenAbsent() {
            DigestSet digests = new DigestSet(Map.of("sha512", OTHER_HEX));
            assertThat(digests.sha256()).isNull();
        }

        @Test
        void blankAlgorithmIsRejected() {
            assertThatThrownBy(() -> new DigestSet(Map.of(" ", HEX)))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void blankValueIsRejected() {
            assertThatThrownBy(() -> new DigestSet(Map.of(DigestSet.SHA_256, " ")))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    class Matching {

        @Test
        void matchesWhenSharedAlgorithmHasEqualValue() {
            assertThat(DigestSet.sha256(HEX).matches(DigestSet.sha256(HEX))).isTrue();
        }

        @Test
        void doesNotMatchWhenSharedAlgorithmDiffers() {
            assertThat(DigestSet.sha256(HEX).matches(DigestSet.sha256(OTHER_HEX))).isFalse();
        }

        @Test
        void doesNotMatchWhenNoAlgorithmIsShared() {
            DigestSet sha256 = DigestSet.sha256(HEX);
            DigestSet sha512 = new DigestSet(Map.of("sha512", OTHER_HEX));
            assertThat(sha256.matches(sha512)).isFalse();
        }

        @Test
        void doesNotMatchWhenEitherSideIsEmpty() {
            DigestSet empty = new DigestSet(Map.of());
            assertThat(empty.matches(DigestSet.sha256(HEX))).isFalse();
            assertThat(DigestSet.sha256(HEX).matches(empty)).isFalse();
        }

        @Test
        void matchesOnAnySharedAlgorithmWhenOthersAreAbsent() {
            DigestSet both = new DigestSet(Map.of(DigestSet.SHA_256, HEX, "sha512", OTHER_HEX));
            assertThat(both.matches(DigestSet.sha256(HEX))).isTrue();
        }

        @Test
        void doesNotMatchWhenOneSharedAlgorithmDisagrees() {
            DigestSet both = new DigestSet(Map.of(DigestSet.SHA_256, HEX, "sha512", OTHER_HEX));
            DigestSet conflicting = new DigestSet(
                    Map.of(DigestSet.SHA_256, HEX, "sha512", HEX));
            assertThat(both.matches(conflicting)).isFalse();
        }
    }
}
