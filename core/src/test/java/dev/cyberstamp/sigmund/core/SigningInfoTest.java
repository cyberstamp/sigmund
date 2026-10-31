package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class SigningInfoTest {

    @Nested
    class Display {

        @Test
        void showsTypeAlgorithmFingerprintAndUserId() {
            assertThat(new SigningInfo("sq", "AB12", "Ed25519", "A <a@x>", "pgp6").display())
                    .isEqualTo("sq: pgp6 Ed25519 AB12 (A <a@x>)");
        }

        @Test
        void anUnreadableKeyShowsTypeUnknown() {
            assertThat(new SigningInfo("bc", "key.asc", null, null, null).display())
                    .isEqualTo("bc: type unknown key.asc");
        }
    }
}
