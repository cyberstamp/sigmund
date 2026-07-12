package io.github.aloubyansky.sigmund.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class FingerprintCredentialTest {

    @Nested
    class Matching {

        @Test
        void exactMatch() {
            var a = new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23AB01CD23");
            var b = new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23AB01CD23");
            assertTrue(a.matches(b));
            assertTrue(b.matches(a));
        }

        @Test
        void suffixMatch_shortIsSubsetOfLong() {
            var full = new FingerprintCredential("openpgp4",
                    "AB01CD23EF45678901234AEE18F83AFDEB230042");
            var shortFp = new FingerprintCredential("openpgp4",
                    "4AEE18F83AFDEB230042");
            assertTrue(full.matches(shortFp));
            assertTrue(shortFp.matches(full));
        }

        @Test
        void caseInsensitive() {
            var upper = new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23");
            var lower = new FingerprintCredential("openpgp4", "4aee18f83afdeb23");
            assertTrue(upper.matches(lower));
        }

        @Test
        void tooShort_noMatch() {
            var a = new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23");
            var b = new FingerprintCredential("openpgp4", "3AFDEB23");
            assertFalse(a.matches(b));
        }

        @Test
        void differentType_noMatch() {
            var v4 = new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23");
            var v6 = new FingerprintCredential("openpgp6", "4AEE18F83AFDEB23");
            assertFalse(v4.matches(v6));
        }

        @Test
        void differentFingerprint_noMatch() {
            var a = new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23");
            var b = new FingerprintCredential("openpgp4", "AAEE18F83AFDEB23");
            assertFalse(a.matches(b));
        }

        @Test
        void crossType_noMatch() {
            var fp = new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23");
            var email = new EmailCredential("alice@example.com");
            assertFalse(fp.matches(email));
        }
    }

    @Nested
    class Properties {

        @Test
        void type() {
            var cred = new FingerprintCredential("openpgp6", "ABCD1234ABCD1234");
            assertEquals("openpgp6", cred.type());
        }

        @Test
        void displayName_returnsFingerprint() {
            var cred = new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23");
            assertEquals("4AEE18F83AFDEB23", cred.displayName());
        }
    }

    @Nested
    class Validation {

        @Test
        void nullType_throws() {
            assertThrows(IllegalArgumentException.class,
                    () -> new FingerprintCredential(null, "4AEE18F83AFDEB23"));
        }

        @Test
        void blankFingerprint_throws() {
            assertThrows(IllegalArgumentException.class,
                    () -> new FingerprintCredential("openpgp4", "  "));
        }
    }
}
