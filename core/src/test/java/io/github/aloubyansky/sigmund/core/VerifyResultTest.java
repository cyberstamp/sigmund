package io.github.aloubyansky.sigmund.core;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class VerifyResultTest {

    @Nested
    class EvidenceResultTests {

        @Test
        void nullVerifyResult_throws() {
            assertThrows(IllegalArgumentException.class,
                    () -> new EvidenceResult(null, List.of(), "test"));
        }
    }

    @Nested
    class UnverifiedResultTests {

        @Test
        void skippedVerdict() {
            var result = new UnverifiedResult(Verdict.SKIPPED);
            assertEquals(Verdict.SKIPPED, result.verdict());
            assertNull(result.signerDisplayName());
            assertNull(result.algorithm());
            assertNull(result.signerIdentifier());
        }

        @Test
        void failVerdict() {
            var result = new UnverifiedResult(Verdict.FAIL);
            assertEquals(Verdict.FAIL, result.verdict());
        }

        @Test
        void noKeyVerdict() {
            var result = new UnverifiedResult(Verdict.NO_KEY);
            assertEquals(Verdict.NO_KEY, result.verdict());
        }

        @Test
        void passVerdict_throws() {
            assertThrows(IllegalArgumentException.class,
                    () -> new UnverifiedResult(Verdict.PASS));
        }
    }

    @Nested
    class OpenPgpPreferredKeyId {

        @Test
        void prefersFingerprint() {
            var result = new OpenPgpVerifyResult(Verdict.PASS, null, null, 4, "SHORT", "FULL_FP");
            assertEquals("FULL_FP", result.preferredKeyId());
        }

        @Test
        void fallsBackToKeyId() {
            var result = new OpenPgpVerifyResult(Verdict.PASS, null, null, 4, "SHORT", null);
            assertEquals("SHORT", result.preferredKeyId());
        }

        @Test
        void nullWhenBothNull() {
            var result = new OpenPgpVerifyResult(Verdict.PASS, null, null, 4, null, null);
            assertNull(result.preferredKeyId());
        }
    }

    @Nested
    class SignerIdentifier {

        @Test
        void openPgp_returnsPreferredKeyId() {
            var result = new OpenPgpVerifyResult(Verdict.PASS, null, null, 4, "SHORT", "FULL_FP");
            assertEquals("FULL_FP", result.signerIdentifier());
        }

        @Test
        void openPgp_fallsBackToKeyId() {
            var result = new OpenPgpVerifyResult(Verdict.PASS, null, null, 6, "SHORT", null);
            assertEquals("SHORT", result.signerIdentifier());
        }

        @Test
        void sigstore_returnsNull() {
            var result = new SigstoreVerifyResult(Verdict.PASS, "alice@example.com", "ECDSA",
                    "https://accounts.google.com", "12345");
            assertNull(result.signerIdentifier());
        }

        @Test
        void unverified_returnsNull() {
            var result = new UnverifiedResult(Verdict.SKIPPED);
            assertNull(result.signerIdentifier());
        }
    }
}
