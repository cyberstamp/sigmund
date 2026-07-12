package io.github.aloubyansky.sigmund.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class AlgorithmsTest {

    @Nested
    class AlgorithmName {

        @Test
        void rsa() {
            assertEquals("RSA", Algorithms.algorithmName(1));
            assertEquals("RSA", Algorithms.algorithmName(2));
            assertEquals("RSA", Algorithms.algorithmName(3));
        }

        @Test
        void edDsa() {
            assertEquals("EdDSA", Algorithms.algorithmName(22));
        }

        @Test
        void pqcComposites() {
            assertEquals("ML-DSA-65+Ed25519", Algorithms.algorithmName(30));
            assertEquals("ML-DSA-87+Ed448", Algorithms.algorithmName(31));
            assertEquals("SLH-DSA-SHAKE-128s", Algorithms.algorithmName(32));
        }

        @Test
        void unknownId_returnsNull() {
            assertNull(Algorithms.algorithmName(99));
            assertNull(Algorithms.algorithmName(-1));
        }
    }

    @Nested
    class IsPqcAlgorithm {

        @Test
        void pqcRange() {
            assertTrue(Algorithms.isPqcAlgorithm(30));
            assertTrue(Algorithms.isPqcAlgorithm(36));
            assertTrue(Algorithms.isPqcAlgorithm(33));
        }

        @Test
        void classicalRange() {
            assertFalse(Algorithms.isPqcAlgorithm(1));
            assertFalse(Algorithms.isPqcAlgorithm(22));
            assertFalse(Algorithms.isPqcAlgorithm(29));
        }

        @Test
        void outsideRange() {
            assertFalse(Algorithms.isPqcAlgorithm(37));
            assertFalse(Algorithms.isPqcAlgorithm(-1));
        }
    }

    @Nested
    class IsPqcAlgorithmName {

        @Test
        void pqcNames() {
            assertTrue(Algorithms.isPqcAlgorithmName("ML-DSA-65+Ed25519"));
            assertTrue(Algorithms.isPqcAlgorithmName("ML-DSA-87+Ed448"));
            assertTrue(Algorithms.isPqcAlgorithmName("SLH-DSA-SHAKE-128s"));
            assertTrue(Algorithms.isPqcAlgorithmName("ML-KEM-768+X25519"));
        }

        @Test
        void classicalNames() {
            assertFalse(Algorithms.isPqcAlgorithmName("RSA"));
            assertFalse(Algorithms.isPqcAlgorithmName("EdDSA"));
            assertFalse(Algorithms.isPqcAlgorithmName("ECDSA"));
        }

        @Test
        void unknownName() {
            assertFalse(Algorithms.isPqcAlgorithmName("UNKNOWN"));
        }

        @Test
        void nullName() {
            assertFalse(Algorithms.isPqcAlgorithmName(null));
        }
    }

    @Nested
    class VersionLabel {

        @Test
        void v4() {
            assertEquals("PGP4", Algorithms.versionLabel(4));
        }

        @Test
        void v6() {
            assertEquals("PGP6", Algorithms.versionLabel(6));
        }

        @Test
        void otherPositive() {
            assertEquals("PGP3", Algorithms.versionLabel(3));
            assertEquals("PGP5", Algorithms.versionLabel(5));
        }

        @Test
        void zeroReturnsDash() {
            assertEquals("-", Algorithms.versionLabel(0));
        }

        @Test
        void negativeReturnsDash() {
            assertEquals("-", Algorithms.versionLabel(-1));
        }
    }
}
