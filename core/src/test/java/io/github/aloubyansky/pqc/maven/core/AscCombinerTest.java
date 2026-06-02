package io.github.aloubyansky.pqc.maven.core;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class AscCombinerTest {

    // Generate valid armored blocks for testing
    // These are structurally valid (proper CRC) but cryptographically meaningless
    private static final String ARMORED_BLOCK_1 = createTestBlock1();
    private static final String ARMORED_BLOCK_2 = createTestBlock2();

    private static String createTestBlock1() {
        // Create a small test packet with mock data
        byte[] testData = new byte[] {
                (byte) 0x88, 0x5E, 0x04, 0x00, 0x11, 0x08, 0x00, 0x06,
                0x05, 0x02, 0x61, 0x74, 0x00, 0x09, 0x00, 0x0A, 0x09, 0x10
        };
        return AscCombiner.armor(testData);
    }

    private static String createTestBlock2() {
        // Create a different small test packet with mock data
        byte[] testData = new byte[] {
                (byte) 0x88, 0x75, 0x04, 0x00, 0x16, 0x0A, 0x00, 0x06,
                0x05, 0x02, 0x61, 0x74, 0x00, 0x0A, 0x00, 0x0A, 0x09, 0x11
        };
        return AscCombiner.armor(testData);
    }

    // --- SEPARATE_BLOCKS mode (default) ---

    @Test
    void separateBlocks_preservesTwoArmoredBlocks() {
        String combined = AscCombiner.combine(ARMORED_BLOCK_1, ARMORED_BLOCK_2);

        assertEquals(2, countOccurrences(combined, "-----BEGIN PGP"));
        assertEquals(2, countOccurrences(combined, "-----END PGP"));
    }

    @Test
    void separateBlocks_classicBlockComesFirst() {
        String combined = AscCombiner.combine(ARMORED_BLOCK_1, ARMORED_BLOCK_2);

        assertTrue(combined.startsWith(ARMORED_BLOCK_1.stripTrailing()),
                "Combined output should start with the classic block");
    }

    // --- extractBlock ---

    @Test
    void extractBlock_returnsFirstBlock() {
        String combined = AscCombiner.combine(ARMORED_BLOCK_1, ARMORED_BLOCK_2);

        String first = AscCombiner.extractBlock(combined, 0);
        assertNotNull(first);
        assertEquals(1, countOccurrences(first, "-----BEGIN PGP"));
        assertArrayEquals(AscCombiner.dearmor(ARMORED_BLOCK_1), AscCombiner.dearmor(first));
    }

    @Test
    void extractBlock_returnsSecondBlock() {
        String combined = AscCombiner.combine(ARMORED_BLOCK_1, ARMORED_BLOCK_2);

        String second = AscCombiner.extractBlock(combined, 1);
        assertNotNull(second);
        assertEquals(1, countOccurrences(second, "-----BEGIN PGP"));
        assertArrayEquals(AscCombiner.dearmor(ARMORED_BLOCK_2), AscCombiner.dearmor(second));
    }

    @Test
    void extractBlock_returnsNullForOutOfRange() {
        String combined = AscCombiner.combine(ARMORED_BLOCK_1, ARMORED_BLOCK_2);

        assertNull(AscCombiner.extractBlock(combined, 2));
    }

    @Test
    void extractBlock_returnsNullFromSingleBlockForIndex1() {
        assertNull(AscCombiner.extractBlock(ARMORED_BLOCK_1, 1));
    }

    // --- dearmor ---

    @Test
    void dearmor_extractsRawBytes() {
        byte[] raw = AscCombiner.dearmor(ARMORED_BLOCK_1);

        assertNotNull(raw, "Dearmored result should not be null");
        assertTrue(raw.length > 0, "Dearmored result should not be empty");
    }

    private int countOccurrences(String text, String pattern) {
        int count = 0;
        int index = 0;
        while ((index = text.indexOf(pattern, index)) != -1) {
            count++;
            index += pattern.length();
        }
        return count;
    }
}
