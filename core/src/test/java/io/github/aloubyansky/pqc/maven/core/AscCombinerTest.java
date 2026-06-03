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

    // --- extractAllBlocks ---

    @Test
    void extractAllBlocks_twoBlocks() {
        String combined = AscCombiner.combine(ARMORED_BLOCK_1, ARMORED_BLOCK_2);
        var blocks = AscCombiner.extractAllBlocks(combined);
        assertEquals(2, blocks.size());
        assertArrayEquals(AscCombiner.dearmor(ARMORED_BLOCK_1), AscCombiner.dearmor(blocks.get(0)));
        assertArrayEquals(AscCombiner.dearmor(ARMORED_BLOCK_2), AscCombiner.dearmor(blocks.get(1)));
    }

    @Test
    void extractAllBlocks_singleBlock() {
        var blocks = AscCombiner.extractAllBlocks(ARMORED_BLOCK_1);
        assertEquals(1, blocks.size());
    }

    // --- detectSignatureVersion ---

    @Test
    void detectSignatureVersion_v4() {
        // ARMORED_BLOCK_1 has packet bytes starting with 0x88 0x5E 0x04
        // old format tag 2, 1-byte length, version 4
        assertEquals(4, AscCombiner.detectSignatureVersion(ARMORED_BLOCK_1));
    }

    @Test
    void detectSignatureVersion_v6() {
        // Create a block with version 6: old format tag 2, 1-byte length, version 6
        byte[] v6Data = new byte[] {
                (byte) 0x88, 0x10, 0x06, 0x00, 0x11, 0x08, 0x00, 0x06,
                0x05, 0x02, 0x61, 0x74, 0x00, 0x09, 0x00, 0x0A, 0x09, 0x10
        };
        String armored = AscCombiner.armor(v6Data);
        assertEquals(6, AscCombiner.detectSignatureVersion(armored));
    }

    @Test
    void detectSignatureVersion_newFormat() {
        // New format: 0xC2 = new format tag 2, 1-byte length < 192, version 4
        byte[] newFormatData = new byte[] {
                (byte) 0xC2, 0x10, 0x04, 0x00, 0x11, 0x08, 0x00, 0x06,
                0x05, 0x02, 0x61, 0x74, 0x00, 0x09, 0x00, 0x0A, 0x09, 0x10
        };
        String armored = AscCombiner.armor(newFormatData);
        assertEquals(4, AscCombiner.detectSignatureVersion(armored));
    }

    @Test
    void detectSignatureVersion_compressedDataWrapper() {
        // Compressed data packet (tag 8, old format, indeterminate length)
        // wrapping an uncompressed (algo=0) v4 signature packet
        byte[] compressedWrapped = new byte[] {
                (byte) 0xA3, // tag 8, old format, indeterminate length
                0x00, // compression algo = 0 (uncompressed)
                (byte) 0xC2, 0x10, // inner: new format tag 2, 1-byte length
                0x04, // version 4
                0x00, 0x11, 0x08, 0x00, 0x06,
                0x05, 0x02, 0x61, 0x74, 0x00, 0x09, 0x00, 0x0A, 0x09, 0x10
        };
        String armored = AscCombiner.armor(compressedWrapped);
        assertEquals(4, AscCombiner.detectSignatureVersion(armored));
    }

    @Test
    void detectSignatureVersion_compressedDataWrapper_v6() {
        byte[] compressedWrapped = new byte[] {
                (byte) 0xA3, // tag 8, old format, indeterminate length
                0x00, // compression algo = 0 (uncompressed)
                (byte) 0xC2, 0x10, // inner: new format tag 2, 1-byte length
                0x06, // version 6
                0x00, 0x11, 0x08, 0x00, 0x06,
                0x05, 0x02, 0x61, 0x74, 0x00, 0x09, 0x00, 0x0A, 0x09, 0x10
        };
        String armored = AscCombiner.armor(compressedWrapped);
        assertEquals(6, AscCombiner.detectSignatureVersion(armored));
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
