package io.github.aloubyansky.sigmund.core;

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
    void extractV6IssuerFingerprint_v6() {
        // v6 signature with Issuer Fingerprint subpacket (type 33)
        byte[] fingerprint = new byte[32];
        for (int i = 0; i < 32; i++) {
            fingerprint[i] = (byte) (i + 1);
        }
        byte[] v6Sig = new byte[] {
                (byte) 0xC2, 0x34, // new format tag 2, body length 52
                0x06, // version 6
                0x00, // sig type
                0x11, // pubkey algo
                0x08, // hash algo
                0x02, // salt length
                (byte) 0xAA, (byte) 0xBB, // salt
                0x00, 0x00, 0x00, 0x23, // hashed subpacket data length (35)
                0x22, // subpacket length (34 = 1 type + 1 key version + 32 fp)
                0x21, // subpacket type 33 (Issuer Fingerprint)
                0x06, // key version 6
                // 32 bytes fingerprint filled below
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0x00, 0x00, 0x00, 0x00, // unhashed subpacket data length (0)
                0x00, 0x00, // hash prefix
        };
        System.arraycopy(fingerprint, 0, v6Sig, 16, 32);
        String armored = AscCombiner.armor(v6Sig);
        String expected = "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20";
        assertEquals(expected, AscCombiner.inspectSignaturePacket(armored).issuerFingerprint());
    }

    @Test
    void extractV6IssuerFingerprint_v4ReturnsNull() {
        assertNull(AscCombiner.inspectSignaturePacket(ARMORED_BLOCK_1).issuerFingerprint());
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

    @Test
    void extractPublicKeyAlgorithmIdV4() {
        // ARMORED_BLOCK_1 packet bytes: 0x88 0x5E 0x04 0x00 0x11 ...
        // bodyOffset=2, version=0x04, sigType=0x00, pubkeyAlgo=0x11 (17=DSA)
        assertEquals(0x11, AscCombiner.inspectSignaturePacket(ARMORED_BLOCK_1).algorithmId());
    }

    @Test
    void extractPublicKeyAlgorithmIdV6() {
        byte[] v6Data = new byte[] {
                (byte) 0x88, 0x10, 0x06, 0x00, 0x1F, 0x08, 0x00, 0x06,
                0x05, 0x02, 0x61, 0x74, 0x00, 0x09, 0x00, 0x0A, 0x09, 0x10
        };
        String armored = AscCombiner.armor(v6Data);
        assertEquals(0x1F, AscCombiner.inspectSignaturePacket(armored).algorithmId());
    }

    @Test
    void extractPublicKeyAlgorithmIdV3() {
        // v3 signature packet: version(03) hashLen(05) sigType(00)
        // creationTime(4 bytes) keyId(8 bytes) pubkeyAlgo(01=RSA) hashAlgo(02)
        byte[] v3Data = new byte[] {
                (byte) 0x88, 0x20, // tag 2 (signature), old format, 1-byte length
                0x03, // version 3
                0x05, // hash material length
                0x00, // signature type
                0x61, 0x74, 0x00, 0x00, // creation time
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // key ID (8 bytes)
                0x01, // public-key algorithm (1 = RSA)
                0x02, // hash algorithm
                0x00, 0x00, // hash prefix
                // ... (rest of signature data truncated for test)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        String armored = AscCombiner.armor(v3Data);
        AscCombiner.SignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);
        assertEquals(3, info.version());
        assertEquals(1, info.algorithmId()); // RSA
    }

    @Test
    void isPqcAlgorithmBoundaries() {
        assertFalse(AscCombiner.isPqcAlgorithm(28)); // Ed448
        assertFalse(AscCombiner.isPqcAlgorithm(29)); // unassigned
        assertTrue(AscCombiner.isPqcAlgorithm(30)); // ML-DSA-65+Ed25519
        assertTrue(AscCombiner.isPqcAlgorithm(31)); // ML-DSA-87+Ed448
        assertTrue(AscCombiner.isPqcAlgorithm(36)); // ML-KEM-1024+X448
        assertFalse(AscCombiner.isPqcAlgorithm(37)); // unassigned
    }

    @Test
    void algorithmNameKnown() {
        assertEquals("RSA", AscCombiner.algorithmName(1));
        assertEquals("DSA", AscCombiner.algorithmName(17));
        assertEquals("Ed25519", AscCombiner.algorithmName(27));
        assertEquals("ML-DSA-87+Ed448", AscCombiner.algorithmName(31));
    }

    @Test
    void algorithmNameUnknown() {
        assertNull(AscCombiner.algorithmName(99));
        assertNull(AscCombiner.algorithmName(-1));
    }

    @Test
    void isPqcAlgorithmNamePqc() {
        assertTrue(AscCombiner.isPqcAlgorithmName("ML-DSA-87+Ed448"));
        assertTrue(AscCombiner.isPqcAlgorithmName("ML-DSA-65+Ed25519"));
        assertTrue(AscCombiner.isPqcAlgorithmName("SLH-DSA-SHAKE-128s"));
    }

    @Test
    void isPqcAlgorithmNameClassical() {
        assertFalse(AscCombiner.isPqcAlgorithmName("RSA"));
        assertFalse(AscCombiner.isPqcAlgorithmName("Ed25519"));
        assertFalse(AscCombiner.isPqcAlgorithmName(null));
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
