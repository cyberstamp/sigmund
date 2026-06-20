package io.github.aloubyansky.sigmund.core;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;

/**
 * Utility class for manipulating ASCII-armored OpenPGP data.
 * <p>
 * This class provides methods to dearmor (strip ASCII armor from) OpenPGP blocks,
 * armor (wrap in ASCII armor) raw OpenPGP packets, combine two armored blocks
 * into a single file, and extract individual blocks from a combined file.
 * <p>
 * This is particularly useful for combining classical and post-quantum signatures
 * into a single .asc file with two separate armored blocks.
 */
public final class AscCombiner {

    private static final String BEGIN_MARKER = "-----BEGIN PGP ";
    private static final String END_MARKER = "-----END PGP ";

    /**
     * Private constructor to prevent instantiation of this utility class.
     */
    private AscCombiner() {
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }

    /**
     * Strips ASCII armor from an armored OpenPGP block and returns raw packet bytes.
     * <p>
     * This method removes the ASCII armor envelope (including BEGIN/END markers,
     * headers, and Base64 encoding) from an OpenPGP armored block, returning the
     * underlying binary packet data.
     *
     * @param armored the ASCII-armored OpenPGP block (e.g., a PGP signature)
     * @return the raw OpenPGP packet bytes
     * @throws UncheckedIOException if an I/O error occurs during dearmoring
     * @throws IllegalArgumentException if the input is null or empty
     */
    public static byte[] dearmor(String armored) {
        assertNotEmpty(armored, "Armored input");

        try {
            return dearmorInternal(armored);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to dearmor PGP block", e);
        }
    }

    /**
     * Wraps raw OpenPGP packet bytes in ASCII armor and returns an armored string.
     * <p>
     * This method encodes binary OpenPGP packet data as ASCII-armored text with
     * appropriate BEGIN/END markers, making it suitable for text-based transmission
     * and storage.
     *
     * @param rawPackets the raw OpenPGP packet bytes to armor
     * @return the ASCII-armored OpenPGP block as a string
     * @throws UncheckedIOException if an I/O error occurs during armoring
     * @throws IllegalArgumentException if the input is null or empty
     */
    public static String armor(byte[] rawPackets) {
        assertNotEmpty(rawPackets, "Raw packet data");

        try {
            return armorInternal(rawPackets);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to armor PGP packets", e);
        }
    }

    /**
     * Combines two ASCII-armored OpenPGP blocks into a single file as two
     * separate armored blocks (classic first, PQC second).
     * <p>
     * This format is compatible with Maven Central and other verifiers that
     * only read the first armored block.
     *
     * @param armoredClassic the first ASCII-armored block (typically a classical signature)
     * @param armoredPqc the second ASCII-armored block (typically a PQC signature)
     * @return the combined result
     * @throws IllegalArgumentException if either input is null or empty
     */
    public static String combine(String armoredClassic, String armoredPqc) {
        assertNotEmpty(armoredClassic, "First armored input");
        assertNotEmpty(armoredPqc, "Second armored input");
        return armoredClassic.stripTrailing() + "\n" + armoredPqc.stripTrailing() + "\n";
    }

    /**
     * Extracts the Nth armored block (0-based) from a string that may
     * contain multiple concatenated armored blocks.
     *
     * @param combined the string containing one or more armored blocks
     * @param index the 0-based index of the block to extract
     * @return the extracted armored block, or null if the index is out of range
     * @throws IllegalArgumentException if combined is null or empty
     */
    public static String extractBlock(String combined, int index) {
        assertNotEmpty(combined, "Combined input");

        int blockIndex = 0;
        int searchFrom = 0;
        while (searchFrom < combined.length()) {
            int beginPos = combined.indexOf(BEGIN_MARKER, searchFrom);
            if (beginPos < 0) {
                return null;
            }
            int endMarkerPos = combined.indexOf(END_MARKER, beginPos + BEGIN_MARKER.length());
            if (endMarkerPos < 0) {
                return null;
            }
            int endOfLine = combined.indexOf('\n', endMarkerPos);
            int blockEnd = (endOfLine >= 0) ? endOfLine + 1 : combined.length();

            if (blockIndex == index) {
                return combined.substring(beginPos, blockEnd);
            }
            blockIndex++;
            searchFrom = blockEnd;
        }
        return null;
    }

    /**
     * Extracts all armored blocks from a string that may contain multiple
     * concatenated armored blocks.
     *
     * @param combined the string containing one or more armored blocks
     * @return a list of all armored blocks found, in order
     * @throws IllegalArgumentException if combined is null or empty
     */
    public static List<String> extractAllBlocks(String combined) {
        assertNotEmpty(combined, "Combined input");

        List<String> blocks = new ArrayList<>();
        int searchFrom = 0;
        while (searchFrom < combined.length()) {
            int beginPos = combined.indexOf(BEGIN_MARKER, searchFrom);
            if (beginPos < 0) {
                break;
            }
            int endMarkerPos = combined.indexOf(END_MARKER, beginPos + BEGIN_MARKER.length());
            if (endMarkerPos < 0) {
                break;
            }
            int endOfLine = combined.indexOf('\n', endMarkerPos);
            int blockEnd = (endOfLine >= 0) ? endOfLine + 1 : combined.length();
            blocks.add(combined.substring(beginPos, blockEnd));
            searchFrom = blockEnd;
        }
        return blocks;
    }

    /**
     * Metadata extracted from a signature packet in a single dearmor pass.
     *
     * @param version the OpenPGP signature version (e.g., 4 or 6), or -1 if detection fails
     * @param algorithmId the public-key algorithm ID, or -1 if extraction fails
     * @param issuerFingerprint the issuer fingerprint as an uppercase hex string, or null if not found
     */
    public record SignaturePacketInfo(int version, int algorithmId, String issuerFingerprint) {
    }

    /**
     * Extracts version, algorithm ID, and issuer fingerprint from an armored
     * block in a single dearmor pass.
     *
     * @param armoredBlock a single ASCII-armored OpenPGP block
     * @return the extracted metadata
     */
    public static SignaturePacketInfo inspectSignaturePacket(String armoredBlock) {
        try {
            byte[] raw = dearmorInternal(armoredBlock);
            int version = detectVersionFromPackets(raw);
            int bodyOffset = packetBodyOffset(raw);
            int algoId = extractPublicKeyAlgoId(raw, bodyOffset, version);
            String fingerprint = (version >= 5)
                    ? extractIssuerFingerprintFromPackets(raw)
                    : null;
            return new SignaturePacketInfo(version, algoId, fingerprint);
        } catch (IOException e) {
            return new SignaturePacketInfo(-1, -1, null);
        }
    }

    /**
     * Detects the OpenPGP signature version from an armored block.
     *
     * @param armoredBlock a single ASCII-armored OpenPGP block
     * @return the signature version (e.g., 4 or 6), or -1 if detection fails
     */
    public static int detectSignatureVersion(String armoredBlock) {
        try {
            byte[] raw = dearmorInternal(armoredBlock);
            return detectVersionFromPackets(raw);
        } catch (IOException e) {
            return -1;
        }
    }

    // IANA OpenPGP Public Key Algorithms registry (RFC 9580 + RFC 9980)
    private static final Map<Integer, String> ALGORITHM_NAMES = Map.ofEntries(
            Map.entry(1, "RSA"),
            Map.entry(2, "RSA"),
            Map.entry(3, "RSA"),
            Map.entry(16, "Elgamal"),
            Map.entry(17, "DSA"),
            Map.entry(18, "ECDH"),
            Map.entry(19, "ECDSA"),
            Map.entry(22, "EdDSA"),
            Map.entry(25, "X25519"),
            Map.entry(26, "X448"),
            Map.entry(27, "Ed25519"),
            Map.entry(28, "Ed448"),
            Map.entry(30, "ML-DSA-65+Ed25519"),
            Map.entry(31, "ML-DSA-87+Ed448"),
            Map.entry(32, "SLH-DSA-SHAKE-128s"),
            Map.entry(33, "SLH-DSA-SHAKE-128f"),
            Map.entry(34, "SLH-DSA-SHAKE-256s"),
            Map.entry(35, "ML-KEM-768+X25519"),
            Map.entry(36, "ML-KEM-1024+X448"));

    /**
     * Returns the human-readable name for an OpenPGP public-key algorithm ID.
     *
     * @param algorithmId the IANA-registered algorithm ID
     * @return the algorithm name, or null if the ID is not recognized
     */
    static String algorithmName(int algorithmId) {
        return ALGORITHM_NAMES.get(algorithmId);
    }

    /**
     * Checks whether an OpenPGP public-key algorithm ID designates a
     * post-quantum composite or standalone algorithm.
     * <p>
     * This check is based on the IANA OpenPGP Public Key Algorithms registry
     * as of RFC 9980. The PQC algorithm IDs are 30-36 (ML-DSA, SLH-DSA,
     * ML-KEM composites). This range may need updating as new PQC algorithms
     * are registered with IANA.
     *
     * @param algorithmId the IANA-registered algorithm ID
     * @return true if the algorithm is PQC
     */
    static boolean isPqcAlgorithm(int algorithmId) {
        return algorithmId >= 30 && algorithmId <= 36;
    }

    /**
     * Checks whether an algorithm name corresponds to a PQC algorithm.
     *
     * @param algorithmName the algorithm name to check
     * @return true if the name matches a known PQC algorithm
     */
    static boolean isPqcAlgorithmName(String algorithmName) {
        if (algorithmName == null) {
            return false;
        }
        for (var entry : ALGORITHM_NAMES.entrySet()) {
            if (isPqcAlgorithm(entry.getKey()) && algorithmName.equals(entry.getValue())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Extracts the public-key algorithm ID from the signature packet body.
     * v3 packets have a different layout (algo at offset 15) than v4+ (offset 2).
     */
    private static int extractPublicKeyAlgoId(byte[] raw, int bodyOffset, int version) {
        if (bodyOffset < 0) {
            return -1;
        }
        if (version == 3) {
            int offset = bodyOffset + 15;
            return offset < raw.length ? raw[offset] & 0xFF : -1;
        }
        int offset = bodyOffset + 2;
        return offset < raw.length ? raw[offset] & 0xFF : -1;
    }

    private static final int SUBPACKET_TYPE_ISSUER_FINGERPRINT = 33;

    private static String extractIssuerFingerprintFromPackets(byte[] raw) {
        int bodyOffset = packetBodyOffset(raw);
        if (bodyOffset < 0 || bodyOffset >= raw.length) {
            return null;
        }
        int version = raw[bodyOffset] & 0xFF;
        if (version < 5) {
            return null;
        }
        // After version, sig type, pubkey algo, hash algo:
        int base = bodyOffset + 4;
        // Some v6 implementations (e.g. sq for PQC) omit the salt field;
        // RFC 9580 v6 includes salt length + salt before the hashed subpackets.
        // Try without salt first, then with salt.
        String fp = tryExtractFromSubpackets(raw, base);
        if (fp == null && base < raw.length) {
            int saltLen = raw[base] & 0xFF;
            fp = tryExtractFromSubpackets(raw, base + 1 + saltLen);
        }
        return fp;
    }

    private static String tryExtractFromSubpackets(byte[] raw, int pos) {
        if (pos + 4 > raw.length) {
            return null;
        }
        int hashedLen = ((raw[pos] & 0xFF) << 24) | ((raw[pos + 1] & 0xFF) << 16)
                | ((raw[pos + 2] & 0xFF) << 8) | (raw[pos + 3] & 0xFF);
        if (hashedLen < 0 || hashedLen > 65535 || pos + 4 + hashedLen > raw.length) {
            return null;
        }
        pos += 4;
        String fp = findIssuerFingerprint(raw, pos, pos + hashedLen);
        if (fp != null) {
            return fp;
        }
        pos += hashedLen;
        if (pos + 4 > raw.length) {
            return null;
        }
        int unhashedLen = ((raw[pos] & 0xFF) << 24) | ((raw[pos + 1] & 0xFF) << 16)
                | ((raw[pos + 2] & 0xFF) << 8) | (raw[pos + 3] & 0xFF);
        if (unhashedLen < 0 || unhashedLen > 65535 || pos + 4 + unhashedLen > raw.length) {
            return null;
        }
        pos += 4;
        return findIssuerFingerprint(raw, pos, pos + unhashedLen);
    }

    private static String findIssuerFingerprint(byte[] data, int start, int end) {
        int pos = start;
        while (pos < end) {
            if (pos >= data.length) {
                return null;
            }
            int lenByte = data[pos] & 0xFF;
            int subLen;
            if (lenByte < 192) {
                subLen = lenByte;
                pos += 1;
            } else if (lenByte < 255) {
                if (pos + 1 >= data.length) {
                    return null;
                }
                subLen = ((lenByte - 192) << 8) + (data[pos + 1] & 0xFF) + 192;
                pos += 2;
            } else {
                if (pos + 4 >= data.length) {
                    return null;
                }
                subLen = ((data[pos + 1] & 0xFF) << 24) | ((data[pos + 2] & 0xFF) << 16)
                        | ((data[pos + 3] & 0xFF) << 8) | (data[pos + 4] & 0xFF);
                pos += 5;
            }
            if (subLen < 1 || pos + subLen > data.length) {
                return null;
            }
            int type = data[pos] & 0x7F; // bit 7 is the critical flag
            if (type == SUBPACKET_TYPE_ISSUER_FINGERPRINT && subLen >= 2) {
                int fpLen = subLen - 2; // minus type byte and key version byte
                if (fpLen > 0) {
                    StringBuilder sb = new StringBuilder(fpLen * 2);
                    for (int i = 0; i < fpLen; i++) {
                        sb.append(String.format("%02X", data[pos + 2 + i]));
                    }
                    return sb.toString();
                }
            }
            pos += subLen;
        }
        return null;
    }

    private static final int TAG_SIGNATURE = 2;
    private static final int TAG_COMPRESSED_DATA = 8;

    private static int detectVersionFromPackets(byte[] raw) {
        if (raw.length < 2) {
            return -1;
        }
        int firstByte = raw[0] & 0xFF;
        if ((firstByte & 0x80) == 0) {
            return -1;
        }
        int tag = packetTag(firstByte);
        int bodyOffset = packetBodyOffset(raw);
        if (bodyOffset < 0 || bodyOffset >= raw.length) {
            return -1;
        }
        if (tag == TAG_COMPRESSED_DATA) {
            int algo = raw[bodyOffset] & 0xFF;
            if (algo == 0) {
                int innerStart = bodyOffset + 1;
                if (innerStart >= raw.length) {
                    return -1;
                }
                byte[] inner = new byte[raw.length - innerStart];
                System.arraycopy(raw, innerStart, inner, 0, inner.length);
                return detectVersionFromPackets(inner);
            }
            return -1;
        }
        return raw[bodyOffset] & 0xFF;
    }

    private static int packetTag(int firstByte) {
        if ((firstByte & 0x40) != 0) {
            return firstByte & 0x3F;
        }
        return (firstByte >> 2) & 0x0F;
    }

    /**
     * Computes the offset of the packet body within raw OpenPGP packet data,
     * skipping the tag byte and length field.
     */
    private static int packetBodyOffset(byte[] raw) {
        if (raw.length < 2) {
            return -1;
        }
        int firstByte = raw[0] & 0xFF;
        if ((firstByte & 0x80) == 0) {
            return -1;
        }
        if ((firstByte & 0x40) != 0) {
            // New format: tag byte + variable-length length
            int lenByte = raw[1] & 0xFF;
            if (lenByte < 192) {
                return 2;
            }
            if (lenByte < 224) {
                return 3;
            }
            if (lenByte == 255) {
                return 6;
            }
            return 2; // partial body length
        }
        // Old format: tag byte encodes length type in bits 0-1
        int lengthType = firstByte & 0x03;
        return switch (lengthType) {
            case 0 -> 2;
            case 1 -> 3;
            case 2 -> 5;
            case 3 -> 1;
            default -> -1;
        };
    }

    /**
     * Internal implementation of dearmoring that throws checked IOException.
     *
     * @param armored the ASCII-armored input
     * @return the raw packet bytes
     * @throws IOException if an I/O error occurs
     */
    private static byte[] dearmorInternal(String armored) throws IOException {
        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(armored.getBytes());
                ArmoredInputStream armoredInputStream = new ArmoredInputStream(inputStream)) {
            return readAllBytes(armoredInputStream);
        }
    }

    /**
     * Internal implementation of armoring that throws checked IOException.
     *
     * @param rawPackets the raw packet bytes to armor
     * @return the ASCII-armored string
     * @throws IOException if an I/O error occurs
     */
    private static String armorInternal(byte[] rawPackets) throws IOException {
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream)) {
            armoredOutputStream.write(rawPackets);
            armoredOutputStream.close();
            return outputStream.toString();
        }
    }

    /**
     * Reads all bytes from an ArmoredInputStream into a byte array.
     *
     * @param inputStream the armored input stream to read from
     * @return all bytes read from the stream
     * @throws IOException if an I/O error occurs
     */
    private static byte[] readAllBytes(ArmoredInputStream inputStream) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[4096];
        int bytesRead;
        while ((bytesRead = inputStream.read(chunk)) != -1) {
            buffer.write(chunk, 0, bytesRead);
        }
        return buffer.toByteArray();
    }

    /**
     * Validates that a String input is not null or empty.
     *
     * @param input the input to validate
     * @param paramName the parameter name for error messages
     * @throws IllegalArgumentException if the input is null or empty
     */
    private static void assertNotEmpty(String input, String paramName) {
        if (input == null || input.isEmpty()) {
            throw new IllegalArgumentException(paramName + " must not be null or empty");
        }
    }

    /**
     * Validates that a byte array input is not null or empty.
     *
     * @param input the input to validate
     * @param paramName the parameter name for error messages
     * @throws IllegalArgumentException if the input is null or empty
     */
    private static void assertNotEmpty(byte[] input, String paramName) {
        if (input == null || input.length == 0) {
            throw new IllegalArgumentException(paramName + " must not be null or empty");
        }
    }
}
