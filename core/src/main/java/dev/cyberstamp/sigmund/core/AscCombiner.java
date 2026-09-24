package dev.cyberstamp.sigmund.core;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
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
final class AscCombiner {

    private static final String BEGIN_MARKER = "-----BEGIN PGP ";
    private static final String END_MARKER = "-----END PGP ";

    /** Packet tag for compressed data, which may wrap a signature packet. */
    private static final int TAG_COMPRESSED_DATA = 8;

    /** Signature subpacket type carrying the signer's key fingerprint (RFC 9580 §5.2.3.35). */
    private static final int SUBPACKET_TYPE_ISSUER_FINGERPRINT = 33;

    /** Signature subpacket type carrying the signature creation time (RFC 9580 §5.2.3.11). */
    private static final int SUBPACKET_TYPE_CREATION_TIME = 2;

    /**
     * A half-open range of bytes within a dearmored packet: the subpacket areas of a
     * signature, and the value of a single subpacket inside them.
     *
     * @param start index of the first byte
     * @param end index one past the last byte
     */
    private record ByteRange(int start, int end) {
    }

    /**
     * The hashed and unhashed subpacket areas of a signature packet.
     *
     * <p>
     * Locating them differs by version: v4 declares two-byte area lengths, while v6 declares
     * four-byte lengths and may carry a salt before them. Resolving the areas once means
     * every subpacket — issuer fingerprint, creation time — is read from the same place.
     *
     * @param hashed the area covered by the signature
     * @param unhashed the area that is not covered by the signature
     */
    private record SubpacketAreas(ByteRange hashed, ByteRange unhashed) {
    }

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
     * Extracts version, algorithm ID, and issuer fingerprint from an armored
     * block in a single dearmor pass.
     *
     * @param armoredBlock a single ASCII-armored OpenPGP block
     * @return the extracted metadata
     */
    public static OpenPgpSignaturePacketInfo inspectSignaturePacket(String armoredBlock) {
        try {
            byte[] raw = dearmorInternal(armoredBlock);
            int version = detectVersionFromPackets(raw);
            int bodyOffset = packetBodyOffset(raw);
            int algoId = extractPublicKeyAlgoId(raw, bodyOffset, version);
            SubpacketAreas areas = resolveSubpacketAreas(raw);
            String fingerprint = extractIssuerFingerprintFromPackets(raw, areas);
            Instant creationTime = extractCreationTimeFromPackets(raw, areas);
            return new OpenPgpSignaturePacketInfo(version, algoId, fingerprint, creationTime);
        } catch (IOException e) {
            return new OpenPgpSignaturePacketInfo(-1, -1, null, null);
        }
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

    private static SubpacketAreas resolveSubpacketAreas(byte[] raw) {
        int bodyOffset = packetBodyOffset(raw);
        if (bodyOffset < 0 || bodyOffset >= raw.length) {
            return null;
        }
        int version = raw[bodyOffset] & 0xFF;
        // version(1) + signature type(1) + public-key algorithm(1) + hash algorithm(1)
        int base = bodyOffset + 4;
        if (version == 4) {
            return areasWithLengthSize(raw, base, 2);
        }
        // Some v6 implementations (sq for PQC among them) omit the salt RFC 9580 specifies,
        // so try the layout without a salt first and fall back to skipping one. The variant
        // that yields an issuer fingerprint is the one that parsed correctly.
        SubpacketAreas withoutSalt = areasWithLengthSize(raw, base, 4);
        if (carriesIssuerFingerprint(raw, withoutSalt)) {
            return withoutSalt;
        }
        if (base < raw.length) {
            int saltLength = raw[base] & 0xFF;
            SubpacketAreas withSalt = areasWithLengthSize(raw, base + 1 + saltLength, 4);
            if (carriesIssuerFingerprint(raw, withSalt)) {
                return withSalt;
            }
        }
        return withoutSalt;
    }

    private static boolean carriesIssuerFingerprint(byte[] raw, SubpacketAreas areas) {
        return areas != null && findIssuerFingerprint(raw, areas.hashed()) != null;
    }

    private static SubpacketAreas areasWithLengthSize(byte[] raw, int pos, int lengthSize) {
        int hashedLength = readLength(raw, pos, lengthSize);
        if (hashedLength < 0) {
            return null;
        }
        int hashedStart = pos + lengthSize;
        int hashedEnd = hashedStart + hashedLength;
        if (hashedEnd > raw.length) {
            return null;
        }
        ByteRange hashed = new ByteRange(hashedStart, hashedEnd);
        int unhashedLength = readLength(raw, hashedEnd, lengthSize);
        if (unhashedLength < 0) {
            return new SubpacketAreas(hashed, new ByteRange(hashedEnd, hashedEnd));
        }
        int unhashedStart = hashedEnd + lengthSize;
        int unhashedEnd = Math.min(unhashedStart + unhashedLength, raw.length);
        return new SubpacketAreas(hashed, new ByteRange(unhashedStart, unhashedEnd));
    }

    private static int readLength(byte[] raw, int pos, int lengthSize) {
        if (pos + lengthSize > raw.length) {
            return -1;
        }
        int length = 0;
        for (int i = 0; i < lengthSize; i++) {
            length = (length << 8) | (raw[pos + i] & 0xFF);
        }
        return length >= 0 && length <= 65535 ? length : -1;
    }

    private static String extractIssuerFingerprintFromPackets(byte[] raw, SubpacketAreas areas) {
        if (areas == null) {
            return null;
        }
        String fingerprint = findIssuerFingerprint(raw, areas.hashed());
        return fingerprint != null ? fingerprint : findIssuerFingerprint(raw, areas.unhashed());
    }

    /**
     * Extracts the signature creation time, which the signer sets and nothing else attests.
     *
     * <p>
     * Only the hashed area is consulted: a creation time in the unhashed area is not covered
     * by the signature, so it proves nothing about when the signature was made.
     */
    private static Instant extractCreationTimeFromPackets(byte[] raw, SubpacketAreas areas) {
        return areas == null ? null : findCreationTime(raw, areas.hashed());
    }

    /**
     * Locates a signature subpacket of the given type within a subpacket area.
     *
     * @param data the dearmored packet bytes
     * @param area the subpacket area to search
     * @param type the subpacket type to look for, ignoring the critical-flag bit
     * @return the range holding the subpacket's value, just past its type byte, or
     *         {@code null} when the area holds no such subpacket
     */
    private static ByteRange findSubpacket(byte[] data, ByteRange area, int type) {
        int pos = area.start();
        while (pos < area.end()) {
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
            if ((data[pos] & 0x7F) == type) { // bit 7 is the critical flag
                return new ByteRange(pos + 1, pos + subLen);
            }
            pos += subLen;
        }
        return null;
    }

    private static String findIssuerFingerprint(byte[] data, ByteRange area) {
        ByteRange value = findSubpacket(data, area, SUBPACKET_TYPE_ISSUER_FINGERPRINT);
        if (value == null || value.end() - value.start() < 2) {
            return null;
        }
        // the value begins with a key version byte, then the fingerprint itself
        StringBuilder sb = new StringBuilder();
        for (int i = value.start() + 1; i < value.end(); i++) {
            sb.append(String.format("%02X", data[i]));
        }
        return sb.toString();
    }

    private static Instant findCreationTime(byte[] data, ByteRange area) {
        ByteRange value = findSubpacket(data, area, SUBPACKET_TYPE_CREATION_TIME);
        if (value == null || value.end() - value.start() < 4) {
            return null;
        }
        int at = value.start();
        long seconds = ((long) (data[at] & 0xFF) << 24)
                | ((long) (data[at + 1] & 0xFF) << 16)
                | ((long) (data[at + 2] & 0xFF) << 8)
                | (data[at + 3] & 0xFF);
        return Instant.ofEpochSecond(seconds);
    }

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
