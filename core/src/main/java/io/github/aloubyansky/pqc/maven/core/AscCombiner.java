package io.github.aloubyansky.pqc.maven.core;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
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
        validateInput(armored, "Armored input");

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
        validateInput(rawPackets, "Raw packet data");

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
        validateInput(armoredClassic, "First armored input");
        validateInput(armoredPqc, "Second armored input");
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
        validateInput(combined, "Combined input");

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
    private static void validateInput(String input, String paramName) {
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
    private static void validateInput(byte[] input, String paramName) {
        if (input == null || input.length == 0) {
            throw new IllegalArgumentException(paramName + " must not be null or empty");
        }
    }
}
