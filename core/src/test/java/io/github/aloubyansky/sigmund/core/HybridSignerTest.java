package io.github.aloubyansky.sigmund.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Tests for {@link HybridSigner}.
 * <p>
 * These tests use mock signers to verify orchestration logic without
 * requiring actual GPG or sq installations.
 *
 */
class HybridSignerTest {

    /**
     * Tests that sign() produces a combined .asc file with both signatures.
     */
    @Test
    void sign_producesCombinedAsc(@TempDir Path tempDir) throws Exception {
        // Create artifact
        Path artifact = tempDir.resolve("test.jar");
        Files.writeString(artifact, "fake jar content");

        // Use canned armored blocks that AscCombiner can actually process.
        // Generate them using AscCombiner.armor() with fake packet bytes.
        byte[] fakeClassicPacket = new byte[] { 0x04, 0x00, 0x1F }; // some bytes
        byte[] fakePqcPacket = new byte[] { 0x06, 0x00, 0x2A }; // some bytes
        String fakeClassicAsc = AscCombiner.armor(fakeClassicPacket);
        String fakePqcAsc = AscCombiner.armor(fakePqcPacket);

        GpgRunner gpg = new GpgRunner() {
            @Override
            public String sign(Path artifactFile, Path outputSig) {
                try {
                    Files.writeString(outputSig, fakeClassicAsc);
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
                return fakeClassicAsc;
            }
        };
        SqRunner sq = new SqRunner(tempDir) {
            @Override
            public String sign(Path artifactFile, Path outputSig, String fingerprint) {
                try {
                    Files.writeString(outputSig, fakePqcAsc);
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
                return fakePqcAsc;
            }
        };
        String fp = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        HybridSigner signer = new HybridSigner(gpg, sq, fp);

        Path ascOutput = tempDir.resolve("test.jar.asc");
        signer.sign(artifact, ascOutput);

        String combined = Files.readString(ascOutput);
        assertTrue(combined.contains("-----BEGIN PGP MESSAGE-----"));
        assertTrue(combined.contains("-----END PGP MESSAGE-----"));

        assertEquals(2, countOccurrences(combined, "-----BEGIN PGP MESSAGE-----"));
    }

    /**
     * Counts the number of occurrences of a substring in a string.
     *
     * @param str the string to search in
     * @param substring the substring to count
     * @return the number of occurrences
     */
    private int countOccurrences(String str, String substring) {
        int count = 0;
        int index = 0;
        while ((index = str.indexOf(substring, index)) != -1) {
            count++;
            index += substring.length();
        }
        return count;
    }
}
