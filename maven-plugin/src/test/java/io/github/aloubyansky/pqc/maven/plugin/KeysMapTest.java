package io.github.aloubyansky.pqc.maven.plugin;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class KeysMapTest {

    @TempDir
    Path tempDir;

    @Test
    void parseEmptyFile() throws IOException {
        Path file = writeKeysMap("");
        KeysMap map = KeysMap.parse(file);
        assertTrue(map.entries().isEmpty());
    }

    @Test
    void parseCommentsAndBlankLines() throws IOException {
        Path file = writeKeysMap("""
                # This is a comment

                # Another comment
                """);
        KeysMap map = KeysMap.parse(file);
        assertTrue(map.entries().isEmpty());
    }

    @Test
    void parseSingleGpgFingerprint() throws IOException {
        Path file = writeKeysMap("com.example:lib = 0xABCDEF1234567890");
        KeysMap map = KeysMap.parse(file);
        assertEquals(1, map.entries().size());
        KeysMap.Entry entry = map.entries().get(0);
        assertEquals("com.example", entry.groupPattern());
        assertEquals("lib", entry.artifactPattern());
        List<KeysMap.KeySpec> specs = entry.keySpecs();
        assertEquals(1, specs.size());
        assertEquals(KeysMap.KeySpec.Type.GPG_FINGERPRINT, specs.get(0).type());
        assertEquals("ABCDEF1234567890", specs.get(0).value());
    }

    @Test
    void parsePqcCertSpec() throws IOException {
        Path file = writeKeysMap("org.example:secure = pqc-cert:/path/to/cert.pem");
        KeysMap map = KeysMap.parse(file);
        KeysMap.KeySpec spec = map.entries().get(0).keySpecs().get(0);
        assertEquals(KeysMap.KeySpec.Type.PQC_CERT, spec.type());
        assertEquals("/path/to/cert.pem", spec.value());
    }

    @Test
    void parsePqcFingerprintSpec() throws IOException {
        Path file = writeKeysMap("org.example:secure = pqc:ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234");
        KeysMap map = KeysMap.parse(file);
        KeysMap.KeySpec spec = map.entries().get(0).keySpecs().get(0);
        assertEquals(KeysMap.KeySpec.Type.PQC_FINGERPRINT, spec.type());
        assertEquals("ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234", spec.value());
    }

    @Test
    void parseAnySpec() throws IOException {
        Path file = writeKeysMap("org.junit.* = any");
        KeysMap map = KeysMap.parse(file);
        KeysMap.KeySpec spec = map.entries().get(0).keySpecs().get(0);
        assertEquals(KeysMap.KeySpec.Type.ANY, spec.type());
    }

    @Test
    void parseNoSigSpec() throws IOException {
        Path file = writeKeysMap("com.internal:* = noSig");
        KeysMap map = KeysMap.parse(file);
        KeysMap.KeySpec spec = map.entries().get(0).keySpecs().get(0);
        assertEquals(KeysMap.KeySpec.Type.NO_SIG, spec.type());
    }

    @Test
    void parseMultipleKeySpecs() throws IOException {
        Path file = writeKeysMap("org.example:lib = 0xABCD, pqc-cert:/path/to/cert.pem");
        KeysMap map = KeysMap.parse(file);
        List<KeysMap.KeySpec> specs = map.entries().get(0).keySpecs();
        assertEquals(2, specs.size());
        assertEquals(KeysMap.KeySpec.Type.GPG_FINGERPRINT, specs.get(0).type());
        assertEquals(KeysMap.KeySpec.Type.PQC_CERT, specs.get(1).type());
    }

    @Test
    void parseWildcardGroupPattern() throws IOException {
        Path file = writeKeysMap("com.redhat.* = 0xABCD");
        KeysMap map = KeysMap.parse(file);
        KeysMap.Entry entry = map.entries().get(0);
        assertEquals("com.redhat.*", entry.groupPattern());
        assertNull(entry.artifactPattern());
    }

    @Test
    void parseGroupOnlyPattern() throws IOException {
        Path file = writeKeysMap("com.example = 0xABCD");
        KeysMap map = KeysMap.parse(file);
        KeysMap.Entry entry = map.entries().get(0);
        assertEquals("com.example", entry.groupPattern());
        assertNull(entry.artifactPattern());
    }

    @Test
    void propertyInterpolation() throws IOException {
        Path file = writeKeysMap("org.example:lib = pqc-cert:${test.cert.dir}/cert.pem");
        KeysMap map = KeysMap.parse(file,
                name -> "test.cert.dir".equals(name) ? "/tmp/certs" : null);
        KeysMap.KeySpec spec = map.entries().get(0).keySpecs().get(0);
        assertEquals("/tmp/certs/cert.pem", spec.value());
    }

    @Test
    void unresolvedPropertyKeptAsIs() throws IOException {
        Path file = writeKeysMap("org.example:lib = pqc-cert:${unknown.prop}/cert.pem");
        KeysMap map = KeysMap.parse(file, name -> null);
        KeysMap.KeySpec spec = map.entries().get(0).keySpecs().get(0);
        assertEquals("${unknown.prop}/cert.pem", spec.value());
    }

    @Test
    void matchExactGroupAndArtifact() throws IOException {
        Path file = writeKeysMap("com.example:lib = 0xABCD");
        KeysMap map = KeysMap.parse(file);
        KeysMap.Entry match = map.findMatch("com.example", "lib");
        assertNotNull(match);
        assertNull(map.findMatch("com.example", "other"));
        assertNull(map.findMatch("com.other", "lib"));
    }

    @Test
    void matchWildcardArtifact() throws IOException {
        Path file = writeKeysMap("com.example:* = 0xABCD");
        KeysMap map = KeysMap.parse(file);
        assertNotNull(map.findMatch("com.example", "lib"));
        assertNotNull(map.findMatch("com.example", "other"));
        assertNull(map.findMatch("com.other", "lib"));
    }

    @Test
    void matchWildcardGroup() throws IOException {
        Path file = writeKeysMap("com.example.* = 0xABCD");
        KeysMap map = KeysMap.parse(file);
        assertNotNull(map.findMatch("com.example", "anything"));
        assertNotNull(map.findMatch("com.example.sub", "lib"));
        assertNotNull(map.findMatch("com.example.sub.deep", "lib"));
        assertNull(map.findMatch("com.other", "lib"));
    }

    @Test
    void matchGroupOnly() throws IOException {
        Path file = writeKeysMap("com.example = 0xABCD");
        KeysMap map = KeysMap.parse(file);
        assertNotNull(map.findMatch("com.example", "anything"));
        assertNull(map.findMatch("com.example.sub", "lib"));
    }

    @Test
    void firstMatchWins() throws IOException {
        Path file = writeKeysMap("""
                com.example:lib = 0xFIRST
                com.example:* = 0xSECOND
                """);
        KeysMap map = KeysMap.parse(file);
        KeysMap.Entry match = map.findMatch("com.example", "lib");
        assertNotNull(match);
        assertEquals("FIRST", match.keySpecs().get(0).value());

        KeysMap.Entry other = map.findMatch("com.example", "other");
        assertNotNull(other);
        assertEquals("SECOND", other.keySpecs().get(0).value());
    }

    @Test
    void anyWithOtherSpecsRejected() throws IOException {
        Path file = writeKeysMap("org.example = any, 0xABCD1234");
        assertThrows(IllegalArgumentException.class, () -> KeysMap.parse(file));
    }

    @Test
    void noSigWithOtherSpecsRejected() throws IOException {
        Path file = writeKeysMap("org.example = noSig, pqc:ABCD1234");
        assertThrows(IllegalArgumentException.class, () -> KeysMap.parse(file));
    }

    private Path writeKeysMap(String content) throws IOException {
        Path file = tempDir.resolve("keys.map");
        Files.writeString(file, content);
        return file;
    }
}
