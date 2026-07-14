package io.github.cyberstamp.sigmund.core;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class BcToolFactoryTest {

    @Test
    void toolName() {
        assertEquals("bc", new BcToolFactory().toolName());
    }

    @Test
    void supportedCredentialTypes() {
        assertEquals(Set.of("openpgp4", "openpgp6"),
                new BcToolFactory().supportedCredentialTypes());
    }

    @Test
    void createVerifyOnlyIsAvailable() {
        SignatureTool tool = new BcToolFactory().createVerifyOnly(Map.of());
        assertTrue(tool.isAvailable());
        assertFalse(tool.canSign());
        assertEquals("bc", tool.name());
    }

    @Test
    void createVerifyOnlyWithCustomPaths() {
        SignatureTool tool = new BcToolFactory().createVerifyOnly(Map.of(
                "gnupg-home", "/tmp/gnupg",
                "cert-d-home", "/tmp/cert-d",
                "bc-private-home", "/tmp/bc-private"));
        assertTrue(tool.isAvailable());
    }

    @Test
    void createWithSigningFingerprint() {
        SignatureTool tool = new BcToolFactory().create(null, Map.of(
                "signing-fingerprint", "AABBCCDD"));
        assertTrue(tool.canSign());
    }
}
