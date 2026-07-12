package io.github.aloubyansky.sigmund.core;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class ToolFactoryTest {

    @Nested
    class GpgFactory {

        private final GpgToolFactory factory = new GpgToolFactory();

        @Test
        void toolName() {
            assertEquals("gpg", factory.toolName());
        }

        @Test
        void supportedCredentialTypes() {
            assertEquals(Set.of(Credential.TYPE_OPENPGP_V4), factory.supportedCredentialTypes());
        }

        @Test
        void createVerifyOnly_defaultExecutable() {
            SignatureTool tool = factory.createVerifyOnly(Map.of());
            assertEquals("gpg", tool.name());
        }

        @Test
        void createVerifyOnly_customExecutable() {
            SignatureTool tool = factory.createVerifyOnly(Map.of("executable", "/usr/local/bin/gpg2"));
            assertEquals("gpg", tool.name());
        }

        @Test
        void create_withKeyNameSetting() {
            SignatureTool tool = factory.create(null, Map.of("key-name", "user@example.com"));
            assertTrue(tool.canSign());
        }

        @Test
        void create_withCredentialFallback() {
            var cred = new FingerprintCredential(Credential.TYPE_OPENPGP_V4, "ABCD1234ABCD1234");
            SignatureTool tool = factory.create(cred, Map.of());
            assertTrue(tool.canSign());
        }

        @Test
        void create_noKeyName_noCredential() {
            SignatureTool tool = factory.create(null, Map.of());
            assertTrue(tool.canSign());
        }
    }

    @Nested
    class SqFactory {

        private final SqToolFactory factory = new SqToolFactory();

        @Test
        void toolName() {
            assertEquals("sq", factory.toolName());
        }

        @Test
        void supportedCredentialTypes() {
            assertEquals(
                    Set.of(Credential.TYPE_OPENPGP_V4, Credential.TYPE_OPENPGP_V6),
                    factory.supportedCredentialTypes());
        }

        @Test
        void createVerifyOnly_defaultHome() {
            SignatureTool tool = factory.createVerifyOnly(Map.of());
            assertEquals("sq", tool.name());
            assertFalse(tool.canSign());
        }

        @Test
        void createVerifyOnly_customHome() {
            SignatureTool tool = factory.createVerifyOnly(Map.of("home", "/tmp/sq-home"));
            assertEquals("sq", tool.name());
        }

        @Test
        void create_withFingerprintSetting() {
            SignatureTool tool = factory.create(null, Map.of(
                    "signing-fingerprint", "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234"));
            assertTrue(tool.canSign());
        }

        @Test
        void create_withCredentialFallback() {
            var cred = new FingerprintCredential(Credential.TYPE_OPENPGP_V6,
                    "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234");
            SignatureTool tool = factory.create(cred, Map.of());
            assertTrue(tool.canSign());
        }

        @Test
        void create_noFingerprint_noCredential() {
            SignatureTool tool = factory.create(null, Map.of());
            assertFalse(tool.canSign());
        }

        @Test
        void create_customExecutable() {
            SignatureTool tool = factory.create(null, Map.of("executable", "/opt/bin/sq"));
            assertEquals("sq", tool.name());
        }
    }

    @Nested
    class BuilderIntegration {

        @Test
        void addTool_unknownName_throws() {
            var builder = Sigmund.builder();
            var ex = assertThrows(SigmundException.class,
                    () -> builder.addTool("nonexistent", Map.of()));
            assertTrue(ex.getMessage().contains("Unknown tool"));
        }

        @Test
        void addSigningTool_unknownName_throws() {
            var builder = Sigmund.builder();
            var ex = assertThrows(SigmundException.class,
                    () -> builder.addSigningTool("nonexistent", Map.of()));
            assertTrue(ex.getMessage().contains("Unknown tool"));
        }
    }
}
