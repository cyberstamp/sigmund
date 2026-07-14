package io.github.cyberstamp.sigmund.core;

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
        void createVerifyOnlyDefaultExecutable() {
            SignatureTool tool = factory.createVerifyOnly(Map.of());
            assertEquals("gpg", tool.name());
        }

        @Test
        void createVerifyOnlyCustomExecutable() {
            SignatureTool tool = factory.createVerifyOnly(Map.of("executable", "/usr/local/bin/gpg2"));
            assertEquals("gpg", tool.name());
        }

        @Test
        void createWithKeyNameSetting() {
            SignatureTool tool = factory.create(null, Map.of("key-name", "user@example.com"));
            assertTrue(tool.canSign());
        }

        @Test
        void createWithCredentialFallback() {
            var cred = new FingerprintCredential(Credential.TYPE_OPENPGP_V4, "ABCD1234ABCD1234");
            SignatureTool tool = factory.create(cred, Map.of());
            assertTrue(tool.canSign());
        }

        @Test
        void createNoKeyNameNoCredential() {
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
        void createVerifyOnlyDefaultHome() {
            SignatureTool tool = factory.createVerifyOnly(Map.of());
            assertEquals("sq", tool.name());
            assertFalse(tool.canSign());
        }

        @Test
        void createVerifyOnlyCustomHome() {
            SignatureTool tool = factory.createVerifyOnly(Map.of("home", "/tmp/sq-home"));
            assertEquals("sq", tool.name());
        }

        @Test
        void createWithFingerprintSetting() {
            SignatureTool tool = factory.create(null, Map.of(
                    "signing-fingerprint", "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234"));
            assertTrue(tool.canSign());
        }

        @Test
        void createWithCredentialFallback() {
            var cred = new FingerprintCredential(Credential.TYPE_OPENPGP_V6,
                    "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234");
            SignatureTool tool = factory.create(cred, Map.of());
            assertTrue(tool.canSign());
        }

        @Test
        void createNoFingerprintNoCredential() {
            SignatureTool tool = factory.create(null, Map.of());
            assertFalse(tool.canSign());
        }

        @Test
        void createCustomExecutable() {
            SignatureTool tool = factory.create(null, Map.of("executable", "/opt/bin/sq"));
            assertEquals("sq", tool.name());
        }
    }

    @Nested
    class BcFactory {

        private final BcToolFactory factory = new BcToolFactory();

        @Test
        void toolName() {
            assertEquals("bc", factory.toolName());
        }

        @Test
        void supportedCredentialTypes() {
            assertEquals(
                    Set.of(Credential.TYPE_OPENPGP_V4, Credential.TYPE_OPENPGP_V6),
                    factory.supportedCredentialTypes());
        }

        @Test
        void createVerifyOnlyDefaultPaths() {
            SignatureTool tool = factory.createVerifyOnly(Map.of());
            assertEquals("bc", tool.name());
            assertFalse(tool.canSign());
        }

        @Test
        void createVerifyOnlyCustomPaths() {
            SignatureTool tool = factory.createVerifyOnly(Map.of(
                    "gnupg-home", "/tmp/gnupg",
                    "cert-d-home", "/tmp/cert-d",
                    "bc-private-home", "/tmp/bc-private"));
            assertEquals("bc", tool.name());
        }

        @Test
        void createWithFingerprintSetting() {
            SignatureTool tool = factory.create(null, Map.of(
                    "signing-fingerprint", "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234"));
            assertTrue(tool.canSign());
        }

        @Test
        void createWithCredentialFallback() {
            var cred = new FingerprintCredential(Credential.TYPE_OPENPGP_V6,
                    "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234");
            SignatureTool tool = factory.create(cred, Map.of());
            assertTrue(tool.canSign());
        }

        @Test
        void createNoFingerprintNoCredential() {
            SignatureTool tool = factory.create(null, Map.of());
            assertFalse(tool.canSign());
        }

        @Test
        void createWithTskFile() {
            SignatureTool tool = factory.create(null, Map.of(
                    "signing-fingerprint", "ABCD1234",
                    "tsk-file", "/tmp/key.tsk"));
            assertTrue(tool.canSign());
        }
    }

    @Nested
    class BuilderIntegration {

        @Test
        void addToolUnknownNameThrows() {
            var builder = Sigmund.builder();
            var ex = assertThrows(SigmundException.class,
                    () -> builder.addTool("nonexistent", Map.of()));
            assertTrue(ex.getMessage().contains("Unknown tool"));
        }

        @Test
        void addSigningToolUnknownNameThrows() {
            var builder = Sigmund.builder();
            var ex = assertThrows(SigmundException.class,
                    () -> builder.addSigningTool("nonexistent", Map.of()));
            assertTrue(ex.getMessage().contains("Unknown tool"));
        }
    }
}
