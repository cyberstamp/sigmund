package io.github.aloubyansky.sigmund.core;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SignerTest {

    @TempDir
    Path tempDir;

    @Nested
    class SingleTool {

        @Test
        void producesOneSignatureFile() throws IOException {
            var format = mockFormat("openpgp", ".asc", false);
            var tool = mockSigningTool("gpg", format, "RSA");
            var signer = new Signer(List.of(tool));

            Path artifact = createArtifact("test.jar");
            SigningOutput output = signer.sign(artifact, tempDir);

            assertEquals(1, output.files().size());
            SignedFile sf = output.files().get(0);
            assertEquals("gpg", sf.toolName());
            assertEquals("openpgp", sf.format());
            assertEquals("RSA", sf.algorithm());
            assertTrue(sf.path().getFileName().toString().endsWith(".asc"));
            assertTrue(Files.exists(sf.path()));
        }
    }

    @Nested
    class MultipleSameFormat {

        @Test
        void combinesWhenFormatSupportsCombining() throws IOException {
            var format = mockFormat("openpgp", ".asc", true);
            var gpg = mockSigningTool("gpg", format, "RSA");
            var sq = mockSigningTool("sq", format, "ML-DSA-87+Ed448");
            var signer = new Signer(List.of(gpg, sq));

            Path artifact = createArtifact("test.jar");
            SigningOutput output = signer.sign(artifact, tempDir);

            assertEquals(1, output.files().size());
            SignedFile sf = output.files().get(0);
            assertEquals("gpg+sq", sf.toolName());
            assertEquals("RSA+ML-DSA-87+Ed448", sf.algorithm());
            assertEquals("openpgp", sf.format());
        }

        @Test
        void doesNotCombineWhenFormatDoesNotSupportCombining() throws IOException {
            var format = mockFormat("sigstore", ".sigstore.json", false);
            var tool1 = mockSigningTool("sigstore1", format, "ECDSA");
            var tool2 = mockSigningTool("sigstore2", format, "ECDSA");
            var signer = new Signer(List.of(tool1, tool2));

            Path artifact = createArtifact("test.jar");
            SigningOutput output = signer.sign(artifact, tempDir);

            assertEquals(2, output.files().size());
        }
    }

    @Nested
    class MultipleDifferentFormats {

        @Test
        void producesSeparateFilesPerFormat() throws IOException {
            var openpgpFormat = mockFormat("openpgp", ".asc", true);
            var sigstoreFormat = mockFormat("sigstore", ".sigstore.json", false);
            var gpg = mockSigningTool("gpg", openpgpFormat, "RSA");
            var sigstore = mockSigningTool("sigstore", sigstoreFormat, "ECDSA");
            var signer = new Signer(List.of(gpg, sigstore));

            Path artifact = createArtifact("test.jar");
            SigningOutput output = signer.sign(artifact, tempDir);

            assertEquals(2, output.files().size());
            var formats = output.files().stream().map(SignedFile::format).sorted().toList();
            assertEquals(List.of("openpgp", "sigstore"), formats);
        }
    }

    @Nested
    class Validation {

        @Test
        void rejectsEmptyToolList() {
            var ex = assertThrows(SigmundException.class, () -> new Signer(List.of()));
            assertTrue(ex.getMessage().contains("No signing tools available"));
        }
    }

    @Nested
    class FailureCleanup {

        @Test
        void cleansTempFilesWhenToolThrows() throws IOException {
            var format = mockFormat("openpgp", ".asc", false);
            var goodTool = mockSigningTool("gpg", format, "RSA");
            var failingTool = failingSigningTool("sq", format);
            var signer = new Signer(List.of(goodTool, failingTool));

            Path artifact = createArtifact("test.jar");

            assertThrows(RuntimeException.class, () -> signer.sign(artifact, tempDir));

            long tempFiles = Files.list(tempDir).filter(p -> p.toString().contains("sig-")).count();
            assertEquals(0, tempFiles, "temp files should be cleaned up after failure");
        }

        @Test
        void cleansTempFilesWhenCombineThrows() throws IOException {
            var format = mockFormat("openpgp", ".asc", true, true);
            var tool1 = mockSigningTool("gpg", format, "RSA");
            var tool2 = mockSigningTool("sq", format, "PQC");
            var signer = new Signer(List.of(tool1, tool2));

            Path artifact = createArtifact("test.jar");

            assertThrows(RuntimeException.class, () -> signer.sign(artifact, tempDir));

            long tempFiles = Files.list(tempDir).filter(p -> p.toString().contains("sig-")).count();
            assertEquals(0, tempFiles, "temp files should be cleaned up after combine failure");
        }
    }

    // --- Helpers ---

    private Path createArtifact(String name) throws IOException {
        Path file = tempDir.resolve(name);
        Files.writeString(file, "artifact content");
        return file;
    }

    private static SignatureFormat mockFormat(String name, String ext, boolean combinable) {
        return mockFormat(name, ext, combinable, false);
    }

    private static SignatureFormat mockFormat(String name, String ext, boolean combinable,
            boolean failCombine) {
        return new SignatureFormat() {
            @Override
            public String name() {
                return name;
            }

            @Override
            public String fileExtension() {
                return ext;
            }

            @Override
            public boolean canHandle(Path f) {
                return true;
            }

            @Override
            public List<VerificationUnit> parse(Path f) {
                return List.of();
            }

            @Override
            public boolean supportsCombining() {
                return combinable;
            }

            @Override
            public void combine(List<Path> sigs, Path output) {
                if (failCombine) {
                    throw new RuntimeException("combine failed");
                }
                try {
                    var sb = new StringBuilder();
                    for (Path s : sigs) {
                        sb.append(Files.readString(s));
                    }
                    Files.writeString(output, sb.toString());
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }

    private static SignatureTool failingSigningTool(String name, SignatureFormat format) {
        return new SignatureTool() {
            @Override
            public String name() {
                return name;
            }

            @Override
            public boolean isAvailable() {
                return true;
            }

            @Override
            public boolean canSign() {
                return true;
            }

            @Override
            public SignatureFormat signatureFormat() {
                return format;
            }

            @Override
            public Set<String> supportedCredentialTypes() {
                return Set.of("openpgp4");
            }

            @Override
            public boolean canVerify(VerificationUnit u) {
                return false;
            }

            @Override
            public SignResult sign(Path a, Path o) {
                throw new RuntimeException("signing failed");
            }

            @Override
            public VerifyResult verify(Path a, VerificationUnit u) {
                throw new UnsupportedOperationException();
            }

            @Override
            public List<Credential> extractCredentials(VerifyResult r) {
                return List.of();
            }
        };
    }

    private static SignatureTool mockSigningTool(String name, SignatureFormat format, String algorithm) {
        return new SignatureTool() {
            @Override
            public String name() {
                return name;
            }

            @Override
            public boolean isAvailable() {
                return true;
            }

            @Override
            public boolean canSign() {
                return true;
            }

            @Override
            public SignatureFormat signatureFormat() {
                return format;
            }

            @Override
            public Set<String> supportedCredentialTypes() {
                return Set.of("openpgp4");
            }

            @Override
            public boolean canVerify(VerificationUnit u) {
                return false;
            }

            @Override
            public SignResult sign(Path a, Path o) {
                try {
                    Files.writeString(o, "sig-" + name);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                return new SignResult(algorithm);
            }

            @Override
            public VerifyResult verify(Path a, VerificationUnit u) {
                throw new UnsupportedOperationException();
            }

            @Override
            public List<Credential> extractCredentials(VerifyResult r) {
                return List.of();
            }
        };
    }
}
