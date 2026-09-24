package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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

            assertThat(output.files().size()).isEqualTo(1);
            SignedFile sf = output.files().get(0);
            assertThat(sf.toolName()).isEqualTo("gpg");
            assertThat(sf.format()).isEqualTo("openpgp");
            assertThat(sf.algorithm()).isEqualTo("RSA");
            assertThat(sf.path().getFileName().toString().endsWith(".asc")).isTrue();
            assertThat(Files.exists(sf.path())).isTrue();
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

            assertThat(output.files().size()).isEqualTo(1);
            SignedFile sf = output.files().get(0);
            assertThat(sf.toolName()).isEqualTo("gpg+sq");
            assertThat(sf.algorithm()).isEqualTo("RSA+ML-DSA-87+Ed448");
            assertThat(sf.format()).isEqualTo("openpgp");
        }

        @Test
        void doesNotCombineWhenFormatDoesNotSupportCombining() throws IOException {
            var format = mockFormat("sigstore", ".sigstore.json", false);
            var tool1 = mockSigningTool("sigstore1", format, "ECDSA");
            var tool2 = mockSigningTool("sigstore2", format, "ECDSA");
            var signer = new Signer(List.of(tool1, tool2));

            Path artifact = createArtifact("test.jar");
            SigningOutput output = signer.sign(artifact, tempDir);

            assertThat(output.files().size()).isEqualTo(2);
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

            assertThat(output.files().size()).isEqualTo(2);
            var formats = output.files().stream().map(SignedFile::format).sorted().toList();
            assertThat(formats).isEqualTo(List.of("openpgp", "sigstore"));
        }
    }

    @Nested
    class Validation {

        @Test
        void rejectsEmptyToolList() {
            assertThatThrownBy(() -> new Signer(List.of()))
                    .isInstanceOf(SigmundException.class)
                    .hasMessageContaining("No signing tools available");
        }
    }

    @Nested
    class SigningInfoAggregation {

        @Test
        void aggregatesInfoFromAllTools() {
            var format = mockFormat("openpgp", ".asc", true);
            var gpg = mockSigningTool("gpg", format, "RSA",
                    new SigningInfo("gpg", "AAAA", "RSA", "alice@example.com", Set.of("openpgp4")));
            var sq = mockSigningTool("sq", format, "ML-DSA-87+Ed448",
                    new SigningInfo("sq", "BBBB", "ML-DSA-87+Ed448", "alice@example.com", Set.of("openpgp6")));
            var signer = new Signer(List.of(gpg, sq));

            List<SigningInfo> infos = signer.signingInfo();

            assertThat(infos.size()).isEqualTo(2);
            assertThat(infos.get(0).toolName()).isEqualTo("gpg");
            assertThat(infos.get(0).fingerprint()).isEqualTo("AAAA");
            assertThat(infos.get(1).toolName()).isEqualTo("sq");
            assertThat(infos.get(1).fingerprint()).isEqualTo("BBBB");
        }

        @Test
        void returnsEmptyWhenToolsProvideNoInfo() {
            var format = mockFormat("openpgp", ".asc", false);
            var tool = mockSigningTool("gpg", format, "RSA");
            var signer = new Signer(List.of(tool));

            assertThat(signer.signingInfo().isEmpty()).isTrue();
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

            assertThatThrownBy(() -> signer.sign(artifact, tempDir)).isInstanceOf(RuntimeException.class);

            long tempFiles = Files.list(tempDir).filter(p -> p.toString().contains("sig-")).count();
            assertThat(tempFiles).as("temp files should be cleaned up after failure").isEqualTo(0);
        }

        @Test
        void cleansTempFilesWhenCombineThrows() throws IOException {
            var format = mockFormat("openpgp", ".asc", true, true);
            var tool1 = mockSigningTool("gpg", format, "RSA");
            var tool2 = mockSigningTool("sq", format, "PQC");
            var signer = new Signer(List.of(tool1, tool2));

            Path artifact = createArtifact("test.jar");

            assertThatThrownBy(() -> signer.sign(artifact, tempDir)).isInstanceOf(RuntimeException.class);

            long tempFiles = Files.list(tempDir).filter(p -> p.toString().contains("sig-")).count();
            assertThat(tempFiles).as("temp files should be cleaned up after combine failure").isEqualTo(0);
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
            public boolean canHandleByContent(Evidence e) {
                return true;
            }

            @Override
            public List<Claim> parse(Evidence e) {
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
            public boolean canVerify(Claim u) {
                return false;
            }

            @Override
            public SignResult sign(Path a, Path o) {
                throw new RuntimeException("signing failed");
            }

            @Override
            public VerifyResult verify(Path a, Claim u) {
                throw new UnsupportedOperationException();
            }

            @Override
            public List<Credential> extractCredentials(VerifyResult r) {
                return List.of();
            }
        };
    }

    private static SignatureTool mockSigningTool(String name, SignatureFormat format, String algorithm) {
        return mockSigningTool(name, format, algorithm, null);
    }

    private static SignatureTool mockSigningTool(String name, SignatureFormat format,
            String algorithm, SigningInfo info) {
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
            public List<SigningInfo> signingInfo() {
                return info != null ? List.of(info) : List.of();
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
            public boolean canVerify(Claim u) {
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
            public VerifyResult verify(Path a, Claim u) {
                throw new UnsupportedOperationException();
            }

            @Override
            public List<Credential> extractCredentials(VerifyResult r) {
                return List.of();
            }
        };
    }
}
