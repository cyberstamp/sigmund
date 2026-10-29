package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.junit.jupiter.api.io.TempDir;

/**
 * Integration tests for {@code SIGMUND_BC_SIGNING_KEY} behavior.
 * <p>
 * Each test generates a real Ed25519 key, exports it as armored text, then
 * forks a child JVM with the env var set. The child exercises the full
 * {@link Sigmund.Builder} → {@link Signer} → sign path and writes results
 * to files. The parent reads the files and asserts.
 * <p>
 * This avoids test-only overloads or mock env var lookups — the child process
 * sees a real {@code SIGMUND_BC_SIGNING_KEY} in its environment.
 */
class EphemeralSigningKeyTest {

    /**
     * Child-process entry point. Receives the working directory and mode as
     * arguments, exercises the signing path, and writes results for the parent.
     */
    public static void main(String[] args) throws Exception {
        Path workDir = Path.of(args[0]);
        String mode = args[1];

        Path artifact = workDir.resolve("artifact.jar");
        Files.writeString(artifact, "test artifact content");

        Sigmund sigmund;
        if ("exclusive".equals(mode)) {
            sigmund = Sigmund.builder().build();
        } else if ("key-provider".equals(mode)) {
            List<String> toolchain = List.of("bc", "gpg");
            SigmundConfig config = new SigmundConfig(null, null, null,
                    new SigningConfig(null, toolchain, List.of(), Map.of()),
                    null, null);
            Sigmund.Builder builder = Sigmund.builder().config(config);
            for (String toolName : toolchain) {
                try {
                    builder.addSigningTool(toolName, Map.of());
                } catch (SigmundException e) {
                    // tool not available (e.g., gpg not installed)
                }
            }
            sigmund = builder.build();
        } else {
            throw new IllegalArgumentException("Unknown mode: " + mode);
        }

        Signer signer = sigmund.signer();

        List<SigningInfo> infos = signer.signingInfo();
        StringBuilder toolNames = new StringBuilder();
        for (SigningInfo info : infos) {
            if (!toolNames.isEmpty()) {
                toolNames.append(",");
            }
            toolNames.append(info.toolName());
        }
        Files.writeString(workDir.resolve("tool-names"), toolNames.toString());

        for (SigningInfo info : infos) {
            Files.writeString(workDir.resolve("fingerprint-" + info.toolName()),
                    info.fingerprint());
        }

        SigningOutput output = signer.sign(artifact, workDir);
        StringBuilder signedTools = new StringBuilder();
        for (SignedFile sf : output.files()) {
            if (!signedTools.isEmpty()) {
                signedTools.append(",");
            }
            signedTools.append(sf.toolName());
        }
        Files.writeString(workDir.resolve("signed-tools"), signedTools.toString());
    }

    @Test
    void exclusiveSignerWhenNoConfig(@TempDir Path tempDir) throws Exception {
        String armoredKey = generateArmoredKey(tempDir);
        String expectedFp = Files.readString(tempDir.resolve("fingerprint"));

        Path workDir = tempDir.resolve("work");
        Files.createDirectories(workDir);

        int exitCode = fork(armoredKey, workDir, "exclusive");
        assertThat(exitCode).as("Child process failed").isEqualTo(0);

        assertThat(Files.readString(workDir.resolve("tool-names"))).isEqualTo("bc");
        assertThat(Files.readString(workDir.resolve("signed-tools"))).isEqualTo("bc");
        assertThat(Files.readString(workDir.resolve("fingerprint-bc"))).isEqualTo(expectedFp);
    }

    @EnabledIf("gpgAvailable")
    @Test
    void keyProviderAlongsideGpg(@TempDir Path tempDir) throws Exception {
        String armoredKey = generateArmoredKey(tempDir);
        String expectedFp = Files.readString(tempDir.resolve("fingerprint"));

        Path workDir = tempDir.resolve("work");
        Files.createDirectories(workDir);

        int exitCode = fork(armoredKey, workDir, "key-provider");
        assertThat(exitCode).as("Child process failed").isEqualTo(0);

        String toolNames = Files.readString(workDir.resolve("tool-names"));
        List<String> tools = Arrays.asList(toolNames.split(","));
        assertThat(tools.contains("bc")).as("BC should be a signer").isTrue();
        assertThat(tools.contains("gpg")).as("GPG should be a signer").isTrue();

        assertThat(Files.readString(workDir.resolve("fingerprint-bc"))).isEqualTo(expectedFp);

        String signedTools = Files.readString(workDir.resolve("signed-tools"));
        assertThat(signedTools.contains("bc")).as("BC should have signed").isTrue();
        assertThat(signedTools.contains("gpg")).as("GPG should have signed").isTrue();
    }

    static boolean gpgAvailable() {
        return GpgRunner.isToolAvailable();
    }

    private String generateArmoredKey(Path tempDir) throws Exception {
        BcKeyStore store = new BcKeyStore(null,
                tempDir.resolve("cert-d"), tempDir.resolve("bc-private"));
        BcRunner gen = new BcRunner(store, null, null);
        String fp = gen.generateKey("CI Test <ci@example.com>", "ed25519", null);

        PGPSecretKeyRing ring = store.findSecretKey(fp);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ArmoredOutputStream armored = new ArmoredOutputStream(out)) {
            ring.encode(armored);
        }
        Files.writeString(tempDir.resolve("fingerprint"), fp);
        return out.toString();
    }

    private int fork(String signingKey, Path workDir, String mode) throws Exception {
        String classpath = System.getProperty("java.class.path");
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();

        ProcessBuilder pb = new ProcessBuilder(
                java, "-cp", classpath,
                EphemeralSigningKeyTest.class.getName(),
                workDir.toString(), mode);
        pb.environment().put("SIGMUND_BC_SIGNING_KEY", signingKey);
        pb.directory(workDir.toFile());
        pb.redirectErrorStream(true);

        Process p = pb.start();
        String output = new String(p.getInputStream().readAllBytes());
        int exitCode = p.waitFor();
        if (exitCode != 0) {
            System.err.println("Child process output:\n" + output);
        }
        return exitCode;
    }
}
