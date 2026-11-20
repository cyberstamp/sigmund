package dev.cyberstamp.sigmund.resolver;

import dev.cyberstamp.sigmund.core.KeyGenerator;
import dev.cyberstamp.sigmund.core.Sigmund;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

/**
 * A Bouncy Castle key, an artifact signed with it, and a {@code sigmund.yaml} that requires that key for
 * {@code org.example:*}, all under one directory.
 */
public final class TestKeys {

    private TestKeys() {
    }

    /**
     * The files of one fixture.
     *
     * @param configFile the {@code sigmund.yaml} trusting the key for {@code org.example:*}
     * @param artifact the signed artifact
     * @param signature the artifact's {@code .asc}
     * @param fingerprint the signing key's fingerprint
     */
    public record Fixture(Path configFile, Path artifact, Path signature, String fingerprint) {
    }

    /**
     * Generates a key into {@code dir}, signs an artifact with it and writes the config trusting it.
     *
     * @param dir the directory holding the key stores and files
     * @return the fixture
     */
    public static Fixture create(Path dir) {
        try {
            Map<String, String> tools = Map.of(
                    "cert-d-home", dir.resolve("cert-d").toString(),
                    "bc-private-home", dir.resolve("bc-private").toString(),
                    "gnupg-home", Files.createDirectories(dir.resolve("gnupg")).toString());
            String fingerprint = generateKey(tools);
            Path artifact = Files.writeString(dir.resolve("artifact.jar"), "artifact bytes");
            Path signature = sign(tools, fingerprint, artifact, Files.createDirectories(dir.resolve("signed")));
            Path configFile = Files.writeString(dir.resolve("sigmund.yaml"), config(tools, fingerprint));
            return new Fixture(configFile, artifact, signature, fingerprint);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static String generateKey(Map<String, String> tools) {
        try (Sigmund sigmund = Sigmund.builder().addSigningTool("bc", tools).build()) {
            return sigmund.findTool(KeyGenerator.class).generateKey("Test <test@sigmund.example>", "ed25519", "pgp4");
        }
    }

    private static Path sign(Map<String, String> tools, String fingerprint, Path artifact, Path outputDir) {
        Map<String, String> signing = new HashMap<>(tools);
        signing.put("signing-fingerprint", fingerprint);
        try (Sigmund sigmund = Sigmund.builder().addSigningTool("bc", signing).build()) {
            return sigmund.signer().sign(artifact, outputDir).files().get(0).path();
        }
    }

    private static String config(Map<String, String> tools, String fingerprint) {
        return """
                signers:
                  tester:
                    pgp4: "%s"
                rules:
                  - match: ["org.example:*"]
                    requires: [tester]
                verification:
                  toolchain: [bc]
                  resolve-signers: false
                tools:
                  bc:
                    cert-d-home: "%s"
                    bc-private-home: "%s"
                    gnupg-home: "%s"
                """
                .formatted(
                        fingerprint, tools.get("cert-d-home"), tools.get("bc-private-home"), tools.get("gnupg-home"));
    }
}
