package dev.cyberstamp.sigmund.cli;

import dev.cyberstamp.sigmund.core.SecretKeyExporter;
import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.ToolConfig;
import dev.cyberstamp.sigmund.core.UserPaths;
import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Map;
import java.util.concurrent.Callable;
import picocli.CommandLine;

/**
 * Exports a Bouncy Castle secret key, armored, so that it can be handed to a machine without the
 * key store — a CI runner reading it from {@code SIGMUND_BC_SIGNING_KEY}, or from a {@code tsk-file}.
 * <p>
 * The key is written only to a file, never to the console, and the file is created readable by
 * its owner alone where the filesystem supports it. A key generated with a passphrase stays
 * encrypted with it. The stores are the ones {@code tools.bc} in {@code sigmund.yaml} names, as
 * for {@code keygen}.
 */
@CommandLine.Command(name = "export-secret-key", description = "Export a Bouncy Castle secret key to a file, for CI signing", mixinStandardHelpOptions = true)
public class ExportSecretKeyCommand implements Callable<Integer> {

    @CommandLine.Option(names = { "--fingerprint" }, required = true, description = "Fingerprint of the key to export")
    private String fingerprint;

    @CommandLine.Option(names = { "--output",
            "-o" }, required = true, description = "File to write the secret key to; it must not exist yet")
    private String output;

    @CommandLine.Mixin
    private ConfigMixin configMixin;

    @Override
    public Integer call() {
        try {
            String key = exportFromBc();
            Path outputPath = UserPaths.expand(output);
            writeOwnerOnly(outputPath, key);
            System.err.println("Warning: " + outputPath.toAbsolutePath()
                    + " holds a secret key: whoever has it can sign as the key. Store it as a secret and delete the file.");
            return 0;
        } catch (Exception e) {
            System.err.println("Error exporting key:");
            System.err.println("  " + (e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName()));
            return 1;
        }
    }

    private String exportFromBc() {
        SigmundConfig config = configMixin.loadConfig();
        ToolConfig bc = config.toolsConfig().get("bc");
        Map<String, String> settings = bc == null ? Map.of() : bc.settings();
        try (Sigmund sigmund = Sigmund.builder().config(config).addTool("bc", settings).build()) {
            return sigmund.findTool(SecretKeyExporter.class, "bc").exportSecretKey(fingerprint);
        }
    }

    /**
     * Creates the file readable by its owner only, refusing to overwrite one that exists, so an
     * export never lands in a file others could already read.
     */
    private static void writeOwnerOnly(Path file, String content) throws IOException {
        if (Files.exists(file)) {
            throw new FileAlreadyExistsException(file.toString(), null, "refusing to overwrite it");
        }
        try {
            Files.createFile(file, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        } catch (UnsupportedOperationException e) {
            Files.createFile(file);
        }
        Files.writeString(file, content);
    }
}
