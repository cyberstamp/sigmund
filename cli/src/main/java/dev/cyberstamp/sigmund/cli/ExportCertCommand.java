package dev.cyberstamp.sigmund.cli;

import dev.cyberstamp.sigmund.core.CertExporter;
import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.ToolConfig;
import dev.cyberstamp.sigmund.core.UserPaths;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.Callable;
import picocli.CommandLine;

/**
 * Exports the public certificate of a key Bouncy Castle holds, such as one {@code sigmund keygen}
 * generated, so that it can be published and others can verify what it signs.
 * <p>
 * The CLI covers {@code bc}, the backend with no command-line tool of its own; {@code sq cert
 * export} and {@code gpg --export} export the keys those tools hold. The stores are the ones
 * {@code tools.bc} in {@code sigmund.yaml} names, as for {@code keygen}.
 *
 * <pre>
 * sigmund export-cert --fingerprint 4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12
 * sigmund export-cert --fingerprint 4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12 --output alice.asc
 * </pre>
 */
@CommandLine.Command(name = "export-cert", description = "Export the public certificate of a Bouncy Castle key, such as one keygen generated", mixinStandardHelpOptions = true)
public class ExportCertCommand implements Callable<Integer> {

    @CommandLine.Option(names = {
            "--fingerprint" }, required = true, description = "Fingerprint of the key whose certificate to export")
    private String fingerprint;

    @CommandLine.Option(names = { "--output", "-o" }, description = "Output file (default: print to stdout)")
    private String output;

    @CommandLine.Mixin
    private ConfigMixin configMixin;

    @Override
    public Integer call() {
        try {
            String cert = exportFromBc();
            if (output != null) {
                Path outputPath = UserPaths.expand(output);
                Files.writeString(outputPath, cert);
                System.out.println("Certificate written to " + outputPath.toAbsolutePath());
            } else {
                System.out.print(cert);
            }
            return 0;
        } catch (Exception e) {
            System.err.println("Error exporting certificate:");
            System.err.println("  " + (e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName()));
            return 1;
        }
    }

    private String exportFromBc() {
        SigmundConfig config = configMixin.loadConfig();
        ToolConfig bc = config.toolsConfig().get("bc");
        Map<String, String> settings = bc == null ? Map.of() : bc.settings();
        try (Sigmund sigmund = Sigmund.builder().config(config).addTool("bc", settings).build()) {
            return sigmund.findTool(CertExporter.class, "bc").exportCert(fingerprint);
        }
    }
}
