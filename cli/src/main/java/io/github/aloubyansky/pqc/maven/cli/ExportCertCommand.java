package io.github.aloubyansky.pqc.maven.cli;

import io.github.aloubyansky.pqc.maven.core.SqRunner;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;
import picocli.CommandLine;

/**
 * Command-line interface for exporting PQC certificates.
 * <p>
 * This command exports the public certificate for a PQC key stored in the
 * Sequoia keystore. The exported certificate can be distributed to others
 * for signature verification.
 *
 * <p>
 * Example usage:
 *
 * <pre>
 * # Print certificate to stdout
 * pqc-sign export-cert --fingerprint ABC123...
 *
 * # Save certificate to a file
 * pqc-sign export-cert --fingerprint ABC123... --output signer.cert
 * </pre>
 *
 * @see SqRunner#exportCert(String)
 */
@CommandLine.Command(name = "export-cert", description = "Export a PQC public certificate", mixinStandardHelpOptions = true)
public class ExportCertCommand implements Callable<Integer> {

    @CommandLine.Option(names = {
            "--fingerprint" }, required = true, description = "Fingerprint of the PQC key to export")
    private String fingerprint;

    @CommandLine.Mixin
    private SqHomeMixin sqHomeMixin;

    @CommandLine.Option(names = { "--output", "-o" }, description = "Output file (default: print to stdout)")
    private String output;

    @Override
    public Integer call() {
        try {
            Path sqHomeDir = sqHomeMixin.resolveSequoiaHome();
            SqRunner sq = new SqRunner(sqHomeDir);

            String cert = sq.exportCert(fingerprint);

            if (output != null) {
                Path outputPath = sqHomeMixin.expandTilde(output);
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

}
