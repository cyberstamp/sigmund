package dev.cyberstamp.sigmund.cli;

import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.SignatureVerificationReport;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.Callable;
import picocli.CommandLine;

/**
 * Command-line interface for verifying hybrid signatures.
 * <p>
 * This command verifies all signature blocks in a hybrid signature file.
 * It supports two verification modes:
 * <ul>
 * <li><b>Default mode</b>: All signatures must pass.</li>
 * <li><b>Lenient mode</b> (--lenient flag): At least one signature must pass, none may fail.</li>
 * </ul>
 */
@CommandLine.Command(name = "verify-signature", description = "Verify an artifact's signature file (.asc or .sigstore.json)", mixinStandardHelpOptions = true)
public class VerifySignatureCommand implements Callable<Integer> {

    @CommandLine.Option(names = { "--file" }, required = true, description = "Artifact file to verify")
    private String file;

    @CommandLine.Option(names = { "--signature" }, required = true, description = "Signature file (.asc or .sigstore.json)")
    private String signature;

    @CommandLine.Mixin
    private SqHomeMixin sqHomeMixin;

    @CommandLine.Mixin
    private ConfigMixin configMixin;

    @CommandLine.Option(names = {
            "--lenient" }, description = "Pass if at least one signature is valid and none failed (default: all must pass)")
    private boolean lenient;

    @Override
    public Integer call() {
        try {
            SigmundConfig config = configMixin.loadConfig();
            Path artifactFile = Paths.get(file);
            Path signatureFile = Paths.get(this.signature);

            Sigmund.Builder builder = Sigmund.builder()
                    .config(config);

            if (sqHomeMixin.hasExplicitHome()) {
                builder.toolsConfig(sqHomeMixin.applyTo(config.toolsConfig()));
            }

            try (Sigmund sigmund = builder.build()) {
                SignatureVerificationReport report = sigmund.verify(artifactFile, signatureFile);

                System.out.println(report.format());

                if (lenient) {
                    return report.isLenientPass() ? 0 : 1;
                }
                return report.isPass() ? 0 : 1;
            }
        } catch (Exception e) {
            printErrorMessage(e);
            return 1;
        }
    }

    private void printErrorMessage(Exception e) {
        System.err.println("Error verifying signature:");
        String msg = e.getMessage();
        System.err.println("  " + (msg != null && !msg.isEmpty() ? msg : e.getClass().getSimpleName()));
        Throwable cause = e.getCause();
        while (cause != null) {
            String causeMsg = cause.getMessage();
            if (causeMsg != null && !causeMsg.isEmpty()) {
                System.err.println("  Caused by: " + causeMsg);
            }
            cause = cause.getCause();
        }
        System.err.println();
        System.err.println("Ensure that:");
        System.err.println("  - The signer's public key is available");
        System.err.println("  - The artifact and signature files exist and are readable");
    }
}
