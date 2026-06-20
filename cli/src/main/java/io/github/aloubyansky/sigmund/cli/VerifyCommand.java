package io.github.aloubyansky.sigmund.cli;

import io.github.aloubyansky.sigmund.core.GpgRunner;
import io.github.aloubyansky.sigmund.core.HybridVerifier;
import io.github.aloubyansky.sigmund.core.SqRunner;
import io.github.aloubyansky.sigmund.core.VerificationReport;
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
 *
 * @see HybridVerifier
 * @see VerificationReport
 */
@CommandLine.Command(name = "verify", description = "Verify a hybrid signature", mixinStandardHelpOptions = true)
public class VerifyCommand implements Callable<Integer> {

    @CommandLine.Option(names = { "--file" }, required = true, description = "Artifact file to verify")
    private String file;

    @CommandLine.Option(names = { "--signature" }, required = true, description = "Signature file (.asc)")
    private String signature;

    @CommandLine.Mixin
    private SqHomeMixin sqHomeMixin;

    @CommandLine.Option(names = {
            "--lenient" }, description = "Pass if at least one signature is valid and none failed (default: all must pass)")
    private boolean lenient;

    @Override
    public Integer call() {
        try {
            Path artifactFile = Paths.get(file);
            Path signatureFile = Paths.get(this.signature);

            GpgRunner gpgRunner = new GpgRunner();
            SqRunner sqRunner = createSqRunnerIfAvailable();
            HybridVerifier verifier = new HybridVerifier(gpgRunner, sqRunner);

            VerificationReport report = verifier.verify(artifactFile, signatureFile);

            System.out.println(report.format());

            if (lenient) {
                return report.isLenientPass() ? 0 : 1;
            }
            return report.isPass() ? 0 : 1;
        } catch (Exception e) {
            printErrorMessage(e);
            return 1;
        }
    }

    private SqRunner createSqRunnerIfAvailable() {
        if (!SqRunner.isAvailable()) {
            return null;
        }
        Path sqHomeDir = sqHomeMixin.resolveSequoiaHome();
        return new SqRunner(sqHomeDir);
    }

    private void printErrorMessage(Exception e) {
        System.err.println("Error verifying signature:");
        String msg = e.getMessage();
        System.err.println("  " + (msg != null && !msg.isEmpty() ? msg : e.getClass().getSimpleName()));
        System.err.println();
        System.err.println("Ensure that:");
        System.err.println("  - The 'gpg' command is installed and available");
        System.err.println("  - The signer's public GPG key is in your keyring");
        System.err.println("  - For PQC verification: the 'sq' command is installed");
        System.err.println("  - The artifact and signature files exist and are readable");
    }
}
