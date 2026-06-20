package io.github.aloubyansky.sigmund.plugin;

import io.github.aloubyansky.sigmund.core.GpgRunner;
import io.github.aloubyansky.sigmund.core.HybridVerifier;
import io.github.aloubyansky.sigmund.core.SqRunner;
import io.github.aloubyansky.sigmund.core.VerificationReport;
import java.io.File;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

/**
 * Maven plugin goal that verifies all signatures in an ASC file.
 * <p>
 * By default all signatures must pass. In lenient mode
 * at least one signature must pass and none may fail.
 *
 * @see HybridVerifier
 * @see VerificationReport
 */
@Mojo(name = "verify-artifact", requiresProject = false, threadSafe = true)
public class VerifyArtifactMojo extends AbstractMojo {

    @Parameter(property = "file", required = true)
    private File file;

    @Parameter(property = "signature", required = true)
    private File signature;

    @Parameter(property = "sigmund.sqHome")
    private File sqHome;

    @Parameter(property = "sigmund.lenient", defaultValue = "false")
    private boolean lenient;

    @Override
    public void execute() throws MojoExecutionException {
        validateInputFiles();

        getLog().info("Verifying signature for: " + file.getName());
        getLog().info("Using signature file: " + signature.getName());

        HybridVerifier verifier = createVerifier();
        VerificationReport report = performVerification(verifier);

        logReport(report);
        checkVerificationResult(report);
    }

    private void validateInputFiles() throws MojoExecutionException {
        if (!file.exists()) {
            throw new MojoExecutionException("File does not exist: " + file.getAbsolutePath());
        }
        if (!signature.exists()) {
            throw new MojoExecutionException(
                    "Signature file does not exist: " + signature.getAbsolutePath());
        }
    }

    private HybridVerifier createVerifier() throws MojoExecutionException {
        try {
            GpgRunner gpg = new GpgRunner();
            SqRunner sq = createSqRunner();
            return new HybridVerifier(gpg, sq);
        } catch (Exception e) {
            throw new MojoExecutionException("Failed to create hybrid verifier", e);
        }
    }

    private SqRunner createSqRunner() throws MojoExecutionException {
        if (!SqRunner.isAvailable()) {
            getLog().warn("Sequoia (sq) not found - PQC verification will be skipped");
            return null;
        }
        return new SqRunner(SequoiaHomeResolver.resolve(sqHome));
    }

    private VerificationReport performVerification(HybridVerifier verifier)
            throws MojoExecutionException {
        try {
            return verifier.verify(file.toPath(), signature.toPath());
        } catch (Exception e) {
            throw new MojoExecutionException("Verification failed", e);
        }
    }

    private void logReport(VerificationReport report) {
        getLog().info("");
        getLog().info("========================================");
        for (String line : report.format().split("\n")) {
            getLog().info(line);
        }
        getLog().info("========================================");
        getLog().info("");
    }

    private void checkVerificationResult(VerificationReport report)
            throws MojoExecutionException {
        boolean pass = lenient ? report.isLenientPass() : report.isPass();
        if (!pass) {
            throw new MojoExecutionException(failureMessage(report));
        }
        getLog().info("Verification successful!");
    }

    private String failureMessage(VerificationReport report) {
        return switch (report.outcome()) {
            case NONE_PASSED -> report.signatures().isEmpty()
                    ? "No signatures found in signature file"
                    : "No signatures could be verified - check that the required keys are available";
            case PASS_WITH_FAILURES ->
                "Signature verification failed - one or more signatures are invalid";
            case PASS_WITH_SKIPS ->
                "Not all signatures could be verified - use sigmund.lenient=true to tolerate skipped signatures";
            case ALL_PASS ->
                throw new IllegalStateException("failureMessage called with ALL_PASS outcome");
        };
    }
}
