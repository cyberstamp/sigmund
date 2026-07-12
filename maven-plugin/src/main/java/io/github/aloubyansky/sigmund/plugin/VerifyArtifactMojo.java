package io.github.aloubyansky.sigmund.plugin;

import io.github.aloubyansky.sigmund.core.DiscoveryConfig;
import io.github.aloubyansky.sigmund.core.Sigmund;
import io.github.aloubyansky.sigmund.core.SignatureVerificationReport;
import java.io.File;
import java.util.List;
import java.util.Map;
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
 * @see Sigmund
 * @see SignatureVerificationReport
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

        Sigmund sigmund = createSigmund();
        SignatureVerificationReport report = performVerification(sigmund);

        logReport(report);
        checkVerdict(report);
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

    private Sigmund createSigmund() throws MojoExecutionException {
        try {
            Map<String, Map<String, String>> toolOverrides = SequoiaHomeResolver.toolOverrides(sqHome);
            return Sigmund.builder()
                    .discover()
                    .discoveryConfig(new DiscoveryConfig(true, false, List.of(), toolOverrides))
                    .build();
        } catch (Exception e) {
            throw new MojoExecutionException("Failed to create verifier", e);
        }
    }

    private SignatureVerificationReport performVerification(Sigmund sigmund)
            throws MojoExecutionException {
        try {
            return sigmund.verify(file.toPath(), signature.toPath());
        } catch (Exception e) {
            throw new MojoExecutionException("Verification failed", e);
        }
    }

    private void logReport(SignatureVerificationReport report) {
        getLog().info("");
        getLog().info("========================================");
        for (String line : report.format().split("\n")) {
            getLog().info(line);
        }
        getLog().info("========================================");
        getLog().info("");
    }

    private void checkVerdict(SignatureVerificationReport report)
            throws MojoExecutionException {
        boolean pass = lenient ? report.isLenientPass() : report.isPass();
        if (!pass) {
            throw new MojoExecutionException(failureMessage(report));
        }
        getLog().info("Verification successful!");
    }

    private String failureMessage(SignatureVerificationReport report) {
        boolean hasResults = report.files().stream()
                .anyMatch(f -> !f.results().isEmpty());
        return switch (report.verdict()) {
            case NONE_PASSED -> !hasResults
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
