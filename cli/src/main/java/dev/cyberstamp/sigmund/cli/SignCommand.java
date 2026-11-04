package dev.cyberstamp.sigmund.cli;

import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.SignedFile;
import dev.cyberstamp.sigmund.core.SigningOutput;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.concurrent.Callable;
import picocli.CommandLine;

@CommandLine.Command(name = "sign", description = "Sign an artifact with the keys of the configured signing tools", mixinStandardHelpOptions = true)
public class SignCommand implements Callable<Integer> {

    @CommandLine.Option(names = { "--file" }, required = true, description = "Artifact file to sign")
    private String file;

    @CommandLine.Mixin
    private SqHomeMixin sqHomeMixin;

    @CommandLine.Mixin
    private ConfigMixin configMixin;

    @CommandLine.Option(names = {
            "--profile" }, description = "Signing profile to sign with (default: signing.credential-types, else every key)")
    private String profile;

    @CommandLine.Option(names = {
            "--output" }, description = "Output signature file path (only valid when signing produces a single file)")
    private String output;

    @Override
    public Integer call() {
        try {
            SigmundConfig config = configMixin.loadConfig();
            Path artifactFile = Path.of(file);

            try (Sigmund sigmund = buildSigningSigmund(config)) {
                Path outputDir = artifactFile.getParent();
                if (outputDir == null) {
                    outputDir = Path.of(".");
                }
                SigningOutput result = SigningSupport.signer(sigmund, profile).sign(artifactFile, outputDir);

                if (output != null && !output.isEmpty()) {
                    return handleExplicitOutput(result);
                }
                return handleDefaultOutput(result);
            }
        } catch (Exception e) {
            printErrorMessage(e);
            return 1;
        }
    }

    /**
     * Handles the case where {@code --output} is explicitly set.
     * <p>
     * Only valid when signing produces exactly one file. If multiple files
     * are produced, returns an error since a single output path cannot
     * accommodate them all.
     */
    private int handleExplicitOutput(SigningOutput result) throws Exception {
        if (result.files().size() > 1) {
            System.err.println("Error: --output cannot be used when signing produces multiple files ("
                    + result.files().size() + " files produced).");
            System.err.println("Remove --output to use default file names.");
            return 1;
        }
        Path outputFile = Paths.get(output);
        if (!result.files().isEmpty()) {
            Path produced = result.files().get(0).path();
            if (!produced.equals(outputFile)) {
                Files.move(produced, outputFile, StandardCopyOption.REPLACE_EXISTING);
            }
        }
        System.out.println("Signature created successfully!");
        System.out.println();
        System.out.println("Signature file: " + outputFile.toAbsolutePath().normalize());
        return 0;
    }

    /**
     * Handles default output when {@code --output} is not set.
     * <p>
     * {@link dev.cyberstamp.sigmund.core.Signer#sign} already writes files
     * to the output directory with the correct names, so no renaming is needed.
     */
    private int handleDefaultOutput(SigningOutput result) {
        System.out.println("Signature created successfully!");
        System.out.println();
        for (SignedFile sf : result.files()) {
            System.out.println("Signature file: " + sf.path().toAbsolutePath().normalize());
        }
        return 0;
    }

    private Sigmund buildSigningSigmund(SigmundConfig config) {
        return SigningSupport.buildSigningSigmund(config, sqHomeMixin);
    }

    private void printErrorMessage(Exception e) {
        System.err.println("Error creating signature:");
        String message = e.getMessage();
        System.err.println("  " + (message != null && !message.isEmpty() ? message : e.getClass().getSimpleName()));
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
        System.err.println("  - Signing tools are configured in sigmund.yaml or via CLI flags");
        System.err.println("  - The required keys exist and are accessible");
        System.err.println("  - The artifact file exists and is readable");
    }
}
