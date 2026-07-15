package io.github.cyberstamp.sigmund.cli;

import io.github.cyberstamp.sigmund.core.Sigmund;
import io.github.cyberstamp.sigmund.core.SigmundConfig;
import io.github.cyberstamp.sigmund.core.SigmundException;
import io.github.cyberstamp.sigmund.core.SigningOutput;
import io.github.cyberstamp.sigmund.core.ToolConfig;
import io.github.cyberstamp.sigmund.core.ToolsConfig;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import picocli.CommandLine;

@CommandLine.Command(name = "sign", description = "Create a hybrid signature combining GPG and PQC", mixinStandardHelpOptions = true)
public class SignCommand implements Callable<Integer> {

    @CommandLine.Option(names = { "--file" }, required = true, description = "Artifact file to sign")
    private String file;

    @CommandLine.Option(names = {
            "--pqc-fingerprint" }, description = "PQC key fingerprint (64-char hex); overrides config")
    private String pqcFingerprint;

    @CommandLine.Option(names = {
            "--gpg-key" }, description = "GPG key ID/email (default: use GPG's default key); overrides config")
    private String gpgKey;

    @CommandLine.Mixin
    private SqHomeMixin sqHomeMixin;

    @CommandLine.Mixin
    private ConfigMixin configMixin;

    @CommandLine.Option(names = { "--output" }, description = "Output signature file path (default: <file>.asc)")
    private String output;

    @Override
    public Integer call() {
        try {
            SigmundConfig config = configMixin.loadConfig();
            Path artifactFile = Path.of(file);
            Path outputFile = resolveOutputFile(artifactFile);

            Sigmund sigmund = buildSigningSigmund(config);
            Path outputDir = outputFile.getParent();
            if (outputDir == null) {
                outputDir = Path.of(".");
            }
            SigningOutput result = sigmund.signer()
                    .sign(artifactFile, outputDir);

            if (!result.files().isEmpty()) {
                Path produced = result.files().get(0).path();
                if (!produced.equals(outputFile)) {
                    Files.move(produced, outputFile, StandardCopyOption.REPLACE_EXISTING);
                }
            }

            System.out.println("Signature created successfully!");
            System.out.println();
            System.out.println("Signature file: " + outputFile.toAbsolutePath());
            return 0;
        } catch (Exception e) {
            printErrorMessage(e);
            return 1;
        }
    }

    private Sigmund buildSigningSigmund(SigmundConfig config) {
        Sigmund.Builder builder = Sigmund.builder().config(config);

        Map<String, ToolConfig> configuredTools = config.signingConfig().tools();

        List<String> toolNames = configuredTools.isEmpty()
                ? ToolsConfig.DEFAULT_TOOL_PRIORITY
                : List.copyOf(configuredTools.keySet());

        for (String toolName : toolNames) {
            Map<String, String> settings = mergeToolSettings(toolName, configuredTools);
            try {
                builder.addSigningTool(toolName, settings);
            } catch (SigmundException e) {
                if (configuredTools.containsKey(toolName)) {
                    throw e;
                }
                System.err.println("Note: signing tool '" + toolName + "' not available, skipping");
            }
        }

        return builder.build();
    }

    private Map<String, String> mergeToolSettings(String toolName, Map<String, ToolConfig> configuredTools) {
        Map<String, String> settings = new HashMap<>();
        ToolConfig toolConfig = configuredTools.get(toolName);
        if (toolConfig != null) {
            settings.putAll(toolConfig.settings());
        }
        switch (toolName) {
            case "gpg" -> {
                if (gpgKey != null) {
                    settings.put("key-name", gpgKey);
                }
            }
            case "sq" -> {
                if (pqcFingerprint != null) {
                    settings.put("signing-fingerprint", pqcFingerprint);
                }
                if (sqHomeMixin.hasExplicitHome()) {
                    settings.put("home", sqHomeMixin.resolveSequoiaHome().toString());
                }
            }
            case "bc" -> {
                if (pqcFingerprint != null) {
                    settings.put("signing-fingerprint", pqcFingerprint);
                }
            }
        }
        return settings;
    }

    private Path resolveOutputFile(Path artifactFile) {
        if (output != null && !output.isEmpty()) {
            return Paths.get(output);
        }
        return Paths.get(artifactFile.toString() + ".asc");
    }

    private void printErrorMessage(Exception e) {
        System.err.println("Error creating signature:");
        String message = e.getMessage();
        System.err.println("  " + (message != null && !message.isEmpty() ? message : e.getClass().getSimpleName()));
        System.err.println();
        System.err.println("Ensure that:");
        System.err.println("  - Signing tools are configured in sigmund.yaml or via CLI flags");
        System.err.println("  - The required keys exist and are accessible");
        System.err.println("  - The artifact file exists and is readable");
    }
}
