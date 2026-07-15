package io.github.cyberstamp.sigmund.cli;

import io.github.cyberstamp.sigmund.core.Sigmund;
import io.github.cyberstamp.sigmund.core.SigmundConfig;
import io.github.cyberstamp.sigmund.core.SignatureVerificationReport;
import io.github.cyberstamp.sigmund.core.ToolsConfig;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
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
@CommandLine.Command(name = "verify-signature", description = "Verify a hybrid signature", mixinStandardHelpOptions = true)
public class VerifySignatureCommand implements Callable<Integer> {

    @CommandLine.Option(names = { "--file" }, required = true, description = "Artifact file to verify")
    private String file;

    @CommandLine.Option(names = { "--signature" }, required = true, description = "Signature file (.asc)")
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
                ToolsConfig dc = config.toolsConfig();
                Map<String, Map<String, String>> tools = new HashMap<>(dc.tools());
                Map<String, String> sqSettings = new HashMap<>(tools.getOrDefault("sq", Map.of()));
                sqSettings.put("home", sqHomeMixin.resolveSequoiaHome().toString());
                tools.put("sq", sqSettings);
                builder.toolsConfig(new ToolsConfig(
                        dc.fetchSignerInfo(), dc.importToKeyring(),
                        dc.keyservers(), tools, dc.toolPriority()));
            }

            Sigmund sigmund = builder.build();

            SignatureVerificationReport report = sigmund.verify(artifactFile, signatureFile);

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

    private void printErrorMessage(Exception e) {
        System.err.println("Error verifying signature:");
        String msg = e.getMessage();
        System.err.println("  " + (msg != null && !msg.isEmpty() ? msg : e.getClass().getSimpleName()));
        System.err.println();
        System.err.println("Ensure that:");
        System.err.println("  - The signer's public key is available");
        System.err.println("  - The artifact and signature files exist and are readable");
    }
}
