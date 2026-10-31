package dev.cyberstamp.sigmund.cli;

import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.Signer;
import dev.cyberstamp.sigmund.core.SigningInfo;
import dev.cyberstamp.sigmund.core.SigningPlan;
import java.util.concurrent.Callable;
import picocli.CommandLine;

@CommandLine.Command(name = "signer-info", description = "Display signing tool and identity information", mixinStandardHelpOptions = true)
public class SignerInfoCommand implements Callable<Integer> {

    @CommandLine.Mixin
    private SqHomeMixin sqHomeMixin;

    @CommandLine.Mixin
    private ConfigMixin configMixin;

    @CommandLine.Option(names = { "--profile" }, description = "Signing profile to display (default: use the default profile)")
    private String profile;

    @Override
    public Integer call() {
        try {
            SigmundConfig config = configMixin.loadConfig();
            try (Sigmund sigmund = SigningSupport.buildSigningSigmund(config, sqHomeMixin)) {
                Signer signer = profile != null
                        ? sigmund.signer(profile)
                        : sigmund.signer();

                SigningPlan plan = signer.plan();
                if (profile != null) {
                    System.out.println("Profile: " + profile);
                }
                for (SigningInfo info : plan.keys()) {
                    System.out.println(info.display());
                }
                for (String problem : plan.problems()) {
                    System.out.println("Problem: " + problem);
                }
                return plan.problems().isEmpty() ? 0 : 1;
            }
        } catch (Exception e) {
            System.err.println("Error: " + (e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName()));
            return 1;
        }
    }
}
