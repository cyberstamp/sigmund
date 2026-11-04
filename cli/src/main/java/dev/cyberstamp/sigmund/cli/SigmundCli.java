package dev.cyberstamp.sigmund.cli;

import io.quarkus.picocli.runtime.annotations.TopCommand;
import picocli.CommandLine;

@TopCommand
@CommandLine.Command(name = "sigmund", mixinStandardHelpOptions = true, versionProvider = VersionProvider.class, description = "Sigmund - sign artifacts and verify who signed them", subcommands = {
        KeygenCommand.class, SignCommand.class, SignerInfoCommand.class, VerifySignatureCommand.class,
        ExportCertCommand.class, InspectSignerCommand.class })
public class SigmundCli {
}
