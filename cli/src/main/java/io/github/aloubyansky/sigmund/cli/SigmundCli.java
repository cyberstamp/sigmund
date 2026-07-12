package io.github.aloubyansky.sigmund.cli;

import io.quarkus.picocli.runtime.annotations.TopCommand;
import picocli.CommandLine;

@TopCommand
@CommandLine.Command(name = "sigmund", mixinStandardHelpOptions = true, versionProvider = VersionProvider.class, description = "Sigmund - hybrid PQC signing for Maven artifacts", subcommands = {
        KeygenCommand.class, SignCommand.class, VerifyCommand.class, ExportCertCommand.class })
public class SigmundCli {
}
