package io.github.aloubyansky.pqc.maven.cli;

import io.quarkus.picocli.runtime.annotations.TopCommand;
import picocli.CommandLine;

@TopCommand
@CommandLine.Command(name = "pqc-sign", mixinStandardHelpOptions = true, versionProvider = VersionProvider.class, description = "PQC hybrid signing tool for Maven artifacts", subcommands = {
        KeygenCommand.class, SignCommand.class, VerifyCommand.class, ExportCertCommand.class })
public class PqcSignCli {
}
