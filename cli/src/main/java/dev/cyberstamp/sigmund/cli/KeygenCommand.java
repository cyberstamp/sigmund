package dev.cyberstamp.sigmund.cli;

import dev.cyberstamp.sigmund.core.KeyGenerator;
import dev.cyberstamp.sigmund.core.PassphraseProvider;
import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundConfig;
import dev.cyberstamp.sigmund.core.ToolConfig;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;
import picocli.CommandLine;

@CommandLine.Command(name = "keygen", description = {
        "Generate a new Bouncy Castle signing key.",
        "Keys for sq and gpg are generated with those tools: sq key generate, gpg --quick-gen-key." }, mixinStandardHelpOptions = true)
public class KeygenCommand implements Callable<Integer> {

    @CommandLine.Option(names = {
            "--userid" }, required = true, description = "User ID for the key (e.g., \"Alice <alice@example.org>\")")
    private String userId;

    @CommandLine.Option(names = {
            "--cipher-suite" }, description = "Cipher suite (default: tools.bc.cipher-suite, else ed25519)")
    private String cipherSuite;

    @CommandLine.Option(names = {
            "--credential-type" }, description = "Key version: pgp4 or pgp6 (default: pgp4, which keyservers serve and gpg signs with)")
    private String credentialType;

    @CommandLine.Option(names = {
            "--passphrase-env" }, description = "Environment variable containing the passphrase (default: SIGMUND_BC_PASSPHRASE)")
    private String passphraseEnv;

    @CommandLine.Mixin
    private ConfigMixin configMixin;

    @Override
    public Integer call() {
        try {
            return generateBcKey();
        } catch (Exception e) {
            printErrorMessage(e);
            return 1;
        }
    }

    private int generateBcKey() {
        SigmundConfig config = configMixin.loadConfig();

        Map<String, String> settings = new HashMap<>();
        ToolConfig toolConfig = config.toolsConfig().get("bc");
        if (toolConfig != null) {
            settings.putAll(toolConfig.settings());
        }
        if (passphraseEnv != null) {
            settings.put("passphrase-env", passphraseEnv);
        }

        PassphraseResult passphraseResult = resolveKeygenPassphrase();

        Sigmund.Builder builder = Sigmund.builder().config(config);
        if (passphraseResult.provider != null) {
            builder.bcPassphraseProvider(passphraseResult.provider);
        }
        try (Sigmund sigmund = builder.addSigningTool("bc", settings).build()) {
            KeyGenerator keygen = sigmund.findTool(KeyGenerator.class, "bc");
            String fingerprint = keygen.generateKey(userId, cipherSuite, credentialType);

            System.out.println("BC key generated successfully!");
            System.out.println();
            System.out.println("Fingerprint: " + fingerprint);
            if (passphraseResult.provider != null) {
                if (passphraseResult.envVarSource != null) {
                    System.out.println("Key is passphrase-protected (from " + passphraseResult.envVarSource + ").");
                } else {
                    System.out.println("Key is passphrase-protected.");
                }
            }
            System.out.println();
            System.out.println("Use this fingerprint with the 'sign' command.");
            return 0;
        }
    }

    private record PassphraseResult(PassphraseProvider provider, String envVarSource) {
    }

    /**
     * Resolves the passphrase provider for keygen, prompting with confirmation
     * when interactive. Returns a result with a null provider if no passphrase
     * should be set.
     *
     * <p>
     * This method builds a {@link PassphraseProvider} that captures the
     * passphrase as a {@code char[]} and passes it to the builder via
     * {@link Sigmund.Builder#bcPassphraseProvider} — never converting to
     * {@code String}. A {@code String} is immutable and cannot be zeroed,
     * so converting would leave the passphrase in heap memory indefinitely.
     * The {@code char[]} is zeroed after the provider's first invocation.
     *
     * <p>
     * The returned {@link PassphraseResult} includes the env var name when
     * the passphrase was sourced from the environment, so the caller can
     * notify the user — an env var set in a prior session or CI config
     * would otherwise silently encrypt the key.
     */
    private PassphraseResult resolveKeygenPassphrase() {
        String envVar = passphraseEnv != null ? passphraseEnv : "SIGMUND_BC_PASSPHRASE";
        String envValue = System.getenv(envVar);
        if (envValue != null && !envValue.isEmpty()) {
            return new PassphraseResult(fp -> envValue.toCharArray(), envVar);
        }
        if (passphraseEnv != null) {
            throw new IllegalArgumentException(
                    "Environment variable " + passphraseEnv + " is not set");
        }
        java.io.Console console = System.console();
        if (console == null) {
            return new PassphraseResult(null, null);
        }
        char[] passphrase = console.readPassword("Enter passphrase for new BC key (empty for none): ");
        if (passphrase == null || passphrase.length == 0) {
            return new PassphraseResult(null, null);
        }
        char[] confirm = console.readPassword("Confirm passphrase: ");
        if (!Arrays.equals(passphrase, confirm)) {
            Arrays.fill(passphrase, '\0');
            if (confirm != null) {
                Arrays.fill(confirm, '\0');
            }
            throw new IllegalArgumentException("Passphrases do not match");
        }
        if (confirm != null) {
            Arrays.fill(confirm, '\0');
        }
        PassphraseProvider provider = fp -> {
            char[] copy = Arrays.copyOf(passphrase, passphrase.length);
            Arrays.fill(passphrase, '\0');
            return copy;
        };
        return new PassphraseResult(provider, null);
    }

    private void printErrorMessage(Exception e) {
        System.err.println("Error generating key:");
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
    }
}
