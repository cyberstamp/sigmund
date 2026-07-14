package io.github.cyberstamp.sigmund.core;

import java.nio.file.Path;
import java.util.Map;
import java.util.Set;

/**
 * Factory for constructing {@link BcRunner} instances from configuration.
 */
final class BcToolFactory implements SignatureToolFactory {

    @Override
    public String toolName() {
        return "bc";
    }

    @Override
    public Set<String> supportedCredentialTypes() {
        return Set.of(Credential.TYPE_OPENPGP_V4, Credential.TYPE_OPENPGP_V6);
    }

    @Override
    public SignatureTool create(Credential credential, Map<String, String> settings) {
        BcKeyStore keyStore = buildKeyStore(settings);
        String fingerprint = settings.get("signing-fingerprint");
        if (fingerprint == null && credential instanceof FingerprintCredential fp) {
            fingerprint = fp.fingerprint();
        }
        Path tskFile = resolveOptionalPath(settings, "tsk-file");
        return new BcRunner(keyStore, fingerprint, tskFile);
    }

    @Override
    public SignatureTool createVerifyOnly(Map<String, String> settings) {
        BcKeyStore keyStore = buildKeyStore(settings);
        return new BcRunner(keyStore, null, null);
    }

    /**
     * Builds a key store from the given settings.
     */
    private static BcKeyStore buildKeyStore(Map<String, String> settings) {
        Path gnupgHome = resolveGnupgHome(settings);
        Path certDHome = resolveCertDHome(settings);
        Path bcPrivateHome = resolveBcPrivateHome(settings, certDHome);
        return new BcKeyStore(gnupgHome, certDHome, bcPrivateHome);
    }

    /**
     * Resolves the GnuPG home directory.
     */
    private static Path resolveGnupgHome(Map<String, String> settings) {
        String home = settings.get("gnupg-home");
        if (home != null) {
            return Path.of(home);
        }
        String userHome = System.getProperty("user.home");
        return userHome != null ? Path.of(userHome, ".gnupg") : null;
    }

    /**
     * Resolves the shared cert-d directory.
     */
    private static Path resolveCertDHome(Map<String, String> settings) {
        String home = settings.get("cert-d-home");
        if (home != null) {
            return Path.of(home);
        }
        String userHome = System.getProperty("user.home");
        if (userHome == null) {
            throw new SigmundException("Cannot determine cert-d home: user.home is not set");
        }
        return Path.of(userHome, ".local", "share", "openpgp-cert-d");
    }

    /**
     * Resolves the BC private key store directory.
     */
    private static Path resolveBcPrivateHome(Map<String, String> settings, Path certDHome) {
        String home = settings.get("bc-private-home");
        if (home != null) {
            return Path.of(home);
        }
        return certDHome.resolve("bc-private");
    }

    /**
     * Resolves an optional file path from settings.
     */
    private static Path resolveOptionalPath(Map<String, String> settings, String key) {
        String value = settings.get(key);
        return value != null ? Path.of(value) : null;
    }
}
