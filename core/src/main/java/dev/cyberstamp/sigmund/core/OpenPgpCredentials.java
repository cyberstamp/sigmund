package dev.cyberstamp.sigmund.core;

import java.util.ArrayList;
import java.util.List;

/**
 * Derives proven credentials from a verified OpenPGP signature.
 *
 * <p>
 * Every OpenPGP backend — Bouncy Castle, Sequoia and GnuPG — proves the same things, because
 * what a verified signature establishes is a property of the signature rather than of the
 * tool that checked it: the signing key's fingerprint, and the address in the user ID that
 * key carries. Each tool still owns the decision to use this mapping, as the
 * {@link SignatureTool#extractCredentials(VerifyResult)} contract requires; they simply agree
 * on the answer.
 */
public final class OpenPgpCredentials {

    private OpenPgpCredentials() {
    }

    /**
     * Returns the credentials a result proves.
     *
     * <p>
     * An unverified claim proves nothing, whatever metadata it carries: a signature that did
     * not verify says nothing about who made it. The fingerprint's credential type follows the
     * signature packet version, so a v6 signature proves a v6 credential and policy written for
     * one does not silently accept the other.
     *
     * @param result the verification result
     * @return the proven credentials, empty when the claim did not verify
     */
    public static List<Credential> from(VerifyResult result) {
        if (result == null || !result.isVerified()) {
            return List.of();
        }
        if (!(result instanceof OpenPgpVerifyResult openPgp) || openPgp.fingerprint() == null) {
            return List.of();
        }
        String credentialType = openPgp.version() < 6
                ? Credential.TYPE_OPENPGP_V4
                : Credential.TYPE_OPENPGP_V6;
        List<Credential> credentials = new ArrayList<>(2);
        credentials.add(new FingerprintCredential(credentialType, openPgp.fingerprint()));
        String email = email(result.signerDisplayName());
        if (email != null) {
            credentials.add(new EmailCredential(email));
        }
        return List.copyOf(credentials);
    }

    /**
     * Extracts the email address from an OpenPGP user ID of the form {@code "Name <email>"},
     * accepting a bare address as well.
     *
     * @param userId the user ID string, may be {@code null}
     * @return the extracted email, or {@code null} when the user ID carries none
     */
    public static String email(String userId) {
        if (userId == null) {
            return null;
        }
        int open = userId.indexOf('<');
        int close = userId.indexOf('>', open + 1);
        if (open >= 0 && close > open + 1) {
            return userId.substring(open + 1, close).trim();
        }
        String trimmed = userId.trim();
        if (trimmed.contains("@") && !trimmed.contains(" ")) {
            return trimmed;
        }
        return null;
    }
}
