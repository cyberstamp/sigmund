package io.github.aloubyansky.sigmund.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class OidcCredentialTest {

    @Test
    void exactMatch() {
        var a = new OidcCredential("https://issuer.example.com", "https://github.com/org/repo");
        var b = new OidcCredential("https://issuer.example.com", "https://github.com/org/repo");
        assertTrue(a.matches(b));
    }

    @Test
    void differentIssuer_noMatch() {
        var a = new OidcCredential("https://issuer1.example.com", "subject");
        var b = new OidcCredential("https://issuer2.example.com", "subject");
        assertFalse(a.matches(b));
    }

    @Test
    void differentSubject_noMatch() {
        var a = new OidcCredential("https://issuer.example.com", "subject-a");
        var b = new OidcCredential("https://issuer.example.com", "subject-b");
        assertFalse(a.matches(b));
    }

    @Test
    void crossType_email_noMatch() {
        var oidc = new OidcCredential("https://issuer.example.com", "alice@example.com");
        var email = new EmailCredential("alice@example.com");
        assertFalse(oidc.matches(email));
    }

    @Test
    void crossType_fingerprint_noMatch() {
        var oidc = new OidcCredential("https://issuer.example.com", "subject");
        var fp = new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23");
        assertFalse(oidc.matches(fp));
    }

    @Test
    void type_isOidc() {
        assertEquals("oidc",
                new OidcCredential("https://issuer.example.com", "subject").type());
    }

    @Test
    void displayName_includesIssuer() {
        var cred = new OidcCredential("https://issuer.example.com", "alice@example.com");
        assertEquals("alice@example.com (via https://issuer.example.com)", cred.displayName());
    }

    @Test
    void nullIssuer_throws() {
        assertThrows(IllegalArgumentException.class,
                () -> new OidcCredential(null, "subject"));
    }

    @Test
    void blankSubject_throws() {
        assertThrows(IllegalArgumentException.class,
                () -> new OidcCredential("https://issuer.example.com", "  "));
    }
}
