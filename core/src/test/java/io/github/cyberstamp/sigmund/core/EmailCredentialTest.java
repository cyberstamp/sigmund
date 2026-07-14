package io.github.cyberstamp.sigmund.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class EmailCredentialTest {

    @Test
    void exactMatch() {
        var a = new EmailCredential("alice@example.com");
        var b = new EmailCredential("alice@example.com");
        assertTrue(a.matches(b));
    }

    @Test
    void differentEmailNoMatch() {
        var a = new EmailCredential("alice@example.com");
        var b = new EmailCredential("bob@example.com");
        assertFalse(a.matches(b));
    }

    @Test
    void caseSensitive() {
        var a = new EmailCredential("Alice@Example.com");
        var b = new EmailCredential("alice@example.com");
        assertFalse(a.matches(b));
    }

    @Test
    void crossTypeNoMatch() {
        var email = new EmailCredential("alice@example.com");
        var fp = new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23");
        assertFalse(email.matches(fp));
    }

    @Test
    void typeIsEmail() {
        assertEquals("email", new EmailCredential("a@b.com").type());
    }

    @Test
    void displayNameReturnsEmail() {
        assertEquals("alice@example.com", new EmailCredential("alice@example.com").displayName());
    }

    @Test
    void nullEmailThrows() {
        assertThrows(IllegalArgumentException.class, () -> new EmailCredential(null));
    }

    @Test
    void blankEmailThrows() {
        assertThrows(IllegalArgumentException.class, () -> new EmailCredential("  "));
    }
}
