package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class IssuerKindTest {

    @Nested
    class Classification {

        @Test
        void knownDirectoryByItsUrl() {
            assertThat(IssuerKind.of("https://keys.openpgp.org")).isEqualTo(IssuerKind.OPENPGP_DIRECTORY);
            assertThat(IssuerKind.KEYS_OPENPGP_ORG).isEqualTo("https://keys.openpgp.org");
        }

        @Test
        void knownDirectoryMayOmitTheScheme() {
            assertThat(IssuerKind.of("keys.openpgp.org")).isEqualTo(IssuerKind.OPENPGP_DIRECTORY);
            assertThat(IssuerKind.canonicalName("keys.openpgp.org"))
                    .isEqualTo(IssuerKind.KEYS_OPENPGP_ORG);
        }

        @Test
        void knownDirectoryIgnoresHostCaseAndTrailingSlash() {
            assertThat(IssuerKind.canonicalName("https://Keys.OpenPGP.org/"))
                    .isEqualTo(IssuerKind.KEYS_OPENPGP_ORG);
        }

        @Test
        void aKeyserverUrlNamesItsDirectory() {
            assertThat(IssuerKind.directoryServing("hkps://keys.openpgp.org"))
                    .isEqualTo(IssuerKind.KEYS_OPENPGP_ORG);
            assertThat(IssuerKind.directoryServing("https://keys.openpgp.org"))
                    .isEqualTo(IssuerKind.KEYS_OPENPGP_ORG);
            assertThat(IssuerKind.directoryServing("HKPS://Keys.OpenPGP.org/"))
                    .isEqualTo(IssuerKind.KEYS_OPENPGP_ORG);
            assertThat(IssuerKind.directoryServing("hkps://keyserver.ubuntu.com")).isNull();
        }

        @Test
        void anyOtherHttpsUrlIsAnOidcIssuer() {
            assertThat(IssuerKind.of("https://token.actions.githubusercontent.com"))
                    .isEqualTo(IssuerKind.OIDC);
        }

        @Test
        void oidcIssuerNameIsKeptAsWritten() {
            assertThat(IssuerKind.canonicalName(" https://accounts.google.com "))
                    .isEqualTo("https://accounts.google.com");
        }

        @Test
        void anUnknownBareNameIsUnclassified() {
            assertThat(IssuerKind.of("keyserver.ubuntu.com")).isNull();
        }

        @Test
        void plainHttpIsUnclassified() {
            assertThat(IssuerKind.of("http://issuer.example.com")).isNull();
        }
    }

    @Nested
    class Vocabulary {

        @Test
        void directoryAssertsOnlyEmail() {
            assertThat(IssuerKind.OPENPGP_DIRECTORY.asserts(List.of("email"))).isTrue();
            assertThat(IssuerKind.OPENPGP_DIRECTORY.asserts(List.of("subject"))).isFalse();
        }

        @Test
        void oidcAssertsFulcioExtensions() {
            assertThat(IssuerKind.OIDC.asserts(List.of(
                    "subject", "email", "source-repository-uri", "build-config-uri",
                    "deployment-environment", "token-subject"))).isTrue();
        }

    }
}
