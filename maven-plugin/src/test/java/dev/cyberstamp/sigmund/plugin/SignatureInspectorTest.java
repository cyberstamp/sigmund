package dev.cyberstamp.sigmund.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import dev.cyberstamp.sigmund.core.ArtifactCoords;
import dev.cyberstamp.sigmund.core.IndeterminateReason;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class SignatureInspectorTest {

    @Nested
    class VersionLabelTests {

        @Test
        void v4ReturnsPGP4() {
            assertThat(SignatureInspector.versionLabel(4)).isEqualTo("PGP4");
        }

        @Test
        void v6ReturnsPGP6() {
            assertThat(SignatureInspector.versionLabel(6)).isEqualTo("PGP6");
        }

        @Test
        void v3ReturnsPGP3() {
            assertThat(SignatureInspector.versionLabel(3)).isEqualTo("PGP3");
        }

        @Test
        void v5ReturnsPGP5() {
            assertThat(SignatureInspector.versionLabel(5)).isEqualTo("PGP5");
        }

        @Test
        void zeroReturnsDash() {
            assertThat(SignatureInspector.versionLabel(0)).isEqualTo("-");
        }

        @Test
        void negativeReturnsDash() {
            assertThat(SignatureInspector.versionLabel(-1)).isEqualTo("-");
        }
    }

    @Nested
    class ParseKeyserversTests {

        @Test
        void singleServer() {
            assertThat(SignatureInspector.parseKeyservers("hkps://keys.openpgp.org"))
                    .isEqualTo(List.of("hkps://keys.openpgp.org"));
        }

        @Test
        void multipleServers() {
            assertThat(SignatureInspector.parseKeyservers(
                    "hkps://keyserver.ubuntu.com,hkps://keys.openpgp.org"))
                    .isEqualTo(List.of("hkps://keyserver.ubuntu.com", "hkps://keys.openpgp.org"));
        }

        @Test
        void withWhitespaceTrimmed() {
            assertThat(SignatureInspector.parseKeyservers("  hkps://a.com , hkps://b.com  "))
                    .isEqualTo(List.of("hkps://a.com", "hkps://b.com"));
        }

        @Test
        void emptySegmentsFiltered() {
            assertThat(SignatureInspector.parseKeyservers("hkps://a.com,,, "))
                    .isEqualTo(List.of("hkps://a.com"));
        }

        @Test
        void allEmptyReturnsEmptyList() {
            assertThat(SignatureInspector.parseKeyservers(",,,"))
                    .isEqualTo(List.of());
        }
    }

    @Nested
    class SignedArtifactRecords {

        private final ArtifactCoords coords = new ArtifactCoords("org.example", "lib", "", "jar", "1.0");

        /** A signature file that yielded no claim is neither absent evidence nor a broken tool. */
        @ParameterizedTest
        @EnumSource(value = IndeterminateReason.class, names = { "EVIDENCE_UNREADABLE", "EVIDENCE_MALFORMED" })
        void aSignatureFileWithoutClaimsIsIndeterminateNamingTheFile(IndeterminateReason reason) {
            Path file = Path.of("repo/lib-1.0.jar.asc");
            SignatureInspector.SignedArtifact entry = SignatureInspector.SignedArtifact.withoutClaims(coords, "central",
                    file, reason, file + " is empty");

            assertThat(entry.hasClaim()).isTrue();
            assertThat(entry.verifyResult().isIndeterminate()).isTrue();
            assertThat(entry.verifyResult().reason()).isEqualTo(reason);
            assertThat(entry.verifyResult().detail()).isEqualTo(file + " is empty");
            assertThat(entry.signatureFile()).isEqualTo(file);
        }
    }
}
