package io.github.aloubyansky.sigmund.plugin;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class SignatureInspectorTest {

    @Nested
    class VersionLabelTests {

        @Test
        void v4ReturnsPGP4() {
            assertEquals("PGP4", SignatureInspector.versionLabel(4));
        }

        @Test
        void v6ReturnsPGP6() {
            assertEquals("PGP6", SignatureInspector.versionLabel(6));
        }

        @Test
        void v3ReturnsPGP3() {
            assertEquals("PGP3", SignatureInspector.versionLabel(3));
        }

        @Test
        void v5ReturnsPGP5() {
            assertEquals("PGP5", SignatureInspector.versionLabel(5));
        }

        @Test
        void zeroReturnsDash() {
            assertEquals("-", SignatureInspector.versionLabel(0));
        }

        @Test
        void negativeReturnsDash() {
            assertEquals("-", SignatureInspector.versionLabel(-1));
        }
    }

    @Nested
    class ParseKeyserversTests {

        @Test
        void singleServer() {
            assertEquals(List.of("hkps://keys.openpgp.org"),
                    SignatureInspector.parseKeyservers("hkps://keys.openpgp.org"));
        }

        @Test
        void multipleServers() {
            assertEquals(
                    List.of("hkps://keyserver.ubuntu.com", "hkps://keys.openpgp.org"),
                    SignatureInspector.parseKeyservers(
                            "hkps://keyserver.ubuntu.com,hkps://keys.openpgp.org"));
        }

        @Test
        void withWhitespaceTrimmed() {
            assertEquals(
                    List.of("hkps://a.com", "hkps://b.com"),
                    SignatureInspector.parseKeyservers("  hkps://a.com , hkps://b.com  "));
        }

        @Test
        void emptySegmentsFiltered() {
            assertEquals(List.of("hkps://a.com"),
                    SignatureInspector.parseKeyservers("hkps://a.com,,, "));
        }

        @Test
        void allEmptyReturnsEmptyList() {
            assertEquals(List.of(), SignatureInspector.parseKeyservers(",,,"));
        }
    }
}
