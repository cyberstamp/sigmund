package io.github.aloubyansky.sigmund.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class OpenPgpSignatureFormatTest {

    private final OpenPgpSignatureFormat format = new OpenPgpSignatureFormat();

    @Nested
    class Properties {

        @Test
        void name() {
            assertEquals("openpgp", format.name());
        }

        @Test
        void fileExtension() {
            assertEquals(".asc", format.fileExtension());
        }

        @Test
        void supportsCombining() {
            assertTrue(format.supportsCombining());
        }
    }

    @Nested
    class CanHandle {

        @Test
        void validAscFile(@TempDir Path tmp) throws IOException {
            Path file = tmp.resolve("sig.asc");
            Files.writeString(file, "-----BEGIN PGP SIGNATURE-----\ndata\n-----END PGP SIGNATURE-----\n");
            assertTrue(format.canHandle(file));
        }

        @Test
        void nonPgpFile(@TempDir Path tmp) throws IOException {
            Path file = tmp.resolve("bundle.json");
            Files.writeString(file, "{\"mediaType\": \"application/vnd.dev.sigstore.bundle.v0.3+json\"}");
            assertFalse(format.canHandle(file));
        }

        @Test
        void missingFile(@TempDir Path tmp) {
            Path file = tmp.resolve("nonexistent.asc");
            assertFalse(format.canHandle(file));
        }
    }

    @Nested
    class Parse {

        @Test
        void singleBlock(@TempDir Path tmp) throws IOException {
            String block = "-----BEGIN PGP SIGNATURE-----\n\niQEzBAABCgAdFiEE\n=test\n-----END PGP SIGNATURE-----\n";
            Path file = tmp.resolve("sig.asc");
            Files.writeString(file, block);

            List<VerificationUnit> units = format.parse(file);
            assertEquals(1, units.size());
            assertInstanceOf(OpenPgpVerificationUnit.class, units.get(0));
        }

        @Test
        void multipleBlocks(@TempDir Path tmp) throws IOException {
            String block1 = "-----BEGIN PGP SIGNATURE-----\n\niQEzBAABCgAdFiEE\n=test\n-----END PGP SIGNATURE-----\n";
            String block2 = "-----BEGIN PGP SIGNATURE-----\n\niQEzBAABCgAdFiFF\n=test\n-----END PGP SIGNATURE-----\n";
            Path file = tmp.resolve("combined.asc");
            Files.writeString(file, block1 + block2);

            List<VerificationUnit> units = format.parse(file);
            assertEquals(2, units.size());
        }

        @Test
        void parsedUnitRetainsArmoredBlock(@TempDir Path tmp) throws IOException {
            String block = "-----BEGIN PGP SIGNATURE-----\n\niQEzBAABCgAdFiEE\n=test\n-----END PGP SIGNATURE-----\n";
            Path file = tmp.resolve("sig.asc");
            Files.writeString(file, block);

            OpenPgpVerificationUnit unit = (OpenPgpVerificationUnit) format.parse(file).get(0);
            assertTrue(unit.armoredBlock().contains("BEGIN PGP SIGNATURE"));
        }
    }

    @Nested
    class Combine {

        @Test
        void combinesTwoFiles(@TempDir Path tmp) throws IOException {
            Path sig1 = tmp.resolve("sig1.asc");
            Path sig2 = tmp.resolve("sig2.asc");
            Path output = tmp.resolve("combined.asc");
            Files.writeString(sig1, "-----BEGIN PGP SIGNATURE-----\nblock1\n-----END PGP SIGNATURE-----\n");
            Files.writeString(sig2, "-----BEGIN PGP SIGNATURE-----\nblock2\n-----END PGP SIGNATURE-----\n");

            format.combine(List.of(sig1, sig2), output);

            String result = Files.readString(output);
            assertTrue(result.contains("block1"));
            assertTrue(result.contains("block2"));
        }
    }
}
