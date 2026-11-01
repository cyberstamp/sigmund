package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
            assertThat(format.name()).isEqualTo("openpgp");
        }

        @Test
        void fileExtension() {
            assertThat(format.fileExtension()).isEqualTo(".asc");
        }

        @Test
        void supportsCombining() {
            assertThat(format.supportsCombining()).isTrue();
        }
    }

    @Nested
    class CanHandle {

        @Test
        void validAscFile(@TempDir Path tmp) throws IOException {
            Path file = tmp.resolve("sig.asc");
            Files.writeString(file, "-----BEGIN PGP SIGNATURE-----\ndata\n-----END PGP SIGNATURE-----\n");
            assertThat(format.canHandle(Evidence.read(file, Evidence.SOURCE_SIDECAR))).isTrue();
        }

        @Test
        void nonPgpFile(@TempDir Path tmp) throws IOException {
            Path file = tmp.resolve("bundle.json");
            Files.writeString(file, "{\"mediaType\": \"application/vnd.dev.sigstore.bundle.v0.3+json\"}");
            assertThat(format.canHandle(Evidence.read(file, Evidence.SOURCE_SIDECAR))).isFalse();
        }

        @Test
        void missingFileCannotBeRead(@TempDir Path tmp) {
            // Detection reads the evidence rather than guessing from the name, so a file that
            // is not there fails when it is read, not silently later
            Path file = tmp.resolve("nonexistent.asc");
            assertThatThrownBy(() -> Evidence.read(file, Evidence.SOURCE_SIDECAR))
                    .isInstanceOf(ToolExecutionException.class);
        }
    }

    @Nested
    class CanHandleByContent {

        @Test
        void returnsTrueForValidPgpContent(@TempDir Path tmp) throws IOException {
            Path file = tmp.resolve("sig.bin");
            Files.writeString(file, "-----BEGIN PGP SIGNATURE-----\ndata\n-----END PGP SIGNATURE-----\n");
            assertThat(format.canHandleByContent(Evidence.read(file, Evidence.SOURCE_SIDECAR))).isTrue();
        }

        @Test
        void returnsFalseForNonPgpContent(@TempDir Path tmp) throws IOException {
            Path file = tmp.resolve("data.bin");
            Files.writeString(file, "This is not a PGP signature file.");
            assertThat(format.canHandleByContent(Evidence.read(file, Evidence.SOURCE_SIDECAR))).isFalse();
        }

        @Test
        void missingFileCannotBeRead(@TempDir Path tmp) {
            Path file = tmp.resolve("missing.bin");
            assertThatThrownBy(() -> Evidence.read(file, Evidence.SOURCE_SIDECAR))
                    .isInstanceOf(ToolExecutionException.class);
        }
    }

    @Nested
    class Parse {

        @Test
        void singleBlock(@TempDir Path tmp) throws IOException {
            String block = "-----BEGIN PGP SIGNATURE-----\n\niQEzBAABCgAdFiEE\n=test\n-----END PGP SIGNATURE-----\n";
            Path file = tmp.resolve("sig.asc");
            Files.writeString(file, block);

            List<Claim> claims = format.parse(Evidence.read(file, Evidence.SOURCE_SIDECAR));
            assertThat(claims).hasSize(1);
            assertThat(claims.get(0)).isInstanceOf(OpenPgpClaim.class);
        }

        @Test
        void multipleBlocks(@TempDir Path tmp) throws IOException {
            String block1 = "-----BEGIN PGP SIGNATURE-----\n\niQEzBAABCgAdFiEE\n=test\n-----END PGP SIGNATURE-----\n";
            String block2 = "-----BEGIN PGP SIGNATURE-----\n\niQEzBAABCgAdFiFF\n=test\n-----END PGP SIGNATURE-----\n";
            Path file = tmp.resolve("combined.asc");
            Files.writeString(file, block1 + block2);

            List<Claim> claims = format.parse(Evidence.read(file, Evidence.SOURCE_SIDECAR));
            assertThat(claims).hasSize(2);
        }

        @Test
        void parsedClaimRetainsArmoredBlock(@TempDir Path tmp) throws IOException {
            String block = "-----BEGIN PGP SIGNATURE-----\n\niQEzBAABCgAdFiEE\n=test\n-----END PGP SIGNATURE-----\n";
            Path file = tmp.resolve("sig.asc");
            Files.writeString(file, block);

            OpenPgpClaim claim = (OpenPgpClaim) format.parse(Evidence.read(file, Evidence.SOURCE_SIDECAR)).get(0);
            assertThat(claim.armoredBlock()).contains("BEGIN PGP SIGNATURE");
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
            assertThat(result).contains("block1");
            assertThat(result).contains("block2");
        }

        /**
         * Verifiers that read only the first block — Maven Central among them — must see the
         * classic signature, whatever order the signatures were made in.
         */
        @Test
        void putsV4BlocksBeforeV6KeepingTheOrderWithinAVersion(@TempDir Path tmp) throws IOException {
            BcKeyStore store = new BcKeyStore(null, tmp.resolve("cert-d"), tmp.resolve("bc-private"));
            Path artifact = Files.writeString(tmp.resolve("artifact.txt"), "content");
            Path v4First = sign(store, artifact, tmp.resolve("v4-first.asc"), null);
            Path v6 = sign(store, artifact, tmp.resolve("v6.asc"), Credential.TYPE_PGP6);
            Path v4Second = sign(store, artifact, tmp.resolve("v4-second.asc"), null);
            Path output = tmp.resolve("combined.asc");

            format.combine(List.of(v6, v4First, v4Second), output);

            List<String> blocks = AscCombiner.extractAllBlocks(Files.readString(output));
            assertThat(blocks).containsExactly(Files.readString(v4First), Files.readString(v4Second),
                    Files.readString(v6));
        }

        private Path sign(BcKeyStore store, Path artifact, Path signature, String credentialType) {
            String fingerprint = new BcRunner(store, null, null).generateKey("Test <test@example.com>", "ed25519",
                    credentialType);
            SigningTests.signWithOnlyKey(new BcRunner(store, fingerprint, null), artifact, signature);
            return signature;
        }
    }
}
