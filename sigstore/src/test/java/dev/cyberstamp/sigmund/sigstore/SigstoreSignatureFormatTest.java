package dev.cyberstamp.sigmund.sigstore;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.cyberstamp.sigmund.core.Claim;
import dev.cyberstamp.sigmund.core.ClaimTimeSource;
import dev.cyberstamp.sigmund.core.Evidence;
import dev.cyberstamp.sigmund.core.SigstoreClaim;
import dev.cyberstamp.sigmund.core.ToolExecutionException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SigstoreSignatureFormatTest {

    private final SigstoreSignatureFormat format = new SigstoreSignatureFormat();

    @TempDir
    Path tempDir;

    @Nested
    class Properties {
        @Test
        void name() {
            assertThat(format.name()).isEqualTo("sigstore");
        }

        @Test
        void fileExtension() {
            assertThat(format.fileExtension()).isEqualTo(".sigstore.json");
        }

        @Test
        void doesNotSupportCombining() {
            assertThat(format.supportsCombining()).isFalse();
        }
    }

    @Nested
    class CanHandle {
        @Test
        void matchesByExtension() throws IOException {
            Path file = tempDir.resolve("artifact.jar.sigstore.json");
            Files.writeString(file, "{}");
            assertThat(format.canHandle(Evidence.read(file, Evidence.SOURCE_SIDECAR))).isTrue();
        }

        @Test
        void matchesByContent() throws IOException {
            Path file = tempDir.resolve("artifact.jar.sig");
            Files.writeString(file,
                    "{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\"}");
            assertThat(format.canHandleByContent(Evidence.read(file, Evidence.SOURCE_SIDECAR))).isTrue();
        }

        @Test
        void matchesOlderBundleVersion() throws IOException {
            Path file = tempDir.resolve("artifact.sig");
            Files.writeString(file,
                    "{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.1+json\"}");
            assertThat(format.canHandleByContent(Evidence.read(file, Evidence.SOURCE_SIDECAR))).isTrue();
        }

        @Test
        void rejectsNonJsonFile() throws IOException {
            Path file = tempDir.resolve("artifact.jar.asc");
            Files.writeString(file, "-----BEGIN PGP SIGNATURE-----");
            assertThat(format.canHandleByContent(Evidence.read(file, Evidence.SOURCE_SIDECAR))).isFalse();
        }

        @Test
        void rejectsJsonWithoutMediaType() throws IOException {
            Path file = tempDir.resolve("data.json");
            Files.writeString(file, "{\"key\":\"value\"}");
            assertThat(format.canHandleByContent(Evidence.read(file, Evidence.SOURCE_SIDECAR))).isFalse();
        }

        @Test
        void rejectsJsonWithWrongMediaType() throws IOException {
            Path file = tempDir.resolve("data.json");
            Files.writeString(file, "{\"mediaType\":\"application/json\"}");
            assertThat(format.canHandleByContent(Evidence.read(file, Evidence.SOURCE_SIDECAR))).isFalse();
        }

        @Test
        void rejectsEmptyFile() throws IOException {
            Path file = tempDir.resolve("empty.json");
            Files.writeString(file, "");
            assertThat(format.canHandleByContent(Evidence.read(file, Evidence.SOURCE_SIDECAR))).isFalse();
        }

        @Test
        void missingFileCannotBeRead() {
            // Detection works from evidence that was read, so a missing file fails at the
            // read rather than being reported as "not a bundle"
            Path file = tempDir.resolve("nonexistent.json");
            assertThatThrownBy(() -> Evidence.read(file, Evidence.SOURCE_SIDECAR))
                    .isInstanceOf(ToolExecutionException.class);
        }
    }

    @Nested
    class Parse {
        @Test
        void returnsSingleClaim() throws IOException {
            String bundle = "{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\","
                    + "\"content\":\"test\"}";
            Path file = tempDir.resolve("artifact.jar.sigstore.json");
            Files.writeString(file, bundle);

            List<Claim> claims = format.parse(Evidence.read(file, Evidence.SOURCE_SIDECAR));

            assertThat(claims.size()).isEqualTo(1);
            assertThat(claims.get(0)).isInstanceOf(SigstoreClaim.class);
            assertThat(((SigstoreClaim) claims.get(0)).jsonBundle())
                    .isEqualTo(bundle);
        }

        @Test
        void unparseableBundleStillYieldsAClaimWithoutAClaimTime() throws IOException {
            // claim time is evidence Sigmund reads, not evidence it requires: a bundle that
            // will not parse is still handed to the tool, which decides the outcome
            String bundle = "{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\","
                    + "\"content\":\"test\"}";
            Path file = tempDir.resolve("artifact.jar.sigstore.json");
            Files.writeString(file, bundle);

            SigstoreClaim claim = (SigstoreClaim) format.parse(Evidence.read(file, Evidence.SOURCE_SIDECAR)).get(0);

            assertThat(claim.claimTime()).isNull();
            assertThat(claim.claimTimeSource()).isEqualTo(ClaimTimeSource.TRANSPARENCY_LOG);
        }

        @Test
        void claimTimeComesFromTheTransparencyLogEntry() throws IOException {
            Path file = tempDir.resolve("artifact.jar.sigstore.json");
            Files.writeString(file, bundleWithIntegratedTime(1_700_000_000L));

            SigstoreClaim claim = (SigstoreClaim) format.parse(Evidence.read(file, Evidence.SOURCE_SIDECAR)).get(0);

            assertThat(claim.claimTime()).isEqualTo(Instant.ofEpochSecond(1_700_000_000L));
        }

        @Test
        void preservesExactJsonContent() throws IOException {
            String bundle = "  { \"mediaType\" : \"test\" , \"extra\" : true }  ";
            Path file = tempDir.resolve("bundle.sigstore.json");
            Files.writeString(file, bundle);

            List<Claim> claims = format.parse(Evidence.read(file, Evidence.SOURCE_SIDECAR));

            assertThat(((SigstoreClaim) claims.get(0)).jsonBundle())
                    .isEqualTo(bundle);
        }
    }

    /**
     * Builds the fragment of a Sigstore bundle that carries the log entry's integrated
     * time, in protobuf's JSON encoding where an int64 is rendered as a string.
     */
    private static String bundleWithIntegratedTime(long epochSeconds) {
        return "{\"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\","
                + "\"verificationMaterial\":{\"tlogEntries\":[{"
                + "\"logIndex\":\"42\",\"integratedTime\":\"" + epochSeconds + "\"}]}}";
    }
}
