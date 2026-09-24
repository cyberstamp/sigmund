package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SignatureEvidenceAdapterTest {

    @TempDir
    static Path fixtures;

    /**
     * Real files on disk: the adapter digests the evidence it reads, so a path that does not
     * exist is not a usable fixture.
     */
    static Path ARTIFACT;
    static Path EVIDENCE;

    @BeforeAll
    static void createFixtures() throws IOException {
        ARTIFACT = Files.writeString(fixtures.resolve("artifact.jar"), "artifact bytes");
        EVIDENCE = Files.writeString(fixtures.resolve("artifact.jar.asc"), "evidence bytes");
    }

    private static final String FP = "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12";
    private static final OpenPgpClaim V4_CLAIM = new OpenPgpClaim("armored", 4, FP, 1, null);

    @Nested
    class ClaimProvenance {

        @Test
        void recordsTheEvidenceFileThatWasRead(@TempDir Path dir) throws Exception {
            Path evidence = Files.writeString(dir.resolve("lib.jar.asc"), "abc");
            var adapter = adapterWith(singleClaimFormat(),
                    List.of(mockTool("bc", true, true, passVerifyResult(), List.of())));

            List<ClaimResult> results = adapter.verify(dir.resolve("lib.jar"),
                    Evidence.read(evidence, Evidence.SOURCE_SIDECAR));

            EvidenceRef ref = results.get(0).evidence();
            assertThat(ref.file()).isEqualTo(evidence);
            assertThat(ref.digest().sha256()).isEqualTo(
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
            assertThat(ref.source()).isEqualTo(Evidence.SOURCE_SIDECAR);
        }

        @Test
        void recordsTheTrustRootTheToolVerifiedAgainst(@TempDir Path dir) throws Exception {
            Path evidence = Files.writeString(dir.resolve("lib.jar.asc"), "abc");
            TrustRootRef root = TrustRootRef.keyring(dir.resolve("cert-d"));
            var adapter = adapterWith(singleClaimFormat(),
                    List.of(mockTool("bc", true, true, passVerifyResult(), List.of(), root)));

            List<ClaimResult> results = adapter.verify(dir.resolve("lib.jar"),
                    Evidence.read(evidence, Evidence.SOURCE_SIDECAR));

            assertThat(results.get(0).trustRoot()).isEqualTo(root);
        }
    }

    @Nested
    class BasicVerification {

        @Test
        void singleClaimVerifiedAndCredentialsExtracted() {
            var tool = mockTool("gpg", true, true, passVerifyResult(),
                    List.of(new FingerprintCredential("openpgp4", FP)));
            var adapter = adapterWith(singleClaimFormat(), List.of(tool));

            List<ClaimResult> results = adapter.verify(ARTIFACT, Evidence.read(EVIDENCE, Evidence.SOURCE_SIDECAR));

            assertThat(results).hasSize(1);
            assertThat((results.get(0).outcome() == ClaimOutcome.VERIFIED)).isTrue();
            assertThat(results.get(0).attesterCredentials()).hasSize(1);
            assertThat(results.get(0).attesterCredentials().get(0).type()).isEqualTo("openpgp4");
            assertThat(results.get(0).kind()).isEqualTo("openpgp");
        }

        @Test
        void noToolCanHandleClaim() {
            var tool = mockTool("gpg", true, false, null, List.of());
            var adapter = adapterWith(singleClaimFormat(), List.of(tool));

            List<ClaimResult> results = adapter.verify(ARTIFACT, Evidence.read(EVIDENCE, Evidence.SOURCE_SIDECAR));

            assertThat(results).hasSize(1);
            assertThat(results.get(0).isIndeterminateBecause(IndeterminateReason.UNSUPPORTED_ALGORITHM)).isTrue();
            assertThat(results.get(0).attesterCredentials()).isEmpty();
        }

        @Test
        void skippedToolFallsThroughToNext() {
            var skipping = mockTool("bc", true, true,
                    new OpenPgpVerifyResult(ClaimOutcome.INDETERMINATE, IndeterminateReason.UNSUPPORTED_ALGORITHM, null, null,
                            4, null, null),
                    List.of());
            var passing = mockTool("gpg", true, true, passVerifyResult(),
                    List.of(new FingerprintCredential("openpgp4", FP)));
            var adapter = adapterWith(singleClaimFormat(), List.of(skipping, passing));

            List<ClaimResult> results = adapter.verify(ARTIFACT, Evidence.read(EVIDENCE, Evidence.SOURCE_SIDECAR));

            assertThat(results).hasSize(1);
            assertThat((results.get(0).outcome() == ClaimOutcome.VERIFIED)).isTrue();
            assertThat(results.get(0).attesterCredentials()).hasSize(1);
        }

        @Test
        void allToolsSkipReturnsSkipped() {
            var tool1 = mockTool("bc", true, true,
                    new OpenPgpVerifyResult(ClaimOutcome.INDETERMINATE, IndeterminateReason.UNSUPPORTED_ALGORITHM, null, null,
                            4, null, null),
                    List.of());
            var tool2 = mockTool("gpg", true, true,
                    new OpenPgpVerifyResult(ClaimOutcome.INDETERMINATE, IndeterminateReason.UNSUPPORTED_ALGORITHM, null, null,
                            4, null, null),
                    List.of());
            var adapter = adapterWith(singleClaimFormat(), List.of(tool1, tool2));

            List<ClaimResult> results = adapter.verify(ARTIFACT, Evidence.read(EVIDENCE, Evidence.SOURCE_SIDECAR));

            assertThat(results).hasSize(1);
            assertThat(results.get(0).isIndeterminateBecause(IndeterminateReason.UNSUPPORTED_ALGORITHM)).isTrue();
        }

        @Test
        void multipleClaimsRoutedIndependently() {
            var format = mockFormat("openpgp", ".asc", true,
                    List.of(V4_CLAIM, new OpenPgpClaim("armored2", 6, "FP2", 1, null)));
            var v4Tool = mockToolForVersion("gpg", 4, passVerifyResult(),
                    List.of(new FingerprintCredential("openpgp4", FP)));
            var v6Tool = mockToolForVersion("sq", 6, passVerifyResult(),
                    List.of(new FingerprintCredential("openpgp6", "FP2")));
            var adapter = adapterWith(format, List.of(v4Tool, v6Tool));

            List<ClaimResult> results = adapter.verify(ARTIFACT, Evidence.read(EVIDENCE, Evidence.SOURCE_SIDECAR));

            assertThat(results).hasSize(2);
            assertThat(results.get(0).attesterCredentials().get(0).type()).isEqualTo("openpgp4");
            assertThat(results.get(1).attesterCredentials().get(0).type()).isEqualTo("openpgp6");
        }
    }

    @Nested
    class Availability {

        @Test
        void availableWhenAnyToolAvailable() {
            var tool = mockTool("gpg", true, false, null, List.of());
            var adapter = adapterWith(singleClaimFormat(), List.of(tool));
            assertThat(adapter.isAvailable()).isTrue();
        }

        @Test
        void unavailableWhenNoToolAvailable() {
            var tool = mockTool("gpg", false, false, null, List.of());
            var adapter = adapterWith(singleClaimFormat(), List.of(tool));
            assertThat(adapter.isAvailable()).isFalse();
        }

        @Test
        void nameDelegatesToFormat() {
            var adapter = adapterWith(singleClaimFormat(), List.of());
            assertThat(adapter.name()).isEqualTo("openpgp");
        }

        @Test
        void canHandleDelegatesToFormat() {
            var adapter = adapterWith(singleClaimFormat(), List.of());
            assertThat(adapter.canHandle(Evidence.read(EVIDENCE, Evidence.SOURCE_SIDECAR))).isTrue();
        }
    }

    @Nested
    class KeyFetching {

        @Test
        void noKeyWithNonImporterTool() {
            var tool = mockTool("gpg", true, true, noKeyVerifyResult(), List.of());
            var adapter = adapterWith(singleClaimFormat(), List.of(tool));

            List<ClaimResult> results = adapter.verify(ARTIFACT, Evidence.read(EVIDENCE, Evidence.SOURCE_SIDECAR));

            assertThat(results.get(0).isIndeterminateBecause(IndeterminateReason.KEY_UNAVAILABLE)).isTrue();
        }

        @Test
        void noKeyWithImportSucceeds() {
            var importingTool = mockImportingTool("bc", true);
            var adapter = adapterWith(singleClaimFormat(), List.of(importingTool));

            List<ClaimResult> results = adapter.verify(ARTIFACT, Evidence.read(EVIDENCE, Evidence.SOURCE_SIDECAR));

            assertThat((results.get(0).outcome() == ClaimOutcome.VERIFIED)).isTrue();
        }

        @Test
        void noKeyWithImportFailure() {
            var importingTool = mockImportingTool("bc", false);
            var adapter = adapterWith(singleClaimFormat(), List.of(importingTool));

            List<ClaimResult> results = adapter.verify(ARTIFACT, Evidence.read(EVIDENCE, Evidence.SOURCE_SIDECAR));

            assertThat(results.get(0).isIndeterminateBecause(IndeterminateReason.KEY_UNAVAILABLE)).isTrue();
        }

        @Test
        void noKeyContinuesToNextTool() {
            var failingTool = mockTool("gpg", true, true, noKeyVerifyResult(), List.of());
            var passingTool = mockImportingTool("bc", true);
            var adapter = adapterWith(singleClaimFormat(), List.of(failingTool, passingTool));

            List<ClaimResult> results = adapter.verify(ARTIFACT, Evidence.read(EVIDENCE, Evidence.SOURCE_SIDECAR));

            assertThat((results.get(0).outcome() == ClaimOutcome.VERIFIED)).isTrue();
        }

        @Test
        void noKeyFromAllToolsReturnsLastNoKey() {
            var tool1 = mockTool("gpg", true, true, noKeyVerifyResult(), List.of());
            var tool2 = mockImportingTool("bc", false);
            var adapter = adapterWith(singleClaimFormat(), List.of(tool1, tool2));

            List<ClaimResult> results = adapter.verify(ARTIFACT, Evidence.read(EVIDENCE, Evidence.SOURCE_SIDECAR));

            assertThat(results.get(0).isIndeterminateBecause(IndeterminateReason.KEY_UNAVAILABLE)).isTrue();
        }

        @Test
        void failContinuesToNextTool() {
            var failTool = mockTool("bc", true, true, failVerifyResult(), List.of());
            var passingTool = mockTool("gpg", true, true, passVerifyResult(),
                    List.of(new FingerprintCredential("openpgp4", FP)));
            var adapter = adapterWith(singleClaimFormat(), List.of(failTool, passingTool));

            List<ClaimResult> results = adapter.verify(ARTIFACT, Evidence.read(EVIDENCE, Evidence.SOURCE_SIDECAR));

            assertThat((results.get(0).outcome() == ClaimOutcome.VERIFIED)).isTrue();
        }

        @Test
        void failOverridesNoKey() {
            var noKeyTool = mockTool("bc", true, true, noKeyVerifyResult(), List.of());
            var failTool = mockTool("gpg", true, true, failVerifyResult(), List.of());
            var adapter = adapterWith(singleClaimFormat(), List.of(noKeyTool, failTool));

            List<ClaimResult> results = adapter.verify(ARTIFACT, Evidence.read(EVIDENCE, Evidence.SOURCE_SIDECAR));

            assertThat((results.get(0).outcome() == ClaimOutcome.FAILED)).isTrue();
        }
    }

    // --- Helpers ---

    private static SignatureEvidenceAdapter adapterWith(SignatureFormat format,
            List<SignatureTool> tools) {
        return new SignatureEvidenceAdapter(format, tools);
    }

    private static SignatureFormat singleClaimFormat() {
        return mockFormat("openpgp", ".asc", true, List.of(V4_CLAIM));
    }

    private static SignatureFormat mockFormat(String name, String ext, boolean canHandle,
            List<Claim> claims) {
        return new SignatureFormat() {
            @Override
            public String name() {
                return name;
            }

            @Override
            public String fileExtension() {
                return ext;
            }

            @Override
            public boolean canHandleByContent(Evidence e) {
                return canHandle;
            }

            @Override
            public List<Claim> parse(Evidence e) {
                return claims;
            }
        };
    }

    private static OpenPgpVerifyResult passVerifyResult() {
        return new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, "Test", "RSA", 4, FP, FP);
    }

    private static OpenPgpVerifyResult noKeyVerifyResult() {
        return new OpenPgpVerifyResult(ClaimOutcome.INDETERMINATE, IndeterminateReason.KEY_UNAVAILABLE, null, null, 4, FP, FP);
    }

    private static OpenPgpVerifyResult failVerifyResult() {
        return new OpenPgpVerifyResult(ClaimOutcome.FAILED, null, null, "RSA", 4, FP, FP);
    }

    @Nested
    class AToolThatThrows {

        @Test
        void isRecordedAsAnIndeterminateClaimRatherThanAbortingTheRun() {
            var adapter = adapterWith(singleClaimFormat(),
                    List.of(toolThrowingFrom("sq", "verify")));

            List<ClaimResult> results = adapter.verify(ARTIFACT,
                    Evidence.read(EVIDENCE, Evidence.SOURCE_SIDECAR));

            assertThat(results).hasSize(1);
            assertThat(results.get(0).isIndeterminateBecause(IndeterminateReason.TOOL_UNAVAILABLE))
                    .isTrue();
            assertThat(results.get(0).verifiedBy()).isEqualTo("sq");
        }

        /** The reported crash: the tool verified the claim, then threw naming its trust root. */
        @Test
        void isRecordedEvenWhenItThrowsAfterVerifying() {
            var adapter = adapterWith(singleClaimFormat(),
                    List.of(toolThrowingFrom("sq", "trustRoot")));

            List<ClaimResult> results = adapter.verify(ARTIFACT,
                    Evidence.read(EVIDENCE, Evidence.SOURCE_SIDECAR));

            assertThat(results.get(0).isIndeterminateBecause(IndeterminateReason.TOOL_UNAVAILABLE))
                    .isTrue();
        }

        @Test
        void doesNotStopAnotherToolFromVerifyingTheClaim() {
            var adapter = adapterWith(singleClaimFormat(),
                    List.of(toolThrowingFrom("sq", "verify"),
                            mockTool("bc", true, true, passVerifyResult(), List.of())));

            List<ClaimResult> results = adapter.verify(ARTIFACT,
                    Evidence.read(EVIDENCE, Evidence.SOURCE_SIDECAR));

            assertThat(results.get(0).outcome()).isEqualTo(ClaimOutcome.VERIFIED);
            assertThat(results.get(0).verifiedBy()).isEqualTo("bc");
        }
    }

    /**
     * A tool that fails the way a misconfigured backend does: an unchecked exception from
     * the call named by {@code failingCall}.
     */
    private static SignatureTool toolThrowingFrom(String name, String failingCall) {
        return new SignatureTool() {
            @Override
            public TrustRootRef trustRoot() {
                if ("trustRoot".equals(failingCall)) {
                    throw new IllegalStateException("no cert store configured");
                }
                return TrustRootRef.unknown();
            }

            @Override
            public String name() {
                return name;
            }

            @Override
            public boolean isAvailable() {
                return true;
            }

            @Override
            public boolean canSign() {
                return false;
            }

            @Override
            public SignatureFormat signatureFormat() {
                return mockFormat("openpgp", ".asc", true, List.of());
            }

            @Override
            public Set<String> supportedCredentialTypes() {
                return Set.of("openpgp4");
            }

            @Override
            public boolean canVerify(Claim claim) {
                return true;
            }

            @Override
            public SignResult sign(Path a, Path o) {
                throw new UnsupportedOperationException();
            }

            @Override
            public VerifyResult verify(Path a, Claim u) {
                if ("verify".equals(failingCall)) {
                    throw new IllegalStateException("sq exited with code 70");
                }
                return passVerifyResult();
            }

            @Override
            public List<Credential> extractCredentials(VerifyResult r) {
                return List.of();
            }
        };
    }

    private static SignatureTool mockTool(String name, boolean available, boolean canVerify,
            VerifyResult result, List<Credential> credentials) {
        return mockTool(name, available, canVerify, result, credentials, TrustRootRef.unknown());
    }

    private static SignatureTool mockTool(String name, boolean available, boolean canVerify,
            VerifyResult result, List<Credential> credentials, TrustRootRef trustRoot) {
        return new SignatureTool() {
            @Override
            public TrustRootRef trustRoot() {
                return trustRoot;
            }

            @Override
            public String name() {
                return name;
            }

            @Override
            public boolean isAvailable() {
                return available;
            }

            @Override
            public boolean canSign() {
                return false;
            }

            @Override
            public SignatureFormat signatureFormat() {
                return mockFormat("openpgp", ".asc", true, List.of());
            }

            @Override
            public Set<String> supportedCredentialTypes() {
                return Set.of("openpgp4");
            }

            @Override
            public boolean canVerify(Claim claim) {
                return canVerify;
            }

            @Override
            public SignResult sign(Path a, Path o) {
                throw new UnsupportedOperationException();
            }

            @Override
            public VerifyResult verify(Path a, Claim u) {
                return result;
            }

            @Override
            public List<Credential> extractCredentials(VerifyResult r) {
                return credentials;
            }
        };
    }

    private static SignatureTool mockToolForVersion(String name, int version,
            VerifyResult result, List<Credential> credentials) {
        return new SignatureTool() {
            @Override
            public String name() {
                return name;
            }

            @Override
            public boolean isAvailable() {
                return true;
            }

            @Override
            public boolean canSign() {
                return false;
            }

            @Override
            public SignatureFormat signatureFormat() {
                return mockFormat("openpgp", ".asc", true, List.of());
            }

            @Override
            public Set<String> supportedCredentialTypes() {
                return Set.of("openpgp6");
            }

            @Override
            public boolean canVerify(Claim claim) {
                return claim instanceof OpenPgpClaim o && o.packetVersion() == version;
            }

            @Override
            public SignResult sign(Path a, Path o) {
                throw new UnsupportedOperationException();
            }

            @Override
            public VerifyResult verify(Path a, Claim u) {
                return result;
            }

            @Override
            public List<Credential> extractCredentials(VerifyResult r) {
                return credentials;
            }
        };
    }

    private static SignatureTool mockImportingTool(String name, boolean importSucceeds) {
        return new ImportingTool(name, importSucceeds);
    }

    private static class ImportingTool implements SignatureTool, KeyImporter {
        private final String name;
        private final boolean importSucceeds;
        private boolean imported;

        ImportingTool(String name, boolean importSucceeds) {
            this.name = name;
            this.importSucceeds = importSucceeds;
        }

        @Override
        public String name() {
            return name;
        }

        @Override
        public boolean isAvailable() {
            return true;
        }

        @Override
        public boolean canSign() {
            return false;
        }

        @Override
        public SignatureFormat signatureFormat() {
            return mockFormat("openpgp", ".asc", true, List.of());
        }

        @Override
        public Set<String> supportedCredentialTypes() {
            return Set.of("openpgp4");
        }

        @Override
        public boolean canVerify(Claim claim) {
            return true;
        }

        @Override
        public SignResult sign(Path a, Path o) {
            throw new UnsupportedOperationException();
        }

        @Override
        public VerifyResult verify(Path a, Claim u) {
            if (imported) {
                return new OpenPgpVerifyResult(ClaimOutcome.VERIFIED, null, "Test", "RSA", 4, FP, FP);
            }
            return new OpenPgpVerifyResult(ClaimOutcome.INDETERMINATE, IndeterminateReason.KEY_UNAVAILABLE, null, null, 4, FP,
                    FP);
        }

        @Override
        public List<Credential> extractCredentials(VerifyResult r) {
            if (r.isVerified()) {
                return List.of(new FingerprintCredential("openpgp4", FP));
            }
            return List.of();
        }

        @Override
        public boolean canFetchKeys() {
            return true;
        }

        @Override
        public boolean fetchKey(String keyId) {
            imported = importSucceeds;
            return importSucceeds;
        }

        private static SignatureFormat mockFormat(String name, String ext, boolean canHandle,
                List<Claim> claims) {
            return new SignatureFormat() {
                @Override
                public String name() {
                    return name;
                }

                @Override
                public String fileExtension() {
                    return ext;
                }

                @Override
                public boolean canHandleByContent(Evidence e) {
                    return canHandle;
                }

                @Override
                public List<Claim> parse(Evidence e) {
                    return claims;
                }
            };
        }
    }
}
