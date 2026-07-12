package io.github.aloubyansky.sigmund.core;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class SignatureEvidenceAdapterTest {

    private static final Path ARTIFACT = Path.of("artifact.jar");
    private static final Path EVIDENCE = Path.of("artifact.jar.asc");
    private static final String FP = "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12";
    private static final OpenPgpVerificationUnit V4_UNIT = new OpenPgpVerificationUnit("armored", 4, FP, 1);

    @Nested
    class BasicVerification {

        @Test
        void singleUnitVerifiedAndCredentialsExtracted() {
            var tool = mockTool("gpg", true, true, passVerifyResult(),
                    List.of(new FingerprintCredential("openpgp4", FP)));
            var adapter = adapterWith(singleUnitFormat(), List.of(tool), DiscoveryConfig.DEFAULT);

            List<EvidenceResult> results = adapter.verify(ARTIFACT, EVIDENCE);

            assertEquals(1, results.size());
            assertEquals(Verdict.PASS, results.get(0).verdict());
            assertEquals(1, results.get(0).provenCredentials().size());
            assertEquals("openpgp4", results.get(0).provenCredentials().get(0).type());
            assertEquals("openpgp", results.get(0).provider());
        }

        @Test
        void noToolCanHandleUnit() {
            var tool = mockTool("gpg", true, false, null, List.of());
            var adapter = adapterWith(singleUnitFormat(), List.of(tool), DiscoveryConfig.DEFAULT);

            List<EvidenceResult> results = adapter.verify(ARTIFACT, EVIDENCE);

            assertEquals(1, results.size());
            assertEquals(Verdict.SKIPPED, results.get(0).verdict());
            assertTrue(results.get(0).provenCredentials().isEmpty());
        }

        @Test
        void multipleUnitsRoutedIndependently() {
            var format = mockFormat("openpgp", ".asc", true,
                    List.of(V4_UNIT, new OpenPgpVerificationUnit("armored2", 6, "FP2", 1)));
            var v4Tool = mockToolForVersion("gpg", 4, passVerifyResult(),
                    List.of(new FingerprintCredential("openpgp4", FP)));
            var v6Tool = mockToolForVersion("sq", 6, passVerifyResult(),
                    List.of(new FingerprintCredential("openpgp6", "FP2")));
            var adapter = adapterWith(format, List.of(v4Tool, v6Tool), DiscoveryConfig.DEFAULT);

            List<EvidenceResult> results = adapter.verify(ARTIFACT, EVIDENCE);

            assertEquals(2, results.size());
            assertEquals("openpgp4", results.get(0).provenCredentials().get(0).type());
            assertEquals("openpgp6", results.get(1).provenCredentials().get(0).type());
        }
    }

    @Nested
    class Availability {

        @Test
        void availableWhenAnyToolAvailable() {
            var tool = mockTool("gpg", true, false, null, List.of());
            var adapter = adapterWith(singleUnitFormat(), List.of(tool), DiscoveryConfig.DEFAULT);
            assertTrue(adapter.isAvailable());
        }

        @Test
        void unavailableWhenNoToolAvailable() {
            var tool = mockTool("gpg", false, false, null, List.of());
            var adapter = adapterWith(singleUnitFormat(), List.of(tool), DiscoveryConfig.DEFAULT);
            assertFalse(adapter.isAvailable());
        }

        @Test
        void nameDelegatesToFormat() {
            var adapter = adapterWith(singleUnitFormat(), List.of(), DiscoveryConfig.DEFAULT);
            assertEquals("openpgp", adapter.name());
        }

        @Test
        void canHandleDelegatesToFormat() {
            var adapter = adapterWith(singleUnitFormat(), List.of(), DiscoveryConfig.DEFAULT);
            assertTrue(adapter.canHandle(EVIDENCE));
        }
    }

    @Nested
    class KeyFetching {

        @Test
        void noKeyWithDiscoveryDisabled() {
            var config = new DiscoveryConfig(false, false, List.of(), java.util.Map.of());
            var tool = mockTool("gpg", true, true, noKeyVerifyResult(), List.of());
            var adapter = adapterWith(singleUnitFormat(), List.of(tool), config);

            List<EvidenceResult> results = adapter.verify(ARTIFACT, EVIDENCE);

            assertEquals(Verdict.NO_KEY, results.get(0).verdict());
        }

        @Test
        void noKeyWithDiscoveryEnabledAndImportSucceeds() {
            var config = new DiscoveryConfig(true, false, List.of("hkps://keys.example.com"),
                    java.util.Map.of());
            var importingTool = mockImportingTool("gpg", true);
            var adapter = adapterWith(singleUnitFormat(), List.of(importingTool), config);

            List<EvidenceResult> results = adapter.verify(ARTIFACT, EVIDENCE);

            assertEquals(Verdict.PASS, results.get(0).verdict());
        }

        @Test
        void noKeyWithDiscoveryEnabledButNoKeyImporter() {
            var config = new DiscoveryConfig(true, false, List.of(), java.util.Map.of());
            var tool = mockTool("gpg", true, true, noKeyVerifyResult(), List.of());
            var adapter = adapterWith(singleUnitFormat(), List.of(tool), config);

            List<EvidenceResult> results = adapter.verify(ARTIFACT, EVIDENCE);

            assertEquals(Verdict.NO_KEY, results.get(0).verdict());
        }

        @Test
        void noKeyWithImportFailure() {
            var config = new DiscoveryConfig(true, false, List.of("hkps://keys.example.com"),
                    java.util.Map.of());
            var importingTool = mockImportingTool("gpg", false);
            var adapter = adapterWith(singleUnitFormat(), List.of(importingTool), config);

            List<EvidenceResult> results = adapter.verify(ARTIFACT, EVIDENCE);

            assertEquals(Verdict.NO_KEY, results.get(0).verdict());
        }
    }

    // --- Helpers ---

    private static SignatureEvidenceAdapter adapterWith(SignatureFormat format,
            List<SignatureTool> tools, DiscoveryConfig config) {
        return new SignatureEvidenceAdapter(format, tools, config);
    }

    private static SignatureFormat singleUnitFormat() {
        return mockFormat("openpgp", ".asc", true, List.of(V4_UNIT));
    }

    private static SignatureFormat mockFormat(String name, String ext, boolean canHandle,
            List<VerificationUnit> units) {
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
            public boolean canHandle(Path f) {
                return canHandle;
            }

            @Override
            public List<VerificationUnit> parse(Path f) {
                return units;
            }
        };
    }

    private static OpenPgpVerifyResult passVerifyResult() {
        return new OpenPgpVerifyResult(Verdict.PASS, "Test", "RSA", 4, FP, FP);
    }

    private static OpenPgpVerifyResult noKeyVerifyResult() {
        return new OpenPgpVerifyResult(Verdict.NO_KEY, null, null, 4, null, null);
    }

    private static SignatureTool mockTool(String name, boolean available, boolean canVerify,
            VerifyResult result, List<Credential> credentials) {
        return new SignatureTool() {
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
            public boolean canVerify(VerificationUnit unit) {
                return canVerify;
            }

            @Override
            public SignResult sign(Path a, Path o) {
                throw new UnsupportedOperationException();
            }

            @Override
            public VerifyResult verify(Path a, VerificationUnit u) {
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
            public boolean canVerify(VerificationUnit unit) {
                return unit instanceof OpenPgpVerificationUnit o && o.packetVersion() == version;
            }

            @Override
            public SignResult sign(Path a, Path o) {
                throw new UnsupportedOperationException();
            }

            @Override
            public VerifyResult verify(Path a, VerificationUnit u) {
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
        public boolean canVerify(VerificationUnit unit) {
            return true;
        }

        @Override
        public SignResult sign(Path a, Path o) {
            throw new UnsupportedOperationException();
        }

        @Override
        public VerifyResult verify(Path a, VerificationUnit u) {
            if (imported) {
                return new OpenPgpVerifyResult(Verdict.PASS, "Test", "RSA", 4, FP, FP);
            }
            return new OpenPgpVerifyResult(Verdict.NO_KEY, null, null, 4, null, null);
        }

        @Override
        public List<Credential> extractCredentials(VerifyResult r) {
            if (r.verdict() == Verdict.PASS) {
                return List.of(new FingerprintCredential("openpgp4", FP));
            }
            return List.of();
        }

        @Override
        public boolean importKey(String keyId, String keyserver) {
            imported = importSucceeds;
            return importSucceeds;
        }

        private static SignatureFormat mockFormat(String name, String ext, boolean canHandle,
                List<VerificationUnit> units) {
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
                public boolean canHandle(Path f) {
                    return canHandle;
                }

                @Override
                public List<VerificationUnit> parse(Path f) {
                    return units;
                }
            };
        }
    }
}
