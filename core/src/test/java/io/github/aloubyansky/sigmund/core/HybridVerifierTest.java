package io.github.aloubyansky.sigmund.core;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class HybridVerifierTest {

    @Nested
    class ReportTests {

        @Test
        void reportAllPass() {
            VerificationReport report = new VerificationReport(List.of(
                    new SignatureInfo(4, "0xABCD1234", "RSA", "User <u@test.com>",
                            VerificationResult.PASS),
                    new SignatureInfo(6, "abc123def456", SqRunner.DEFAULT_PQC_ALGORITHM, null,
                            VerificationResult.PASS)));

            assertEquals(VerificationOutcome.ALL_PASS, report.outcome());
            assertTrue(report.isPass());
            assertTrue(report.isLenientPass());

            String formatted = report.format();
            assertTrue(formatted.contains("PASS"));
            assertTrue(formatted.contains("0xABCD1234"));
            assertTrue(formatted.contains(SqRunner.DEFAULT_PQC_ALGORITHM));
            assertTrue(formatted.contains("abc123def456"));
        }

        @Test
        void reportOneFail() {
            VerificationReport report = new VerificationReport(List.of(
                    new SignatureInfo(4, "0xABCD1234", "RSA", null, VerificationResult.PASS),
                    new SignatureInfo(6, "abc123", SqRunner.DEFAULT_PQC_ALGORITHM, null,
                            VerificationResult.FAIL)));

            assertEquals(VerificationOutcome.PASS_WITH_FAILURES, report.outcome());
            assertFalse(report.isPass());
            assertFalse(report.isLenientPass());
            String formatted = report.format();
            assertTrue(formatted.contains("FAIL"));
        }

        @Test
        void reportEmpty() {
            VerificationReport report = new VerificationReport(List.of());
            assertEquals(VerificationOutcome.NONE_PASSED, report.outcome());
            assertFalse(report.isPass());
            assertFalse(report.isLenientPass());
            String formatted = report.format();
            assertTrue(formatted.contains("No signatures found"));
        }

        @Test
        void reportSinglePass() {
            VerificationReport report = new VerificationReport(List.of(
                    new SignatureInfo(4, "0xABCD1234", "RSA", null, VerificationResult.PASS)));

            assertEquals(VerificationOutcome.ALL_PASS, report.outcome());
            assertTrue(report.isPass());
            assertTrue(report.isLenientPass());
            String formatted = report.format();
            assertTrue(formatted.contains("1 signature valid"));
        }

        @Test
        void reportNullKeyIdOmitted() {
            VerificationReport report = new VerificationReport(List.of(
                    new SignatureInfo(4, null, "RSA", null, VerificationResult.PASS)));

            String formatted = report.format();
            assertFalse(formatted.contains("[key:"));
        }

        @Test
        void reportSignerUserIdShown() {
            VerificationReport report = new VerificationReport(List.of(
                    new SignatureInfo(4, "KEY1", "RSA", "Test <test@test.com>",
                            VerificationResult.PASS)));

            String formatted = report.format();
            assertTrue(formatted.contains("[signer: Test <test@test.com>]"));
        }

        @Test
        void reportThreeSignatures() {
            VerificationReport report = new VerificationReport(List.of(
                    new SignatureInfo(4, "KEY1", "RSA", null, VerificationResult.PASS),
                    new SignatureInfo(4, "KEY2", "EDDSA", null, VerificationResult.PASS),
                    new SignatureInfo(6, "FP1", SqRunner.DEFAULT_PQC_ALGORITHM, null,
                            VerificationResult.PASS)));

            assertEquals(VerificationOutcome.ALL_PASS, report.outcome());
            assertTrue(report.isPass());
            String formatted = report.format();
            assertTrue(formatted.contains("[1]"));
            assertTrue(formatted.contains("[2]"));
            assertTrue(formatted.contains("[3]"));
            assertTrue(formatted.contains("3 signatures valid"));
        }

        @Test
        void reportSkippedNotStrictPass() {
            VerificationReport report = new VerificationReport(List.of(
                    new SignatureInfo(4, "KEY1", "RSA", null, VerificationResult.PASS),
                    new SignatureInfo(6, "FP1", SqRunner.DEFAULT_PQC_ALGORITHM, null,
                            VerificationResult.SKIPPED)));

            assertEquals(VerificationOutcome.PASS_WITH_SKIPS, report.outcome());
            assertFalse(report.isPass());
            assertTrue(report.isLenientPass());
        }

        @Test
        void reportVersionLabels() {
            assertEquals("GPG v4", VerificationReport.versionLabel(4, "RSA"));
            assertEquals("GPG v3", VerificationReport.versionLabel(3, "DSA"));
            assertEquals("PQC v6", VerificationReport.versionLabel(6, SqRunner.DEFAULT_PQC_ALGORITHM));
            assertEquals("SQ v6", VerificationReport.versionLabel(6, "Ed25519"));
            assertEquals("SQ v6", VerificationReport.versionLabel(6, null));
            assertEquals("unknown", VerificationReport.versionLabel(-1, null));
            assertEquals("unknown", VerificationReport.versionLabel(0, null));
        }

        @Test
        void reportDefensiveCopy() {
            var mutableList = new java.util.ArrayList<>(List.of(
                    new SignatureInfo(4, "KEY1", "RSA", null, VerificationResult.PASS)));
            VerificationReport report = new VerificationReport(mutableList);
            mutableList.clear();
            assertEquals(1, report.signatures().size());
        }

        @Test
        void reportPassWithSkipsFormatShowsPass() {
            VerificationReport report = new VerificationReport(List.of(
                    new SignatureInfo(4, "KEY1", "RSA", null, VerificationResult.PASS),
                    new SignatureInfo(6, "FP1", SqRunner.DEFAULT_PQC_ALGORITHM, null,
                            VerificationResult.SKIPPED)));

            String formatted = report.format();
            assertTrue(formatted.contains("Overall: PASS (1/2 verified)"));
        }

        @Test
        void reportAllFail() {
            VerificationReport report = new VerificationReport(List.of(
                    new SignatureInfo(4, "KEY1", "RSA", null, VerificationResult.FAIL),
                    new SignatureInfo(6, "FP1", SqRunner.DEFAULT_PQC_ALGORITHM, null,
                            VerificationResult.FAIL)));

            assertEquals(VerificationOutcome.NONE_PASSED, report.outcome());
            assertFalse(report.isPass());
            assertFalse(report.isLenientPass());
        }

        @Test
        void reportAllSkipped() {
            VerificationReport report = new VerificationReport(List.of(
                    new SignatureInfo(4, "KEY1", "RSA", null, VerificationResult.SKIPPED),
                    new SignatureInfo(6, "FP1", SqRunner.DEFAULT_PQC_ALGORITHM, null,
                            VerificationResult.SKIPPED)));

            assertEquals(VerificationOutcome.NONE_PASSED, report.outcome());
            assertFalse(report.isLenientPass());
        }

        @Test
        void reportNoKeyPartial() {
            VerificationReport report = new VerificationReport(List.of(
                    new SignatureInfo(4, "KEY1", "RSA", null, VerificationResult.PASS),
                    new SignatureInfo(6, "FP1", SqRunner.DEFAULT_PQC_ALGORITHM, null,
                            VerificationResult.NO_KEY)));

            assertEquals(VerificationOutcome.PASS_WITH_SKIPS, report.outcome());
            assertTrue(report.isLenientPass());
            assertFalse(report.isPass());
        }
    }

    @Nested
    class VerifyTests {

        @TempDir
        Path tempDir;

        private static final byte[] V4_PACKET = {
                (byte) 0x88, 0x5E, 0x04, 0x00, 0x11, 0x08, 0x00, 0x06,
                0x05, 0x02, 0x61, 0x74, 0x00, 0x09, 0x00, 0x0A, 0x09, 0x10
        };

        private static final byte[] V6_PACKET = {
                (byte) 0x88, 0x10, 0x06, 0x00, 0x11, 0x08, 0x00, 0x06,
                0x05, 0x02, 0x61, 0x74, 0x00, 0x09, 0x00, 0x0A, 0x09, 0x10
        };

        private Path writeArtifact() throws IOException {
            Path artifact = tempDir.resolve("test.jar");
            Files.writeString(artifact, "test content");
            return artifact;
        }

        private Path writeCombinedAsc(String v4Block, String v6Block) throws IOException {
            String combined = AscCombiner.combine(v4Block, v6Block);
            Path sig = tempDir.resolve("test.jar.asc");
            Files.writeString(sig, combined);
            return sig;
        }

        private Path writeSingleBlockAsc(String block) throws IOException {
            Path sig = tempDir.resolve("test.jar.asc");
            Files.writeString(sig, block);
            return sig;
        }

        private Path writeMultiBlockAsc(String... blocks) throws IOException {
            StringBuilder sb = new StringBuilder();
            for (String block : blocks) {
                if (!sb.isEmpty()) {
                    sb.append("\n");
                }
                sb.append(block.stripTrailing());
            }
            sb.append("\n");
            Path sig = tempDir.resolve("test.jar.asc");
            Files.writeString(sig, sb.toString());
            return sig;
        }

        private GpgRunner mockGpg(VerificationResult result, String keyId) {
            return new GpgRunner() {
                @Override
                public VerifyResult verify(Path artifactFile, Path signatureFile) {
                    return new VerifyResult(result, keyId, "RSA", "Test User <test@test.com>");
                }
            };
        }

        private SqRunner mockSqWithCert(boolean verifyResult, Path certFile) {
            return new SqRunner(tempDir) {
                @Override
                public CertInfo inspectCert(String fingerprint) {
                    return new CertInfo(SqRunner.DEFAULT_PQC_ALGORITHM, "PQC User", certFile);
                }

                @Override
                public Path findCertFile(String fingerprint) {
                    return certFile;
                }

                @Override
                public boolean verifyCertFile(Path artifactFile, Path signatureFile, Path cert) {
                    return verifyResult;
                }
            };
        }

        private SqRunner mockSqNoCert() {
            return new SqRunner(tempDir) {
                @Override
                public CertInfo inspectCert(String fingerprint) {
                    return null;
                }
            };
        }

        @Test
        void verifyBothPass() throws Exception {
            Path artifact = writeArtifact();
            Path certFile = tempDir.resolve("cert.pem");
            Files.writeString(certFile, "fake");
            Path sig = writeCombinedAsc(AscCombiner.armor(V4_PACKET), AscCombiner.armor(V6_PACKET));

            HybridVerifier verifier = new HybridVerifier(
                    mockGpg(VerificationResult.PASS, "KEY123"),
                    mockSqWithCert(true, certFile));

            VerificationReport report = verifier.verify(artifact, sig);

            assertEquals(2, report.signatures().size());
            assertEquals(VerificationResult.PASS, report.signatures().get(0).result());
            assertEquals("KEY123", report.signatures().get(0).keyId());
            assertEquals(4, report.signatures().get(0).version());
            assertEquals(6, report.signatures().get(1).version());
        }

        @Test
        void verifyClassicPassPqcNoFingerprint() throws Exception {
            Path artifact = writeArtifact();
            Path sig = writeCombinedAsc(AscCombiner.armor(V4_PACKET), AscCombiner.armor(V6_PACKET));

            HybridVerifier verifier = new HybridVerifier(
                    mockGpg(VerificationResult.PASS, "KEY123"),
                    mockSqNoCert());

            // V6_PACKET has no issuer fingerprint → SKIPPED
            VerificationReport report = verifier.verify(artifact, sig);

            assertEquals(VerificationOutcome.PASS_WITH_SKIPS, report.outcome());
            assertEquals(VerificationResult.PASS, report.signatures().get(0).result());
            assertEquals(VerificationResult.SKIPPED, report.signatures().get(1).result());
        }

        @Test
        void verifyClassicFails() throws Exception {
            Path artifact = writeArtifact();
            Path sig = writeSingleBlockAsc(AscCombiner.armor(V4_PACKET));

            HybridVerifier verifier = new HybridVerifier(
                    mockGpg(VerificationResult.FAIL, "KEY123"),
                    mockSqNoCert());

            VerificationReport report = verifier.verify(artifact, sig);

            assertFalse(report.isPass());
            assertEquals(VerificationResult.FAIL, report.signatures().get(0).result());
        }

        @Test
        void verifyOnlyClassic() throws Exception {
            Path artifact = writeArtifact();
            Path sig = writeSingleBlockAsc(AscCombiner.armor(V4_PACKET));

            HybridVerifier verifier = new HybridVerifier(
                    mockGpg(VerificationResult.PASS, "KEY123"),
                    mockSqNoCert());

            VerificationReport report = verifier.verify(artifact, sig);

            assertTrue(report.isPass());
            assertEquals(1, report.signatures().size());
            assertEquals(4, report.signatures().get(0).version());
        }

        @Test
        void verifySqNullPqcSkipped() throws Exception {
            Path artifact = writeArtifact();
            Path sig = writeCombinedAsc(AscCombiner.armor(V4_PACKET), AscCombiner.armor(V6_PACKET));

            HybridVerifier verifier = new HybridVerifier(
                    mockGpg(VerificationResult.PASS, "KEY123"),
                    null);

            VerificationReport report = verifier.verify(artifact, sig);

            assertEquals(VerificationOutcome.PASS_WITH_SKIPS, report.outcome());
            assertFalse(report.isPass());
            assertTrue(report.isLenientPass());
            assertEquals(VerificationResult.SKIPPED, report.signatures().get(1).result());
        }

        @Test
        void verifyPqcNoCertNoKey() throws Exception {
            Path artifact = writeArtifact();
            Path sig = writeCombinedAsc(AscCombiner.armor(V4_PACKET), AscCombiner.armor(V6_PACKET));

            HybridVerifier verifier = new HybridVerifier(
                    mockGpg(VerificationResult.PASS, "KEY123"),
                    mockSqNoCert());

            VerificationReport report = verifier.verify(artifact, sig);

            assertEquals(VerificationResult.PASS, report.signatures().get(0).result());
            // V6_PACKET has no issuer fingerprint subpacket, so SKIPPED
            assertEquals(VerificationResult.SKIPPED, report.signatures().get(1).result());
        }

        @Test
        void verifyNoClassicBlockOnlyPqc() throws Exception {
            Path artifact = writeArtifact();
            Path certFile = tempDir.resolve("cert.pem");
            Files.writeString(certFile, "fake");
            Path sig = writeSingleBlockAsc(AscCombiner.armor(V6_PACKET));

            GpgRunner gpg = new GpgRunner() {
                @Override
                public VerifyResult verify(Path artifactFile, Path signatureFile) {
                    fail("GPG verify should not be called when no classic block present");
                    return null;
                }
            };

            HybridVerifier verifier = new HybridVerifier(gpg, mockSqWithCert(true, certFile));
            VerificationReport report = verifier.verify(artifact, sig);

            assertEquals(1, report.signatures().size());
            assertTrue(report.signatures().get(0).version() > 4);
        }

        @Test
        void verifyUnreadableSignatureFileThrowsIOException() throws Exception {
            Path artifact = writeArtifact();
            Path nonexistent = tempDir.resolve("nonexistent.asc");

            HybridVerifier verifier = new HybridVerifier(
                    mockGpg(VerificationResult.PASS, "KEY123"),
                    mockSqNoCert());

            assertThrows(IOException.class,
                    () -> verifier.verify(artifact, nonexistent));
        }

        @Test
        void verifyThreeBlocks() throws Exception {
            Path artifact = writeArtifact();
            Path certFile = tempDir.resolve("cert.pem");
            Files.writeString(certFile, "fake");
            Path sig = writeMultiBlockAsc(
                    AscCombiner.armor(V4_PACKET),
                    AscCombiner.armor(V4_PACKET),
                    AscCombiner.armor(V6_PACKET));

            HybridVerifier verifier = new HybridVerifier(
                    mockGpg(VerificationResult.PASS, "KEY123"),
                    mockSqWithCert(true, certFile));

            VerificationReport report = verifier.verify(artifact, sig);

            assertEquals(3, report.signatures().size());
            assertEquals(4, report.signatures().get(0).version());
            assertEquals(4, report.signatures().get(1).version());
            assertTrue(report.signatures().get(2).version() > 4);
        }

        @Test
        void verifyCorruptBlockMarkedAsFail() throws Exception {
            Path artifact = writeArtifact();
            byte[] corruptPacket = { 0x00, 0x01 };
            Path sig = writeSingleBlockAsc(AscCombiner.armor(corruptPacket));

            AtomicBoolean gpgCalled = new AtomicBoolean(false);
            GpgRunner gpg = new GpgRunner() {
                @Override
                public VerifyResult verify(Path artifactFile, Path signatureFile) {
                    gpgCalled.set(true);
                    return new VerifyResult(VerificationResult.PASS, "KEY", "RSA", null);
                }
            };

            HybridVerifier verifier = new HybridVerifier(gpg, mockSqNoCert());
            VerificationReport report = verifier.verify(artifact, sig);

            assertEquals(1, report.signatures().size());
            assertEquals(VerificationResult.FAIL, report.signatures().get(0).result());
            assertFalse(gpgCalled.get());
        }

        @Test
        void verifyEmptySignatureFile() throws Exception {
            Path artifact = writeArtifact();
            Path sig = tempDir.resolve("empty.asc");
            Files.writeString(sig, "");

            HybridVerifier verifier = new HybridVerifier(
                    mockGpg(VerificationResult.PASS, "KEY123"),
                    mockSqNoCert());

            VerificationReport report = verifier.verify(artifact, sig);

            assertTrue(report.signatures().isEmpty());
            assertEquals(VerificationOutcome.NONE_PASSED, report.outcome());
        }

        @Test
        void verifyBlankSignatureFile() throws Exception {
            Path artifact = writeArtifact();
            Path sig = tempDir.resolve("blank.asc");
            Files.writeString(sig, "   \n  \n  ");

            HybridVerifier verifier = new HybridVerifier(
                    mockGpg(VerificationResult.PASS, "KEY123"),
                    mockSqNoCert());

            VerificationReport report = verifier.verify(artifact, sig);

            assertTrue(report.signatures().isEmpty());
        }

        @Test
        void verifyNullArtifactFileThrows() {
            HybridVerifier verifier = new HybridVerifier(mockGpg(VerificationResult.PASS, "KEY123"), null);
            assertThrows(IllegalArgumentException.class,
                    () -> verifier.verify(null, tempDir.resolve("sig.asc")));
        }

        @Test
        void verifyNullSignatureFileThrows() throws Exception {
            Path artifact = writeArtifact();
            HybridVerifier verifier = new HybridVerifier(mockGpg(VerificationResult.PASS, "KEY123"), null);
            assertThrows(IllegalArgumentException.class,
                    () -> verifier.verify(artifact, null));
        }

        @Test
        void constructorNullGpgThrows() {
            assertThrows(IllegalArgumentException.class, () -> new HybridVerifier(null, null));
        }
    }
}
