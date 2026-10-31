package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;

/**
 * Signs through {@link Sigmund} with several keys of one tool listed under
 * {@code tools.<name>.signing-fingerprint}, using the real tools: the signatures land in one
 * {@code .asc}, one block per key, and every block verifies with each tool that can read it.
 */
class MultiKeySigningTest {

    private static final String SQ_V6_SUITE = "cv25519";

    @TempDir
    Path dir;

    private Path artifact;

    @Test
    @DisabledIfSystemProperty(named = "sigmund.test.skip-gpg", matches = "true")
    @DisabledIfSystemProperty(named = "sigmund.test.skip-sq", matches = "true")
    void sqSignsWithAV4AndAV6KeyIntoOneAsc() throws Exception {
        SqRunner sq = new SqRunner(sqHome());
        String v4 = sq.generateKey("V4 <v4@example.com>", "cv25519", "rfc4880");
        String v6 = sq.generateKey("V6 <v6@example.com>", SQ_V6_SUITE, "rfc9580");

        List<OpenPgpClaim> claims = sign(sqConfig(v4, v6), null, "sq");

        assertThat(claims).extracting(OpenPgpClaim::packetVersion).containsExactlyInAnyOrder(4, 6);
        for (OpenPgpClaim claim : claims) {
            assertThat(sq.verify(artifact, claim).isVerified()).as("sq verifies v" + claim.packetVersion())
                    .isTrue();
        }
        BcKeyStore verifyStore = bcStore("verify");
        importIntoBc(verifyStore, sq.exportCert(v4));
        importIntoBc(verifyStore, sq.exportCert(v6));
        BcRunner bc = new BcRunner(verifyStore, null, null);
        for (OpenPgpClaim claim : claims) {
            assertThat(bc.verify(artifact, claim).isVerified()).as("bc verifies v" + claim.packetVersion())
                    .isTrue();
        }
        GpgRunner gpg = gpgRunner("verify-gpg");
        importIntoGpg("verify-gpg", sq.exportCert(v4));
        OpenPgpClaim v4Claim = claims.stream().filter(c -> c.packetVersion() == 4).findFirst().orElseThrow();
        assertThat(gpg.verify(artifact, v4Claim).isVerified()).as("gpg verifies the v4 block").isTrue();
    }

    @Test
    @DisabledIfSystemProperty(named = "sigmund.test.skip-sq", matches = "true")
    void sqUnderAClassicProfileSignsWithTheV4KeyOnly() throws Exception {
        SqRunner sq = new SqRunner(sqHome());
        String v4 = sq.generateKey("V4 <v4@example.com>", "cv25519", "rfc4880");
        String v6 = sq.generateKey("V6 <v6@example.com>", SQ_V6_SUITE, "rfc9580");

        List<OpenPgpClaim> claims = sign(sqConfig(v4, v6), "classic", "sq");

        assertThat(claims).extracting(OpenPgpClaim::packetVersion).containsExactly(4);
    }

    @Test
    @DisabledIfSystemProperty(named = "sigmund.test.skip-gpg", matches = "true")
    @DisabledIfSystemProperty(named = "sigmund.test.skip-sq", matches = "true")
    void bcSignsWithTwoV4KeysIntoOneAsc() throws Exception {
        BcKeyStore signStore = bcStore("sign");
        BcRunner bcSigner = new BcRunner(signStore, null, null);
        String fp1 = bcSigner.generateKey("One <one@example.com>", "ed25519", null);
        String fp2 = bcSigner.generateKey("Two <two@example.com>", "ed25519", null);

        List<OpenPgpClaim> claims = sign(bcConfig(fp1, fp2), null, "bc");

        assertThat(claims).extracting(OpenPgpClaim::packetVersion).containsExactly(4, 4);
        List<Credential> proven = new ArrayList<>();
        for (OpenPgpClaim claim : claims) {
            VerifyResult result = bcSigner.verify(artifact, claim);
            assertThat(result.isVerified()).as("bc verifies").isTrue();
            proven.addAll(bcSigner.extractCredentials(result));
        }
        assertThat(proven).contains(KeyCredential.openPgp(fp1), KeyCredential.openPgp(fp2));
        verifyWithSq(claims, bcSigner.exportCert(fp1), bcSigner.exportCert(fp2));
        verifyWithGpg(claims, bcSigner.exportCert(fp1), bcSigner.exportCert(fp2));
    }

    @Test
    @DisabledIfSystemProperty(named = "sigmund.test.skip-gpg", matches = "true")
    @DisabledIfSystemProperty(named = "sigmund.test.skip-sq", matches = "true")
    void gpgSignsWithTwoV4KeysIntoOneAsc() throws Exception {
        String fp1 = generateGpgKey("One <one@example.com>");
        String fp2 = generateGpgKey("Two <two@example.com>");

        List<OpenPgpClaim> claims = sign("""
                tools:
                  gpg:
                    home: %s
                    signing-fingerprint: [%s, %s]
                signing:
                  toolchain: [gpg]
                """.formatted(gpgHome("gpg"), fp1, fp2), null, "gpg");

        assertThat(claims).extracting(OpenPgpClaim::packetVersion).containsExactly(4, 4);
        assertThat(claims).extracting(OpenPgpClaim::issuerFingerprint).containsExactlyInAnyOrder(fp1, fp2);
        GpgRunner gpg = gpgRunner("gpg");
        for (OpenPgpClaim claim : claims) {
            assertThat(gpg.verify(artifact, claim).isVerified()).as("gpg verifies").isTrue();
        }
        String cert1 = exportFromGpg(fp1);
        String cert2 = exportFromGpg(fp2);
        BcKeyStore verifyStore = bcStore("verify");
        importIntoBc(verifyStore, cert1);
        importIntoBc(verifyStore, cert2);
        BcRunner bc = new BcRunner(verifyStore, null, null);
        for (OpenPgpClaim claim : claims) {
            assertThat(bc.verify(artifact, claim).isVerified()).as("bc verifies").isTrue();
        }
        verifyWithSq(claims, cert1, cert2);
    }

    @Test
    void aRequestedTypeWithNoKeyFailsBeforeSigning() throws Exception {
        String fp = new BcRunner(bcStore("sign"), null, null).generateKey("One <one@example.com>", "ed25519",
                null);
        writeArtifact();
        Path out = Files.createDirectories(dir.resolve("out"));
        SigmundConfig config = SigmundConfigParser.parse("<test>", new StringReader("""
                tools:
                  bc:
                    %s
                    signing-fingerprint: [%s]
                signing:
                  toolchain: [bc]
                  profiles:
                    hybrid: [pgp4, pgp6]
                """.formatted(bcHomes("sign"), fp)));

        try (Sigmund sigmund = signingSigmund(config, "bc")) {
            assertThatThrownBy(() -> sigmund.signer("hybrid").sign(artifact, out))
                    .isInstanceOf(SigmundException.class)
                    .hasMessageContaining("pgp6");
        }
        try (Stream<Path> written = Files.list(out)) {
            assertThat(written.filter(p -> p.toString().endsWith(".asc"))).isEmpty();
        }
    }

    private String sqConfig(String v4, String v6) {
        return """
                tools:
                  sq:
                    home: %s
                    signing-fingerprint: [%s, %s]
                signing:
                  toolchain: [sq]
                  profiles:
                    classic: [pgp4]
                """.formatted(sqHome(), v4, v6);
    }

    private String bcConfig(String fp1, String fp2) {
        return """
                tools:
                  bc:
                    %s
                    signing-fingerprint: [%s, %s]
                signing:
                  toolchain: [bc]
                """.formatted(bcHomes("sign"), fp1, fp2);
    }

    private String bcHomes(String name) {
        Path base = dir.resolve(name);
        return "gnupg-home: %s\n    cert-d-home: %s\n    bc-private-home: %s".formatted(
                base.resolve("gnupg"), base.resolve("cert-d"), base.resolve("bc-private"));
    }

    private List<OpenPgpClaim> sign(String yaml, String profile, String tool) throws IOException {
        writeArtifact();
        Path out = Files.createDirectories(dir.resolve("out"));
        SigmundConfig config = SigmundConfigParser.parse("<test>", new StringReader(yaml));
        try (Sigmund sigmund = signingSigmund(config, tool)) {
            Signer signer = profile == null ? sigmund.signer() : sigmund.signer(profile);
            signer.sign(artifact, out);
        }
        try (Stream<Path> written = Files.list(out)) {
            assertThat(written.toList()).containsExactly(out.resolve("lib-1.0.jar.asc"));
        }
        List<Claim> parsed = new OpenPgpSignatureFormat()
                .parse(Evidence.read(out.resolve("lib-1.0.jar.asc"), Evidence.SOURCE_SIDECAR));
        return parsed.stream().map(OpenPgpClaim.class::cast).toList();
    }

    private Sigmund signingSigmund(SigmundConfig config, String tool) {
        Map<String, String> settings = new HashMap<>(config.toolsConfig().get(tool).settings());
        return Sigmund.builder().config(config).addSigningTool(tool, settings).build();
    }

    private void writeArtifact() throws IOException {
        artifact = Files.writeString(dir.resolve("lib-1.0.jar"), "artifact");
    }

    private Path sqHome() {
        return dir.resolve("sq-home");
    }

    private BcKeyStore bcStore(String name) {
        Path base = dir.resolve(name);
        return new BcKeyStore(base.resolve("gnupg"), base.resolve("cert-d"), base.resolve("bc-private"));
    }

    private void importIntoBc(BcKeyStore store, String armoredCert) throws IOException {
        try (InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(armoredCert.getBytes()))) {
            store.storeCert(new PGPPublicKeyRing(in, new BcKeyFingerprintCalculator()));
        }
    }

    private void verifyWithSq(List<OpenPgpClaim> claims, String... certs) throws IOException {
        Path home = dir.resolve("verify-sq");
        for (int i = 0; i < certs.length; i++) {
            Path file = Files.writeString(dir.resolve("cert-" + i + ".asc"), certs[i]);
            CliTool.Result imported = CliTool.run(Map.of("SEQUOIA_HOME", home.toString()), "sq",
                    "--overwrite", "cert", "import", file.toString());
            assertThat(imported.exitCode()).as(imported.stderr()).isZero();
        }
        SqRunner sq = new SqRunner(home);
        for (OpenPgpClaim claim : claims) {
            assertThat(sq.verify(artifact, claim).isVerified()).as("sq verifies").isTrue();
        }
    }

    private void verifyWithGpg(List<OpenPgpClaim> claims, String... certs) throws IOException {
        GpgRunner gpg = gpgRunner("verify-gpg");
        for (String cert : certs) {
            importIntoGpg("verify-gpg", cert);
        }
        for (OpenPgpClaim claim : claims) {
            assertThat(gpg.verify(artifact, claim).isVerified()).as("gpg verifies").isTrue();
        }
    }

    private GpgRunner gpgRunner(String name) throws IOException {
        return new GpgRunner("gpg", null, gpgHome(name).toString());
    }

    private Path gpgHome(String name) throws IOException {
        return GpgTestKeys.home(dir.resolve(name + "-home"));
    }

    private void importIntoGpg(String name, String armoredCert) throws IOException {
        Path file = Files.createTempFile(dir, "cert", ".asc");
        Files.writeString(file, armoredCert);
        CliTool.Result imported = CliTool.run(Map.of("GNUPGHOME", gpgHome(name).toString()), "gpg",
                "--batch", "--import", file.toString());
        assertThat(imported.exitCode()).as(imported.stderr()).isZero();
    }

    private String exportFromGpg(String fingerprint) throws IOException {
        CliTool.Result exported = CliTool.run(Map.of("GNUPGHOME", gpgHome("gpg").toString()), "gpg",
                "--batch", "--armor", "--export", fingerprint);
        assertThat(exported.exitCode()).as(exported.stderr()).isZero();
        return exported.stdout();
    }

    private String generateGpgKey(String userId) throws IOException {
        return GpgTestKeys.generate(gpgHome("gpg"), userId, "ed25519");
    }

}
