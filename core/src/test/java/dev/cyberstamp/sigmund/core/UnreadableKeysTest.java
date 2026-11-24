package dev.cyberstamp.sigmund.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A key Bouncy Castle cannot read is never taken for an absent one, and does not hide the keys
 * stored next to it. The fixtures, and how they were made, are described in
 * {@code src/test/resources/unreadable-keys/README.md}.
 */
class UnreadableKeysTest {

    private static final String FIRST = "E564A2E852A935965D3A6D2D6206BC81B2FE9460";
    private static final String SECOND = "C0735664E0426D54790D4A486BC32915B9CBA487";

    @TempDir
    Path dir;

    @Nested
    class OneUnreadableKeyHidesOnlyItself {

        @Test
        void inAGnupgKeybox() throws IOException {
            Path gnupgHome = fixtureDir("keybox", "pubring.kbx");

            VerifyResult result = verifyWith(new BcKeyStore(gnupgHome, dir.resolve("cert-d"),
                    dir.resolve("bc-private")));

            assertThat(result.isVerified()).isTrue();
        }

        @Test
        void inALegacyGnupgKeyring() throws IOException {
            Path gnupgHome = fixtureDir("keyring", "pubring.gpg");

            VerifyResult result = verifyWith(new BcKeyStore(gnupgHome, dir.resolve("cert-d"),
                    dir.resolve("bc-private")));

            assertThat(result.isVerified()).isTrue();
        }

        @Test
        void andIsReportedAsTheCopyOfItsOwnKey() throws IOException {
            BcKeyStore store = new BcKeyStore(fixtureDir("keybox", "pubring.kbx"),
                    dir.resolve("cert-d"), dir.resolve("bc-private"));

            BcKeyStore.PublicKeySearch search = store.searchPublicKey(FIRST);

            assertThat(search.found()).isNull();
            assertThat(search.unreadable().cause()).isEqualTo(UnreadableCertificate.Cause.UNKNOWN_ALGORITHM);
        }

        @Test
        void andIsNotMentionedForAKeyItsIndexSaysItDoesNotHold() throws IOException {
            BcKeyStore store = new BcKeyStore(fixtureDir("keybox", "pubring.kbx"),
                    dir.resolve("cert-d"), dir.resolve("bc-private"));

            assertThat(store.searchPublicKey("AAAABBBBCCCCDDDDEEEEFFFF0000111122223333").unreadable())
                    .isNull();
        }
    }

    @Test
    void aKeyOfAnAlgorithmBouncyCastleImplementsThatItCannotParseIsDamaged() throws IOException {
        byte[] certificate = readFixture("unknown-algorithm-key.gpg");
        certificate[7] = 31;

        assertThat(KeyRingFiles.causeOf(certificate)).isEqualTo(UnreadableCertificate.Cause.DAMAGED);
    }

    @Test
    void aCertificateWithASubkeyBouncyCastleDoesNotKnowStillVerifies() throws IOException {
        writeCertD(SECOND, readFixture("second-key-with-unknown-subkey.gpg"));

        assertThat(verifyWith(certDOnly()).isVerified()).isTrue();
    }

    /**
     * The only copy of the signing key uses an algorithm Bouncy Castle does not know: the claim
     * is one Bouncy Castle cannot check, and the copy is named, rather than the key reported as one
     * to go and find.
     */
    @Test
    void aSigningKeyOfAnAlgorithmBouncyCastleDoesNotKnowIsUnsupportedAndSaysSo() throws IOException {
        byte[] certificate = readFixture("unknown-algorithm-key.gpg");
        String altered = KeyRingFiles.keyFingerprints(certificate).iterator().next();
        writeCertD(altered, certificate);

        VerifyResult result = verifyWith(certDOnly(), altered);

        assertThat(result.isIndeterminate(IndeterminateReason.UNSUPPORTED_ALGORITHM)).isTrue();
        assertThat(result.detail())
                .startsWith("Bouncy Castle cannot read the copy from " + dir.resolve("cert-d") + ": ");
    }

    @Test
    void aDamagedCopyOfTheSigningKeyIsUnavailableAndSaysSo() throws IOException {
        writeCertD(SECOND, "not a certificate".getBytes(StandardCharsets.US_ASCII));

        VerifyResult result = verifyWith(certDOnly());

        assertThat(result.isIndeterminate(IndeterminateReason.KEY_UNAVAILABLE)).isTrue();
        assertThat(result.detail())
                .startsWith("the copy from " + dir.resolve("cert-d") + " cannot be read: ");
    }

    /**
     * A damaged file whose keys cannot be told apart concerns no key in particular: it is
     * warned about once, and a missing key is reported as missing.
     */
    @Test
    void aFileWhoseKeysCannotBeToldApartIsWarnedAboutOnceRatherThanReported() throws IOException {
        Path damaged = dir.resolve("cert-d").resolve("zz").resolve("damaged");
        Files.createDirectories(damaged.getParent());
        Files.writeString(damaged, "not a certificate");
        BcKeyStore store = certDOnly();
        List<String> warnings = new ArrayList<>();
        Logger logger = Logger.getLogger(BcKeyStore.class.getName());
        Handler handler = new Handler() {
            @Override
            public void publish(LogRecord logged) {
                warnings.add(logged.getMessage());
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };
        logger.addHandler(handler);
        try {
            VerifyResult first = verifyWith(store);
            verifyWith(store);

            assertThat(first.detail()).isEqualTo("no local key store has it, and key fetching is off");
            assertThat(warnings).singleElement().asString()
                    .startsWith(damaged + " in openpgp-cert-d " + dir.resolve("cert-d") + " cannot be read (");
        } finally {
            logger.removeHandler(handler);
        }
    }

    /**
     * Named after the signing key, but holding another: the keys it holds are read from its
     * packets, so it is not taken for a copy of the signing key.
     */
    @Test
    void anUnreadableCertificateOfAnotherKeyIsNotMentioned() throws IOException {
        writeCertD(SECOND, readFixture("unknown-algorithm-key.gpg"));

        VerifyResult result = verifyWith(certDOnly());

        assertThat(result.isIndeterminate(IndeterminateReason.KEY_UNAVAILABLE)).isTrue();
        assertThat(result.detail()).isEqualTo("no local key store has it, and key fetching is off");
    }

    @Test
    void theKeysOfAKeyRingAreReadFromItsPackets() throws IOException {
        KeyRingFiles.KeyRingSplit split = KeyRingFiles.splitKeyRings(readFixture("keyring/pubring.gpg"));

        assertThat(KeyRingFiles.keyFingerprints(split.rings().get(1))).containsExactly(SECOND);
    }

    /**
     * A certificate is judged by its keys' fingerprints before it is parsed, so the first,
     * unreadable, certificate of each fixture is never parsed in a search for the second.
     */
    @Nested
    class ASearchByFingerprint {

        private final KeyRingFiles.KeySearch forSecond = new KeyRingFiles.KeySearch(
                keys -> keys.contains(SECOND), ring -> BcKeyStore.matchesFingerprint(ring, SECOND));

        @Test
        void parsesOnlyTheKeyboxBlobWhoseIndexListsTheKey() throws IOException {
            List<UnreadableCertificate> unreadable = new ArrayList<>();

            PGPPublicKeyRing found = KeyRingFiles.findInKeyBox(fixtureDir("keybox", "pubring.kbx").resolve("pubring.kbx"),
                    forSecond, TrustRootRef.unknown(), unreadable);

            assertThat(found).isNotNull();
            assertThat(unreadable).isEmpty();
        }

        @Test
        void parsesOnlyTheKeyRingWhosePacketsHoldTheKey() throws IOException {
            List<UnreadableCertificate> unreadable = new ArrayList<>();

            PGPPublicKeyRing found = KeyRingFiles.findInKeyRingFile(
                    fixtureDir("keyring", "pubring.gpg").resolve("pubring.gpg"), forSecond, TrustRootRef.unknown(),
                    unreadable);

            assertThat(found).isNotNull();
            assertThat(unreadable).isEmpty();
        }

        /** What a store's index or a ring's packets claim never decides alone. */
        @Test
        void findsNothingTheParsedCertificateDoesNotConfirm() throws IOException {
            KeyRingFiles.KeySearch indexOnly = new KeyRingFiles.KeySearch(keys -> keys.contains(SECOND), ring -> false);

            assertThat(KeyRingFiles.findInKeyBox(fixtureDir("keybox", "pubring.kbx").resolve("pubring.kbx"), indexOnly,
                    TrustRootRef.unknown(), new ArrayList<>())).isNull();
        }

        @Test
        void aCertDFileWhosePacketsHoldAnotherKeyIsNotParsed() throws IOException {
            Path file = dir.resolve("unknown-algorithm-key.gpg");
            Files.write(file, readFixture("unknown-algorithm-key.gpg"));
            List<UnreadableCertificate> unreadable = new ArrayList<>();

            assertThat(KeyRingFiles.findInCertificate(file, forSecond, TrustRootRef.unknown(), Set.of(), unreadable))
                    .isNull();
            assertThat(unreadable).isEmpty();
        }
    }

    @Nested
    class SplittingAKeyringFile {

        @Test
        void yieldsEachKeyRing() throws IOException {
            KeyRingFiles.KeyRingSplit split = KeyRingFiles.splitKeyRings(readFixture("keyring/pubring.gpg"));

            assertThat(split.rings()).hasSize(2);
            assertThat(split.problem()).isNull();
        }

        @Test
        void keepsTheRingsBeforeATruncatedPacket() throws IOException {
            byte[] keyring = readFixture("keyring/pubring.gpg");
            byte[] truncated = Arrays.copyOf(keyring, keyring.length - 10);

            KeyRingFiles.KeyRingSplit split = KeyRingFiles.splitKeyRings(truncated);

            assertThat(split.rings()).hasSize(1);
            assertThat(split.problem()).startsWith("truncated packet at offset ");
        }
    }

    private VerifyResult verifyWith(BcKeyStore store) throws IOException {
        return verifyWith(store, null);
    }

    /** Verifies the fixture signature as a claim by {@code issuer}, or by its own issuer when {@code null}. */
    private VerifyResult verifyWith(BcKeyStore store, String issuer) throws IOException {
        Path artifact = dir.resolve("artifact.txt");
        Files.write(artifact, readFixture("artifact.txt"));
        String armored = new String(readFixture("artifact.txt.asc"), StandardCharsets.US_ASCII);
        OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armored);
        OpenPgpClaim claim = new OpenPgpClaim(armored, info.version(),
                issuer != null ? issuer : info.issuerFingerprint(), info.algorithmId(), null);
        try (BcRunner runner = new BcRunner(store, null, null)) {
            return runner.verify(artifact, claim);
        }
    }

    private BcKeyStore certDOnly() {
        return new BcKeyStore(null, dir.resolve("cert-d"), dir.resolve("bc-private"));
    }

    private void writeCertD(String fingerprint, byte[] content) throws IOException {
        String lower = fingerprint.toLowerCase();
        Path file = dir.resolve("cert-d").resolve(lower.substring(0, 2)).resolve(lower.substring(2));
        Files.createDirectories(file.getParent());
        Files.write(file, content);
    }

    private Path fixtureDir(String name, String file) throws IOException {
        Path home = dir.resolve(name);
        Files.createDirectories(home);
        Files.write(home.resolve(file), readFixture(name + "/" + file));
        return home;
    }

    private static byte[] readFixture(String name) throws IOException {
        try (InputStream in = UnreadableKeysTest.class.getResourceAsStream("/unreadable-keys/" + name)) {
            assertThat(in).as(name).isNotNull();
            return in.readAllBytes();
        }
    }
}
