package dev.cyberstamp.sigmund.core;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;
import org.bouncycastle.gpg.keybox.KeyBlob;
import org.bouncycastle.gpg.keybox.KeyInformation;
import org.bouncycastle.gpg.keybox.PublicKeyRingBlob;
import org.bouncycastle.gpg.keybox.bc.BcKeyBox;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

/**
 * Reads the files Bouncy Castle finds keys in, so that one unreadable key hides only itself.
 *
 * <p>
 * A certificate Bouncy Castle cannot read — one with an algorithm it does not implement, such as
 * a post-quantum key, or a damaged one — is recorded as an {@link UnreadableCertificate} rather
 * than dropped, and the keys around it are still read: a GnuPG keybox blob by blob, a legacy
 * keyring file key ring by key ring. Why it could not be read, and which keys it holds, are
 * decided from its packets, which can be told apart without understanding their algorithms.
 */
final class KeyRingFiles {

    private static final int TAG_SIGNATURE = 2;
    private static final int TAG_SECRET_KEY = 5;
    private static final int TAG_PUBLIC_KEY = 6;
    private static final int TAG_PUBLIC_SUBKEY = 14;

    /**
     * The public-key algorithms Bouncy Castle 1.87 implements (RFC 9580 §9.1, RFC 9980): RSA,
     * Elgamal, DSA, ECDH, ECDSA, the legacy EdDSA, X25519, X448, Ed25519, Ed448, and the
     * post-quantum ML-DSA and SLH-DSA signature and ML-KEM encryption algorithms. A certificate it cannot
     * read that uses another is {@link UnreadableCertificate.Cause#UNKNOWN_ALGORITHM}.
     */
    private static final Set<Integer> IMPLEMENTED_ALGORITHMS = Set.of(1, 2, 3, 16, 17, 18, 19, 20, 22, 25,
            26, 27, 28, 30, 31, 32, 33, 34, 35, 36);

    private KeyRingFiles() {
    }

    /**
     * Reads a file holding one certificate, as a cert-d store holds them.
     *
     * @param file the file
     * @param source the store the file belongs to
     * @param namedKeys the keys the file is named after, used when its packets cannot be told
     *        apart
     * @param unreadable where a file that cannot be read is recorded
     * @return the certificate, or {@code null} when it cannot be read
     */
    static PGPPublicKeyRing readCertificate(Path file, TrustRootRef source, Set<String> namedKeys,
            List<UnreadableCertificate> unreadable) {
        return findInCertificate(file, KeySearch.everyCertificate(ring -> true), source, namedKeys, unreadable);
    }

    /**
     * Reads a file holding one certificate, as a cert-d store holds them, when a search wants
     * it: one whose key packets a search does not take as a candidate is not parsed.
     *
     * @param file the file
     * @param search the certificate wanted
     * @param source the store the file belongs to
     * @param namedKeys the keys the file is named after, used when its packets cannot be told
     *        apart
     * @param unreadable where a file that cannot be read is recorded
     * @return the certificate, or {@code null} when it is not the one wanted or cannot be read
     */
    static PGPPublicKeyRing findInCertificate(Path file, KeySearch search, TrustRootRef source,
            Set<String> namedKeys, List<UnreadableCertificate> unreadable) {
        byte[] data;
        try (InputStream in = new BufferedInputStream(Files.newInputStream(file));
                InputStream decoded = PGPUtil.getDecoderStream(in)) {
            data = decoded.readAllBytes();
        } catch (IOException | RuntimeException e) {
            unreadable.add(new UnreadableCertificate(source, file, namedKeys,
                    UnreadableCertificate.Cause.DAMAGED, messageOf(e)));
            return null;
        }
        if (!search.mayBe(keyFingerprints(data))) {
            return null;
        }
        PGPPublicKeyRing ring;
        try {
            ring = parse(data);
        } catch (IOException | RuntimeException e) {
            unreadable.add(unreadable(data, source, file, namedKeys, messageOf(e)));
            return null;
        }
        return search.matches().test(ring) ? ring : null;
    }

    /**
     * Reads the certificates a keyserver served.
     *
     * <p>
     * A keyserver may serve several certificates for one key, and every one is read: which of
     * them is the certificate of the key asked for is decided from their signatures, not from
     * the order they were served in. A certificate that cannot be read is recorded and the next
     * one is still read; a body holding no certificate at all is recorded as a copy of the key
     * asked for that cannot be read.
     *
     * @param body what the keyserver returned, armored or binary
     * @param keyserver the keyserver URL
     * @param keyId the key ID or fingerprint the keyserver was asked for
     * @param unreadable where a copy that cannot be read is recorded, with the keys its packets
     *        hold, else as a copy of that key
     * @return the certificates read, in the order served; empty when none can be read
     */
    static List<PGPPublicKeyRing> readServed(byte[] body, String keyserver, String keyId,
            List<UnreadableCertificate> unreadable) {
        TrustRootRef source = TrustRootRef.keyserver(keyserver);
        byte[] data;
        try (InputStream decoded = PGPUtil.getDecoderStream(new ByteArrayInputStream(body))) {
            data = decoded.readAllBytes();
        } catch (IOException | RuntimeException e) {
            unreadable.add(new UnreadableCertificate(source, null, Set.of(keyId),
                    UnreadableCertificate.Cause.DAMAGED, messageOf(e)));
            return List.of();
        }
        KeyRingSplit split = splitKeyRings(data);
        List<PGPPublicKeyRing> rings = new ArrayList<>(split.rings.size());
        for (byte[] encoded : split.rings()) {
            PGPPublicKeyRing ring = readServedRing(encoded, source, keyId, unreadable);
            if (ring != null) {
                rings.add(ring);
            }
        }
        if (split.problem() != null || split.rings().isEmpty()) {
            unreadable.add(new UnreadableCertificate(source, null, Set.of(keyId), causeOf(data),
                    split.problem() != null ? split.problem() : "no certificate in what was served"));
        }
        return rings;
    }

    private static PGPPublicKeyRing readServedRing(byte[] encoded, TrustRootRef source, String keyId,
            List<UnreadableCertificate> unreadable) {
        try {
            return parse(encoded);
        } catch (IOException | RuntimeException e) {
            unreadable.add(unreadable(encoded, source, null, Set.of(keyId), messageOf(e)));
            return null;
        }
    }

    /**
     * What a search of a key ring file looks for.
     *
     * <p>
     * Parsing a certificate — its signatures above all — is what a search spends its time on,
     * so a certificate is first judged by the fingerprints of the keys it holds, read without
     * parsing it: the index a keybox blob carries, or the key packets of a ring. Only one
     * {@code candidate} accepts, or one whose keys cannot be told that way, is parsed, and it is
     * found when {@code matches} accepts the parsed certificate, so what the index or the
     * packets claim never decides the answer alone. A certificate that is not a candidate is not
     * read, nor recorded when it could not be.
     *
     * @param candidate whether a certificate holding keys with these fingerprints may be the one
     *        wanted
     * @param matches whether the parsed certificate is the one wanted
     */
    record KeySearch(Predicate<Set<String>> candidate, Predicate<PGPPublicKeyRing> matches) {

        /**
         * A search that parses every certificate, for what the key fingerprints cannot tell,
         * such as a user ID.
         *
         * @param matches whether the parsed certificate is the one wanted
         * @return the search
         */
        static KeySearch everyCertificate(Predicate<PGPPublicKeyRing> matches) {
            return new KeySearch(keys -> true, matches);
        }

        private boolean mayBe(Set<String> keys) {
            return keys == null || keys.isEmpty() || candidate.test(keys);
        }
    }

    /**
     * Finds the first key ring in a GnuPG keybox ({@code pubring.kbx}) that a search wants.
     *
     * <p>
     * Each blob is judged by the fingerprints its index lists, which keybox blobs carry outside
     * the key data, and read on its own; one that cannot be read is recorded with those
     * fingerprints.
     *
     * @param keyBox the keybox file
     * @param search the key ring wanted
     * @param source the store the keybox belongs to
     * @param unreadable where blobs, or a keybox, that cannot be read are recorded
     * @return the first matching key ring, or {@code null}
     */
    static PGPPublicKeyRing findInKeyBox(Path keyBox, KeySearch search, TrustRootRef source,
            List<UnreadableCertificate> unreadable) {
        try (InputStream in = new BufferedInputStream(Files.newInputStream(keyBox))) {
            for (KeyBlob blob : new BcKeyBox(in).getKeyBlobs()) {
                if (!(blob instanceof PublicKeyRingBlob ringBlob) || !search.mayBe(indexedKeys(blob))) {
                    continue;
                }
                PGPPublicKeyRing ring = readBlob(ringBlob, keyBox, source, unreadable);
                if (ring != null && search.matches().test(ring)) {
                    return ring;
                }
            }
        } catch (IOException | RuntimeException e) {
            unreadable.add(new UnreadableCertificate(source, keyBox, Set.of(),
                    UnreadableCertificate.Cause.DAMAGED, messageOf(e)));
        }
        return null;
    }

    private static PGPPublicKeyRing readBlob(PublicKeyRingBlob blob, Path keyBox, TrustRootRef source,
            List<UnreadableCertificate> unreadable) {
        try {
            return blob.getPGPPublicKeyRing();
        } catch (IOException | RuntimeException e) {
            unreadable.add(new UnreadableCertificate(source, keyBox, indexedKeys(blob),
                    causeOf(blob.getKeyBytes()), messageOf(e)));
            return null;
        }
    }

    private static Set<String> indexedKeys(KeyBlob blob) {
        Set<String> keys = new LinkedHashSet<>();
        for (KeyInformation key : blob.getKeyInformation()) {
            keys.add(hex(key.getFingerprint()));
        }
        return keys;
    }

    /**
     * Finds the first key ring in a keyring file — legacy {@code pubring.gpg}, a sequence of
     * key rings — that a search wants.
     *
     * <p>
     * The file is split into key rings at each key packet before any is parsed, and each ring
     * is judged by the fingerprints of its key packets, so a ring that cannot be read is
     * recorded and the next one is still read. A packet header that cannot be read ends the
     * split; what follows it is recorded as one unreadable copy.
     *
     * @param keyRingFile the keyring file
     * @param search the key ring wanted
     * @param source the store the file belongs to
     * @param unreadable where rings, or a file, that cannot be read are recorded
     * @return the first matching key ring, or {@code null}
     */
    static PGPPublicKeyRing findInKeyRingFile(Path keyRingFile, KeySearch search, TrustRootRef source,
            List<UnreadableCertificate> unreadable) {
        byte[] data;
        try (InputStream in = new BufferedInputStream(Files.newInputStream(keyRingFile));
                InputStream decoded = PGPUtil.getDecoderStream(in)) {
            data = decoded.readAllBytes();
        } catch (IOException e) {
            unreadable.add(new UnreadableCertificate(source, keyRingFile, Set.of(),
                    UnreadableCertificate.Cause.DAMAGED, messageOf(e)));
            return null;
        }
        KeyRingSplit split = splitKeyRings(data);
        for (byte[] encoded : split.rings()) {
            if (!search.mayBe(keyFingerprints(encoded))) {
                continue;
            }
            PGPPublicKeyRing ring = readRing(encoded, keyRingFile, source, unreadable);
            if (ring != null && search.matches().test(ring)) {
                return ring;
            }
        }
        if (split.problem() != null) {
            unreadable.add(new UnreadableCertificate(source, keyRingFile, Set.of(),
                    UnreadableCertificate.Cause.DAMAGED, split.problem()));
        }
        return null;
    }

    private static PGPPublicKeyRing readRing(byte[] encoded, Path keyRingFile, TrustRootRef source,
            List<UnreadableCertificate> unreadable) {
        try {
            return parse(encoded);
        } catch (IOException | RuntimeException e) {
            unreadable.add(unreadable(encoded, source, keyRingFile, Set.of(), messageOf(e)));
            return null;
        }
    }

    private static PGPPublicKeyRing parse(byte[] encoded) throws IOException {
        try (InputStream in = new ByteArrayInputStream(encoded)) {
            return new PGPPublicKeyRing(in, new BcKeyFingerprintCalculator());
        }
    }

    /**
     * Records a key ring that could not be parsed, with the keys its packets hold, else the keys
     * it is named after, and the cause its packets show.
     */
    private static UnreadableCertificate unreadable(byte[] encoded, TrustRootRef source, Path file,
            Set<String> namedKeys, String message) {
        Set<String> keys = keyFingerprints(encoded);
        return new UnreadableCertificate(source, file, keys != null ? keys : namedKeys,
                causeOf(encoded), message);
    }

    /**
     * Decides why encoded packets could not be read: an algorithm Bouncy Castle does not
     * implement in a key or signature packet, else damage.
     */
    static UnreadableCertificate.Cause causeOf(byte[] data) {
        int pos = 0;
        while (pos < data.length) {
            PacketHeader header = PacketHeader.at(data, pos);
            if (header.problem() != null) {
                break;
            }
            int algorithm = publicKeyAlgorithm(data, header);
            if (algorithm >= 0 && !IMPLEMENTED_ALGORITHMS.contains(algorithm)) {
                return UnreadableCertificate.Cause.UNKNOWN_ALGORITHM;
            }
            pos = header.end();
        }
        return UnreadableCertificate.Cause.DAMAGED;
    }

    /**
     * The public-key algorithm octet of a key packet — after the version and creation time, in
     * v4 and v6 alike — or of a v4 or v6 signature packet — after the version and signature
     * type; {@code -1} for other packets and versions.
     */
    private static int publicKeyAlgorithm(byte[] data, PacketHeader header) {
        int body = header.bodyStart();
        int length = header.end() - body;
        int version = length > 0 ? data[body] : -1;
        boolean modern = version == 4 || version == 6;
        if ((header.tag() == TAG_PUBLIC_KEY || header.tag() == TAG_PUBLIC_SUBKEY
                || header.tag() == TAG_SECRET_KEY) && modern && length > 5) {
            return data[body + 5] & 0xff;
        }
        if (header.tag() == TAG_SIGNATURE && modern && length > 2) {
            return data[body + 2] & 0xff;
        }
        return -1;
    }

    /**
     * Computes the fingerprints of the keys in encoded packets from the packets alone, without
     * parsing the keys: a v4 key's fingerprint is the SHA-1 of {@code 0x99}, a two-octet length
     * and the key packet's body, and a v6 key's the SHA-256 of {@code 0x9B}, a four-octet
     * length and the body (RFC 9580 §5.5.4). A key with an algorithm Bouncy Castle does not
     * know still has a fingerprint.
     *
     * @param data the binary packets of a key ring
     * @return the uppercase fingerprints of its primary key and subkeys, or {@code null} when
     *         its packets cannot be told apart, it holds no key, or a key's version has no
     *         fingerprint defined
     */
    static Set<String> keyFingerprints(byte[] data) {
        Set<String> fingerprints = new LinkedHashSet<>();
        int pos = 0;
        while (pos < data.length) {
            PacketHeader header = PacketHeader.at(data, pos);
            if (header.problem() != null) {
                return null;
            }
            if (header.tag() == TAG_PUBLIC_KEY || header.tag() == TAG_PUBLIC_SUBKEY) {
                String fingerprint = fingerprintOf(Arrays.copyOfRange(data, header.bodyStart(), header.end()));
                if (fingerprint == null) {
                    return null;
                }
                fingerprints.add(fingerprint);
            }
            pos = header.end();
        }
        return fingerprints.isEmpty() ? null : fingerprints;
    }

    private static String fingerprintOf(byte[] keyBody) {
        if (keyBody.length == 0) {
            return null;
        }
        try {
            return switch (keyBody[0]) {
                case 4 -> hex(digest("SHA-1", new byte[] { (byte) 0x99,
                        (byte) (keyBody.length >> 8), (byte) keyBody.length }, keyBody));
                case 6 -> hex(digest("SHA-256", new byte[] { (byte) 0x9B,
                        (byte) (keyBody.length >> 24), (byte) (keyBody.length >> 16),
                        (byte) (keyBody.length >> 8), (byte) keyBody.length }, keyBody));
                default -> null;
            };
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("the JDK provides " + e.getMessage(), e);
        }
    }

    private static byte[] digest(String algorithm, byte[] prefix, byte[] body)
            throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        digest.update(prefix);
        return digest.digest(body);
    }

    /**
     * Formats bytes, such as a fingerprint, as uppercase hex: the form fingerprints take throughout
     * Sigmund, so two formatted fingerprints compare with {@code equals}.
     *
     * @param bytes the bytes to format
     * @return their uppercase hex digits, two per byte
     */
    static String hex(byte[] bytes) {
        return HexFormat.of().withUpperCase().formatHex(bytes);
    }

    /**
     * The key rings a keyring file holds, still encoded, and why splitting stopped early.
     *
     * @param rings each key ring's packets, from its key packet to the next; a ring the split
     *        stopped inside is not among them, so a ring cut short is never read as complete
     * @param problem why the rest of the file, from the ring the split stopped inside, could not
     *        be split, or {@code null} when all of it was
     */
    record KeyRingSplit(List<byte[]> rings, String problem) {
    }

    /**
     * Splits binary OpenPGP data into key rings by reading packet headers only (RFC 9580
     * §4.2), so a key ring whose content Bouncy Castle cannot parse does not hide the next.
     *
     * @param data the binary packets
     * @return the key rings, and why splitting stopped when it did not reach the end
     */
    static KeyRingSplit splitKeyRings(byte[] data) {
        List<byte[]> rings = new ArrayList<>();
        int ringStart = -1;
        int pos = 0;
        String problem = null;
        while (pos < data.length) {
            PacketHeader header = PacketHeader.at(data, pos);
            if (header.problem() != null) {
                problem = header.problem();
                break;
            }
            if (header.tag() == TAG_PUBLIC_KEY || header.tag() == TAG_SECRET_KEY) {
                if (ringStart >= 0) {
                    rings.add(Arrays.copyOfRange(data, ringStart, pos));
                }
                ringStart = pos;
            }
            pos = header.end();
        }
        if (ringStart >= 0 && problem == null) {
            rings.add(Arrays.copyOfRange(data, ringStart, pos));
        }
        return new KeyRingSplit(List.copyOf(rings), problem);
    }

    /**
     * One packet's tag, where its body starts and where it ends, read from its header in either
     * format.
     */
    private record PacketHeader(int tag, int bodyStart, int end, String problem) {

        static PacketHeader at(byte[] data, int pos) {
            int first = data[pos] & 0xff;
            if ((first & 0x80) == 0) {
                return malformed("not a packet header at offset " + pos);
            }
            return (first & 0x40) != 0 ? openPgpFormat(data, pos, first & 0x3f)
                    : legacyFormat(data, pos, (first >> 2) & 0x0f, first & 0x03);
        }

        private static PacketHeader openPgpFormat(byte[] data, int pos, int tag) {
            if (pos + 1 >= data.length) {
                return malformed("truncated packet header at offset " + pos);
            }
            int octet = data[pos + 1] & 0xff;
            if (octet < 192) {
                return body(data, pos, tag, 2, octet);
            }
            if (octet < 224) {
                if (pos + 2 >= data.length) {
                    return malformed("truncated packet header at offset " + pos);
                }
                return body(data, pos, tag, 3, ((octet - 192) << 8) + (data[pos + 2] & 0xff) + 192);
            }
            if (octet == 255) {
                return body(data, pos, tag, 6, fourOctets(data, pos + 2));
            }
            return malformed("partial body length, not used in key rings, at offset " + pos);
        }

        private static PacketHeader legacyFormat(byte[] data, int pos, int tag, int lengthType) {
            return switch (lengthType) {
                case 0 -> pos + 1 < data.length ? body(data, pos, tag, 2, data[pos + 1] & 0xff)
                        : malformed("truncated packet header at offset " + pos);
                case 1 -> pos + 2 < data.length
                        ? body(data, pos, tag, 3, ((data[pos + 1] & 0xff) << 8) | (data[pos + 2] & 0xff))
                        : malformed("truncated packet header at offset " + pos);
                case 2 -> body(data, pos, tag, 5, fourOctets(data, pos + 1));
                default -> malformed("indeterminate packet length at offset " + pos);
            };
        }

        private static long fourOctets(byte[] data, int from) {
            if (from + 3 >= data.length) {
                return -1;
            }
            return ((long) (data[from] & 0xff) << 24) | ((data[from + 1] & 0xff) << 16)
                    | ((data[from + 2] & 0xff) << 8) | (data[from + 3] & 0xff);
        }

        private static PacketHeader body(byte[] data, int pos, int tag, int headerLength,
                long bodyLength) {
            long end = (long) pos + headerLength + bodyLength;
            if (bodyLength < 0 || end > data.length) {
                return malformed("truncated packet at offset " + pos);
            }
            return new PacketHeader(tag, pos + headerLength, (int) end, null);
        }

        private static PacketHeader malformed(String problem) {
            return new PacketHeader(-1, -1, -1, problem);
        }
    }

    /**
     * Names what Bouncy Castle reported reading a copy, for a detail.
     */
    private static String messageOf(Exception e) {
        return e.getMessage() != null && !e.getMessage().isBlank()
                ? e.getMessage()
                : e.getClass().getSimpleName();
    }
}
