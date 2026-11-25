package dev.cyberstamp.sigmund.core;

import java.time.Instant;

/**
 * A single OpenPGP signature block extracted from an armored signature file.
 * <p>
 * Holds the armored text (natural representation for OpenPGP) along with
 * metadata extracted from the signature packet. The metadata enables routing
 * to the correct tool without re-parsing: v1–v4 packets go to GPG,
 * v5+ packets go to Sequoia.
 *
 * @param armoredBlock the ASCII-armored signature block text
 * @param packetVersion the OpenPGP signature packet version (4, 6, etc.),
 *        or {@code -1} if detection failed
 * @param issuerFingerprint the issuer fingerprint as an uppercase hex string,
 *        or {@code null} if not found (v4 signatures may not include it)
 * @param algorithmId the IANA public-key algorithm ID,
 *        or {@code -1} if extraction failed
 * @see Algorithms#algorithmName(int)
 */
public record OpenPgpClaim(
        String armoredBlock,
        int packetVersion,
        String issuerFingerprint,
        int algorithmId,
        Instant creationTime) implements Claim {

    private static final int TAG_SIGNATURE = 2;
    private static final int TAG_COMPRESSED_DATA = 8;
    private static final int BINARY_DOCUMENT = 0x00;
    private static final int CANONICAL_TEXT_DOCUMENT = 0x01;

    /**
     * {@inheritDoc}
     *
     * <p>
     * For OpenPGP this is the signature creation subpacket.
     */
    @Override
    public Instant claimTime() {
        return creationTime;
    }

    /**
     * {@inheritDoc}
     *
     * <p>
     * Always {@link ClaimTimeSource#SIGNER}: the creation subpacket is covered by
     * the signature but chosen by the signer, and OpenPGP has no timestamp authority to
     * corroborate it.
     */
    @Override
    public ClaimTimeSource claimTimeSource() {
        return ClaimTimeSource.SIGNER;
    }

    /**
     * The signature type of the block (RFC 9580 §5.2.1), read from its packet.
     *
     * @return the type, or {@code -1} when the block is not a bare signature packet or the type
     *         cannot be read
     */
    public int signatureType() {
        return AscCombiner.inspectSignaturePacket(armoredBlock).signatureType();
    }

    /**
     * Whether the block holds a signature packet a tool can be asked to verify: a signature
     * whose version can be read, or compressed data, which may wrap one and which the tools
     * unwrap. A block that cannot be decoded into a packet, or whose first packet is anything
     * else — a public key pasted into the {@code .asc} among them — holds no signature, though
     * the file holding it was taken for one.
     *
     * @return {@code true} for a block holding a signature packet, or compressed data
     */
    public boolean holdsSignaturePacket() {
        OpenPgpSignaturePacketInfo info = AscCombiner.inspectSignaturePacket(armoredBlock);
        return info.packetTag() == TAG_COMPRESSED_DATA || info.packetTag() == TAG_SIGNATURE && info.version() > 0;
    }

    /**
     * The tag of the block's first packet (RFC 9580 §5.1).
     *
     * @return the tag, or {@code -1} when the block cannot be decoded into a packet
     */
    public int packetTag() {
        return AscCombiner.inspectSignaturePacket(armoredBlock).packetTag();
    }

    /**
     * Whether the block is a signature that is not made over a document: one whose type is
     * readable and is neither a binary (0x00) nor a canonical text (0x01) document signature.
     * Such a block — a certification, a standalone or timestamp signature — asserts nothing
     * about an artifact even when it was computed over its bytes, and no backend verifies it as
     * if it did.
     *
     * @return {@code true} for a readable type other than a document signature
     */
    public boolean isNonDocumentSignature() {
        int type = signatureType();
        return type >= 0 && type != BINARY_DOCUMENT && type != CANONICAL_TEXT_DOCUMENT;
    }
}
