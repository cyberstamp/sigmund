package dev.cyberstamp.sigmund.core;

/**
 * Armored OpenPGP blocks for tests whose tools are mocked, so only the block's shape matters.
 */
final class OpenPgpTestBlocks {

    /**
     * A v4 binary document signature packet with empty subpacket areas and no signature value:
     * it is a signature to {@link ClaimRouter}, and verifies nowhere.
     */
    static final String DOCUMENT_SIGNATURE = AscCombiner.armor(new byte[] {
            (byte) 0x88, 0x08, 0x04, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00 });

    private OpenPgpTestBlocks() {
    }
}
