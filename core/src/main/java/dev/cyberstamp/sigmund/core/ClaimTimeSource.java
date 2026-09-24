package dev.cyberstamp.sigmund.core;

/**
 * Who asserted a claim's time, and therefore how much that time is worth.
 *
 * <p>
 * Validity is judged at the moment a claim was made, not at the moment it is verified: a
 * signature made while its key was valid stays valid after the key expires. That makes the
 * source of the time load-bearing, because an attacker holding an expired but unrevoked key
 * could otherwise date a signature back into the key's validity period.
 *
 * @see Claim#claimTime()
 */
public enum ClaimTimeSource {

    /**
     * A transparency log recorded and countersigned the time, so it is independent of the
     * signer. Sigstore bundles carry a signed entry timestamp of this kind, which is what
     * lets a short-lived Fulcio certificate be verified long after it expired.
     */
    TRANSPARENCY_LOG,

    /**
     * The signer stated the time and nothing else attests it. An OpenPGP signature creation
     * subpacket is of this kind: it is covered by the signature, so a third party cannot
     * alter it, but the signer chose it. Without a timestamp authority there is no
     * independent check, and the result records that.
     */
    SIGNER
}
