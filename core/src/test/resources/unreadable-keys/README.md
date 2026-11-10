# Unreadable-key fixtures

Keys Bouncy Castle cannot read, next to keys it can, for `UnreadableKeysTest`.

Two Ed25519 v4 keys were generated with GnuPG 2.4:

- first: `E564A2E852A935965D3A6D2D6206BC81B2FE9460` (`One <one@example.org>`)
- second: `C0735664E0426D54790D4A486BC32915B9CBA487` (`Two <two@example.org>`)

`artifact.txt.asc` is the second key's detached signature over `artifact.txt`.

In the files below, a public-key algorithm octet was changed from 22 (EdDSA) to 30
(ML-DSA-65+Ed25519), which Bouncy Castle 1.86 does not know. A fingerprint covers that octet, so
an altered key is another key than the one it was made from.

- `keybox/pubring.kbx`: GnuPG's keybox with both keys; the first key's blob is altered, and its
  SHA-1 checksum recomputed so the keybox itself stays valid. The blob's index still lists the
  first key's fingerprint, as GnuPG wrote it.
- `keyring/pubring.gpg`: both keys exported in that order (`gpg --export`), the first altered.
- `unknown-algorithm-key.gpg`: the second key's certificate with its primary key altered — a
  certificate of some other key, which Bouncy Castle cannot read.
- `second-key-with-unknown-subkey.gpg`: the second key's certificate as exported, followed by a
  subkey packet holding the first key's material, altered. Bouncy Castle reads the certificate
  and drops the subkey it does not know.

A certificate whose own signatures use an algorithm Bouncy Castle does not know — where it fails
on an `sq` ML-DSA certificate ("unknown signature key algorithm: 30") — is tested with a real
one in `BcPostQuantumTest`.
