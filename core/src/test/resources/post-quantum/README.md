# SLH-DSA fixtures

Signatures Bouncy Castle 1.87 made with SLH-DSA keys, for `BcPostQuantumTest`, which checks that
Bouncy Castle and `sq` both verify them and both fail them over altered bytes. Generating an
SLH-DSA key and signing with it takes seconds for the small ("s") parameter sets, so the
signatures are made once and kept here; ML-DSA keys, which are fast, are generated and signed
with at test time.

Each key is a v6 key from Bouncy Castle's `OpenPGPKeyGenerator` preset of the same parameter set,
with an ML-KEM encryption subkey; the signature was made by `BcRunner` over the 12 bytes
`post-quantum` (no newline).

| Files | Algorithm (RFC 9980 ID) | Preset | Primary key fingerprint |
|---|---|---|---|
| `slhdsa128s.cert.asc`, `slhdsa128s.sig.asc` | SLH-DSA-SHAKE-128s (32) | `slhDsaShake128sMlKem768X25519Key` | `E99B0310FA8BC3549DC84535CB23BE860D23BD95EAC110124D15BCC1FF08B419` |
| `slhdsa128f.cert.asc`, `slhdsa128f.sig.asc` | SLH-DSA-SHAKE-128f (33) | `slhDsaShake128fMlKem768X25519Key` | `1EEFFD9B2D65071833A4FE52A92047EC7B5B150F9857C71A8E840731C0CC0A4F` |
| `slhdsa256s.cert.asc`, `slhdsa256s.sig.asc` | SLH-DSA-SHAKE-256s (34) | `slhDsaShake256sMlKem1024X448Key` | `4BBA6ED0ECC5A1AE5C521094FEA0450B09185AD4B643EB0433AB09BCE9E7EF7E` |

The certificates are public; no secret key is kept.
