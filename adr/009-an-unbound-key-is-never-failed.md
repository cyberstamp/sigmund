# ADR-009: An Unbound Key Is Never `FAILED`

## Status

Accepted. Amends [ADR-005](005-verification-result-model.md): its rule that self-signatures which
are present, use accepted algorithms and still do not bind the key are a broken or forged
certificate that stays `FAILED`.

## Context

ADR-005 keeps `FAILED` for signatures that must not be trusted — bytes that do not match, a key
revoked or expired when it signed — and makes a key a tool will not use `INDETERMINATE`. It made
one exception: a certificate whose self-signatures are present and acceptable yet do not bind the
key was read as broken or forged, and `FAILED`.

Two findings, both checked against GnuPG 2.4.9 and Sequoia 1.4.0:

- **The exception fires on valid certificates.** gson 2.11.0 on Maven Central is signed by a key
  whose only user ID is not valid UTF-8. Its certification verifies over the user ID's bytes, and
  GnuPG and Sequoia verify the signature. Bouncy Castle 1.86's certificate API drops a user ID it
  cannot decode, so the key looked unbound and BC reported `FAILED` — the attack signal, which no
  policy can tolerate — for a valid signature on a widely used library.
- **The other backends never applied it.** For a certification that really does not verify over
  its user ID, GnuPG and Sequoia discard the binding and report a key they will not use. Only BC
  reported `FAILED`, so whether such a certificate blocked a build depended on which backend
  answered.

## Decision

A key its certificate does not bind is `INDETERMINATE(KEY_UNAVAILABLE)` — whether no
self-signature binds it, a self-signature does not verify, or a backend cannot use one that does.
A binding rejected only for its algorithm stays `INDETERMINATE(UNSUPPORTED_ALGORITHM)`. `FAILED`
is left with exactly what ADR-005's table lists: bytes that do not match, and a key revoked or
expired when it signed.

## Alternatives

- **Keep `FAILED` for self-signatures that do not verify over their raw bytes**, fixing only the
  undecodable user ID. Rejected: GnuPG and Sequoia would still disagree with BC on a forged
  certificate, and the attack signal would gain nothing. A forged user-ID certification sits
  beside a document signature the key itself made, and a user ID is never a credential; a forged
  subkey binding proves no credential of the victim either way. A policy that tolerates
  `INDETERMINATE` already accepts a signature by any unknown key, which an attacker can produce
  without forging anything.
- **Have Sigmund check self-signatures itself before handing a certificate to `gpg` or `sq`**, so
  all three report `FAILED`. Rejected for the same reason, at the cost of re-implementing
  certificate validation outside the tools.

## Consequences

- The backends agree on forged and stripped certificates: all report `KEY_UNAVAILABLE`.
- They still disagree on a correctly certified user ID that is not UTF-8: GnuPG and Sequoia
  verify, BC reports `KEY_UNAVAILABLE`. Binding such a key from its raw certification in BC, or a
  Bouncy Castle fix, would close the gap; until then it is a documented limitation.
- A tampered certificate is no longer reported as an attack. Its signature still proves nothing,
  so it can never satisfy a rule.
