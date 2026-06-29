# Security model — oboron-go

This is the Go implementation of the Oboron protocol. It is a thin
string/encoding layer (`oboron`) over an authenticated-encryption core
(`obcrypt`), plus a separate, deliberately weak unauthenticated layer
(`obu`). This document covers the guarantees and limits specific to
this implementation; the cryptographic constructions and threat model
are defined by the
[Oboron protocol specification](https://oboron.org).

## What the authenticated core provides

Packages `oboron` and `obcrypt` encrypt a UTF-8 **string** (or raw
bytes, for `obcrypt`) under one of four authenticated schemes and
encode the result to compact obtext. All four — `dsiv`, `psiv`,
`dgcmsiv`, `pgcmsiv` — provide confidentiality and integrity:

| Property                  | All four core schemes                |
|---------------------------|--------------------------------------|
| Confidentiality           | yes                                  |
| Authenticity (integrity)  | yes (AEAD tag)                       |
| Tampering detection       | yes (`ErrDecryptionFailed`)          |
| Wrong-key detection       | yes (`ErrDecryptionFailed`)          |
| Wrong-scheme detection    | yes (`ErrDecryptionFailed`)          |
| Determinism               | `dsiv`/`dgcmsiv` det.; `psiv`/`pgcmsiv` prob. |

The obtext carries no scheme marker — the scheme is part of the
caller's context. Decoding under the wrong scheme fails the
authentication check, like a wrong key. `Dec` **always validates
UTF-8** and never returns an unchecked string: non-UTF-8 plaintext is
rejected, and `Enc` likewise rejects non-UTF-8 input (spec §4.1). The
empty string is outside the plaintext domain and is rejected by both
`Enc` and `Dec`.

## What the obu layer does *not* provide

The `obu` package (`upcbc`, `zdcbc`) is **not authenticated
encryption** and shares no code with the secure core:

- `upcbc` provides confidentiality only (AES-256-CBC). Its ciphertext
  is malleable; it **must not** be used where integrity matters.
- `zdcbc` is reversible **obfuscation** (AES-128-CBC, constant IV),
  deterministic and not cryptographically secure.

The obu secret **must** be independent key material — never derived
from, or shared with, the core master key. The published test vectors
reuse core-key bytes as the obu secret for convenience only; do not
imitate that in production. For anything security-critical, use the
authenticated core.

## Randomness

The probabilistic schemes (`psiv`, `pgcmsiv`, `upcbc`) draw a fresh
nonce/IV from `crypto/rand` (the system CSPRNG) on every encryption; if
randomness is unavailable, `Enc` fails rather than reusing or
synthesizing a nonce (spec §5). Key and secret generation draw from
the same source.

## Usage limits

The deterministic schemes (`dsiv`, `dgcmsiv`) encrypt under a fixed
all-zero nonce. This is sound **only** because AES-SIV and AES-GCM-SIV
are nonce-misuse-resistant
([RFC 5297](https://www.rfc-editor.org/rfc/rfc5297),
[RFC 8452](https://www.rfc-editor.org/rfc/rfc8452)): the only
confidentiality cost is the deterministic-equality leak those schemes
expose by design — equal plaintexts produce equal obtext.

The binding limit is therefore **cumulative data volume per key**, not
nonce reuse: security degrades only as the total data encrypted under
one master key approaches the AES-GCM-SIV birthday bound — far out of
practical reach for the short-string workloads oboron targets. The
library is stateless and tracks no usage, so honoring that bound is a
deployment responsibility: rotate the master key well before it under
high-volume use.

## Key handling

The canonical — and only — key encoding is **128 lowercase hex
characters** (64 for the obu secret). There is no base64 form, and
uppercase hex is rejected, so a key has exactly one textual
representation.

The 64-byte master key is held by `obcrypt.Key`, which zeroizes its
bytes when `Zeroize` is called and via a GC finalizer registered by
the constructors. The obu `Secret` does not auto-zeroize, matching the
obu layer's deliberately weaker design.

## Audit status

This implementation has **not** been independently security-audited.
The cryptographic constructions follow RFC 5297, RFC 8452, and
RFC 5869, and the wire format is pinned by the cross-implementation
test vectors. Evaluate accordingly for high-assurance use.

## Reporting vulnerabilities

If you find a security issue, please email the maintainer at
**dev@deyanovich.org** with a subject line beginning
`[oboron security]`. Include reproduction details, affected versions,
and (if possible) a proposed fix or mitigation. For non-security bugs,
file an issue on the
[GitLab repository](https://gitlab.com/oboron/oboron-go/-/issues).

Coordinated disclosure: I'll acknowledge receipt within 7 days and
work with you on a disclosure timeline appropriate to the severity.
