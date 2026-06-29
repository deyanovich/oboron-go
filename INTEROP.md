# Cross-language interoperability

This document records the interoperability status between the Go
implementation (`oboron-go`) and the Rust / Python reference
implementations of the **Oboron protocol v1.0**.

## What interoperates

Both ecosystems are layered the same way: a bytes-in / bytes-out
crypto core (Go `obcrypt`, Rust `obcrypt`) implementing the
authenticated schemes, with a string-in / string-out encoding layer
(Go `oboron`, Rust `oboron`) on top, and a separate unauthenticated
layer (Go `obu`, Rust `obu`). The interop guarantees hold at the
obtext layer: the encoded string is byte-identical across
implementations for the deterministic schemes, and mutually
decryptable for the probabilistic ones.

| Scheme    | Interoperable | Notes                                     |
|-----------|:-------------:|-------------------------------------------|
| `dsiv`    | ✅ identical  | AES-SIV, full 64-byte key, zero AD        |
| `dgcmsiv` | ✅ identical  | AES-GCM-SIV, HKDF-derived key, zero nonce |
| `psiv`    | ✅ decryptable | AES-SIV, 16-byte nonce as the single AD  |
| `pgcmsiv` | ✅ decryptable | AES-GCM-SIV, 12-byte random nonce        |
| `upcbc`   | ✅ decryptable | AES-256-CBC, random IV, 0x01 padding     |
| `zdcbc`   | ✅ identical  | AES-128-CBC, constant IV, prefix XOR      |

"Identical" means the deterministic schemes produce byte-for-byte the
same obtext for the same key, format, and plaintext. "Decryptable"
means the probabilistic schemes draw a fresh nonce/IV per encryption,
so their obtexts differ, but any conforming implementation decrypts
another's output.

The obtext carries **no scheme marker**: it is exactly the encoding of
the scheme-output bytes defined in the protocol specification (§2.2),
and nothing more. The scheme is supplied by the caller, not embedded.

## What is shared

1. **Scheme-output layouts** — the exact byte layout of each scheme's
   output (nonce placement, tag placement) matches the specification.
2. **Key model** — the SIV family uses the full 64-byte master key
   directly; the GCM-SIV family derives a 32-byte key via
   `HKDF-Expand(master, info="gcmsiv")` with no Extract step.
3. **Encodings** — Crockford base32 (`c32`), RFC 4648 base32 (`b32`),
   URL-safe base64 (`b64`), and hex produce the same output for the
   same bytes, and all decode strictly (no case-folding, no padding,
   no non-canonical input).
4. **Format strings** — `"scheme.encoding"` (e.g. `"dsiv.c32"`) parses
   identically and case-sensitively.
5. **Fixed public test key/secret** — the keyless (`-K`) mode uses the
   same hardcoded values across implementations, so the published test
   vectors bind to a single key with no per-vector key field.

## Conformance

The Go implementation is validated against the canonical
[v1.0.0 test vectors](https://gitlab.com/oboron/oboron-test-vectors):

- **Core positive** (`test-vectors.jsonl`): 2656 vectors across the 4
  core schemes × 4 encodings — deterministic schemes reproduce the
  obtext exactly; probabilistic schemes decode the stored obtext and
  survive a fresh encode/decode round-trip.
- **Core negative** (`negative-test-vectors.jsonl`): 29 vectors,
  each rejected (non-canonical encodings, short scheme outputs,
  tampered ciphertext, empty plaintext).
- **obu positive / negative**
  (`obu-test-vectors.jsonl`, `obu-negative-test-vectors.jsonl`):
  1328 + 3 vectors for `upcbc` and `zdcbc`.

The committed Go test suite drives all four files (see
`oboron/golden_test.go`, `oboron/negative_test.go`,
`obu/golden_test.go`, `obu/negative_test.go`, and the CLI tests under
`cmd/ob`, `cmd/obu`, `cmd/obcrypt`), and the `ob` / `obu` binaries
reproduce every vector through the command-line contract.

## CLI compatibility

The Go `ob`, `obu`, and `obcrypt` binaries expose the same flags and
output as their Rust counterparts:

- `ob` / `obu` — string-in / string-out, validated against the obtext
  vectors (all schemes × encodings, positive and negative).
- `obcrypt` — bytes-in / bytes-out, validated against the `.hex`
  vectors: `obcrypt encrypt -s <scheme> -x` reproduces the framed
  payload as hex, and `obcrypt decrypt -s <scheme> -X` recovers the
  plaintext.

### Encoding output case

| Encoding | Go / Rust output |
|----------|------------------|
| `b32`    | UPPERCASE        |
| `c32`    | lowercase        |
| `b64`    | mixed (URL-safe) |
| `hex`    | lowercase        |
