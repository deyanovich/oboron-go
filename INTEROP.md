# Cross-Language Interoperability: oboron-go <-> oboron-rs

This document describes the interoperability status between the Go
(`oboron-go`) and Rust (`oboron-rs` / `obcrypt-rs`) implementations of
the oboron protocol.

Both ecosystems are layered the same way: a bytes-in / bytes-out
crypto core (Go `obcrypt`, Rust `obcrypt`) implementing the `a`- and
`u`-tier schemes, with an encoding layer (Go `oboron`, Rust `oboron`)
on top that adds obtext encoding and the `z`-tier schemes. The
interop guarantees below hold at both layers: the framed payload
bytes match across `obcrypt` implementations, and the encoded obtext
matches across `oboron` implementations.

## Summary

| Scheme | Interoperable? | Notes |
|--------|:--------------:|-------|
| legacy | ✅ Full | Identical output with same key (verified: 165 vectors) |
| zrbcx  | ✅ Full | Both use 0x01 padding byte |
| aags   | ✅ Full | Both use AES-256-GCM-SIV with key[32:64] |
| aasv   | ✅ Full | Both use AES-256-SIV (CMAC-SIV) with full 64-byte key |
| apgs   | ✅ Full | Both use AES-256-GCM-SIV with key[32:64], nonce prepended |
| apsv   | ✅ Full | Both use AES-256-SIV with full 64-byte key, 16-byte nonce prepended |
| upbc   | ✅ Full | Both use AES-256-CBC with key[8:40], IV prepended, 0x01 padding |

The `a`/`u`-tier rows (aags, aasv, apgs, apsv, upbc) are the schemes
provided by the `obcrypt` core; legacy and zrbcx are `z`-tier and
live in the `oboron` layer.

## CLI Compatibility

The Go `ob`, `obz`, and `obcrypt` CLI binaries are validated against
the `oboron-cli-conformance` cross-implementation test suite. Each
supports the same flags as its Rust counterpart and produces matching
output. Run against the Go binaries, the suite passes every sub-suite
with zero failures — ob smoke + vectors, obz smoke + ztier + legacy,
and obcrypt vectors, 5,027 checks in total as of this writing.

- `ob` / `obz` — string-in / string-out, validated against the
  obtext test vectors (all schemes × encodings).
- `obcrypt` — bytes-in / bytes-out, validated against the `.hex`
  vectors: `obcrypt encrypt -s <scheme> -x` reproduces the `.hex`
  obtext exactly (it is the same framed payload, hex-encoded), and
  `obcrypt decrypt -s <scheme> -X` recovers the plaintext.

### Keyless mode (`-K`)

Both Go and Rust use the same hardcoded 64-byte key
(`HARDCODED_KEY_BYTES`):

- Go: `obcrypt.HardcodedKey()` / `oboron.HardcodedMasterKey()` /
  `oboron.HardcodedSecret()`
- Rust: `HARDCODED_KEY_BYTES` / `HARDCODED_SECRET_BYTES`
- Hex (canonical): `381284633d02ea5f35df8596b5cc4218310060468e8b465455a415174ea6e966a9f48eec4ba446ddfc8b78587895356f45a75a1ab7419454dd9f7aa8a95dbdd5`
- Base64url (deprecated): `OBKEYz0C6l8134WWtcxCGDEAYEaOi0ZUVaQVF06m6Wap9I7sS6RG3fyLeFh4lTVvRadaGrdBlFTdn3qoqV291Q`

`ob`/`obz` expose this via the `-K`/`--keyless` flag; `obcrypt` has
no keyless flag — pass the hex key explicitly with `-k`.

### Encoding output case

| Encoding | Go output | Rust output |
|----------|-----------|-------------|
| b32      | UPPERCASE | UPPERCASE   |
| c32      | lowercase | lowercase   |
| b64      | mixed     | mixed       |
| hex      | lowercase | lowercase   |

### Known deltas

#### Legacy scheme: trailing `=` stripped on decode

The `legacy` scheme has a known quirk: `obz dec` strips trailing `=`
characters from the decoded plaintext. This is consistent across both
Go and Rust implementations. Avoid round-trip tests with the `legacy`
scheme on inputs ending with `=` — the decoded output will not match
the original plaintext.

#### Legacy scheme: autodetection limitations

The `legacy` scheme has no 2-byte scheme marker. Autodetection
(`Autodec`) may produce false positives when the encoded ciphertext
coincidentally matches another scheme's marker pattern. This is an
inherent limitation of the heuristic approach and is key-dependent.

## Scheme Details

### legacy (AES-128-CBC, deterministic)

**Status: Fully interoperable** ✅

Both implementations use the same algorithm:

- AES-128 with `key[:16]` and IV from `key[16:32]`
- PKCS7-style padding
- Reversed base32 output

The Rust `legacy-test-vectors.jsonl` embeds a secret in the metadata
line, which is extracted and passed via `-s` to both Go and Rust
CLIs. This confirms bitwise-identical output for 165 test vectors
across all plaintext lengths.

### zrbcx (AES-128-CBC + XOR, deterministic)

**Status: Fully interoperable** ✅

Both implementations use the same encryption algorithm, XOR prefix
restructuring, and padding byte:

| Aspect | Go | Rust |
|--------|-----|------|
| Algorithm | AES-128-CBC | AES-128-CBC |
| Key | `key[:16]` | `key[:16]` |
| IV | `key[16:32]` | `key[16:32]` |
| Padding byte | `0x01` | `0x01` |

### aags (AES-256-GCM-SIV, deterministic)

**Status: Fully interoperable** ✅

| Aspect | Go | Rust |
|--------|-----|------|
| Algorithm | AES-256-GCM-SIV (`agl/gcmsiv`) | AES-256-GCM-SIV (`aes-gcm-siv`) |
| Key bytes | `key[32:64]` | `key[32:64]` |
| Nonce | 12 bytes, all zeros | 12 bytes, all zeros |

### aasv (AES-256-SIV, deterministic)

**Status: Fully interoperable** ✅

| Aspect | Go | Rust |
|--------|-----|------|
| Algorithm | AES-256-SIV (CMAC-SIV, `miscreant.go`) | AES-256-SIV (`aes-siv` crate) |
| Key bytes | All 64 bytes | All 64 bytes |
| Associated data | None (zero AD items) | None (zero AD items) |

### apgs (AES-256-GCM-SIV, probabilistic)

**Status: Fully interoperable** ✅

| Aspect | Go | Rust |
|--------|-----|------|
| Algorithm | AES-256-GCM-SIV | AES-256-GCM-SIV |
| Key bytes | `key[32:64]` | `key[32:64]` |
| Nonce position | Prepended before ciphertext | Prepended before ciphertext |
| Layout | `[nonce_12][ciphertext+tag][marker]` | `[nonce_12][ciphertext+tag]` |

### apsv (AES-256-SIV, probabilistic)

**Status: Fully interoperable** ✅

| Aspect | Go | Rust |
|--------|-----|------|
| Algorithm | AES-256-SIV (CMAC-SIV, `miscreant.go`) | AES-256-SIV (`aes-siv` crate) |
| Key bytes | All 64 bytes | All 64 bytes |
| Nonce | 16 bytes random, used as single AAD item | 16 bytes random, used as single AAD item |
| Layout | `[nonce_16][ciphertext+tag][marker]` | `[nonce_16][ciphertext+tag]` |

### upbc (AES-256-CBC, probabilistic)

**Status: Fully interoperable** ✅

| Aspect | Go | Rust |
|--------|-----|------|
| Algorithm | AES-256-CBC | AES-256-CBC |
| Key bytes | `key[8:40]` | `key[8:40]` |
| IV position | Prepended before ciphertext | Prepended before ciphertext |
| Padding byte | `0x01` | `0x01` |
| Layout | `[iv_16][ciphertext][marker]` | `[iv_16][ciphertext]` |

## What IS Shared

Both implementations share:

1. **Framed payload format** — the `obcrypt` layer's
   `[ciphertext][marker ^ body[0]]` framing is byte-identical
2. **Format string syntax** — `"scheme.encoding"` (e.g., `"aags.c32"`)
   is parsed identically
3. **Encoding backends** — base32, Crockford base32, base64url, hex
   produce the same output for the same bytes
4. **Scheme markers** — the 2-byte XOR markers are identical across
   implementations
5. **Scheme/encoding enums** — all 7 schemes × 4 encodings are
   supported in both
6. **Key material** — all key offsets and sizes are aligned between
   implementations

## Test Coverage

The `obcrypt` core (`obcrypt/obcrypt_test.go`) validates, at the
bytes-in / bytes-out layer: per-scheme round-trips, determinism (and
non-determinism), marker-based scheme detection, tamper rejection for
the `a`-tier schemes, and key hex/zeroize behavior.

The golden test suite (`oboron/golden_test.go`) validates the
encoding layer:

- **165 legacy vectors**: full encode + decode + autodec interop with
  Rust vectors
- **3,320 a-tier vectors**: full decode interop with Rust vectors (all
  schemes)
- **664 ztier vectors**: full decode interop with Rust vectors
- **28 format combinations**: Go self-consistency roundtrip (7 schemes
  × 4 encodings)
- **25 format strings**: all Rust vector format strings parse
  correctly in Go

The CLI integration tests (`cmd/ob/cli_test.go`,
`cmd/obz/cli_test.go`, `cmd/obcrypt/cli_test.go`) validate:

- **ob smoke tests**: keyless enc, explicit key enc, roundtrips (all 5
  schemes, all encodings), short aliases, error handling
- **obz smoke tests**: keyless enc, explicit secret enc, roundtrips
  (zrbcx with b32/b64/hex), error handling
- **ob vector tests**: 3,320 a-tier vectors — deterministic schemes
  get exact enc+dec match, probabilistic schemes get dec+roundtrip
- **obz ztier vector tests**: 664 ztier vectors — deterministic zrbcx
  gets exact enc+dec match
- **obz legacy vector tests**: 165 legacy vectors — exact enc match,
  dec with known trailing `=` strip
- **obcrypt vector tests**: 830 `.hex` vectors (5 a/u schemes) —
  deterministic schemes get exact `encrypt -x` match + decrypt,
  probabilistic schemes get canned decrypt + fresh roundtrip
