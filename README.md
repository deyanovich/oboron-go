# oboron

**String-in / string-out symmetric encryption protocol**

[![Go Reference](https://pkg.go.dev/badge/oboron.org/go.svg)](https://pkg.go.dev/oboron.org/go)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](#license)

oboron's `enc` takes a plaintext UTF-8 string and returns an
encrypted, encoded string (the *obtext*); `dec` reverses it.
Encryption and encoding are combined into one operation, so the output
is always a compact, URL-safe string — never raw bytes.

This is the Go implementation of **Oboron protocol v1.0**. It is
interoperable with the Rust and Python reference implementations: every
implementation produces byte-identical obtext for the same key, scheme,
and encoding under the deterministic schemes, and interoperably
decrypts the probabilistic schemes. The Go code passes the shared
[v1.0.0 test vectors](https://gitlab.com/oboron/oboron-test-vectors)
— positive and negative, core and obu.

- 🔒 **Authenticated encryption** — the four core schemes provide
  confidentiality and integrity.
- 🎯 **Deterministic or probabilistic** — pick per scheme; the
  deterministic schemes give hash-like, prefix-stable references.
- 📦 **Compact** — ~28 chars for a short ID.
- 🌐 **URL-safe** — Crockford base32, lowercase, no special chars by
  default.
- 🔁 **Cross-language** — identical output to the Rust and Python
  implementations.

## Repository structure

The implementation is layered, mirroring the Rust reference:

```
obcrypt/         # crypto core: bytes-in/bytes-out, authenticated schemes
oboron/          # string-in/string-out, authenticated core (imports obcrypt)
obu/             # string-in/string-out, unauthenticated/obfuscation tier
cmd/ob/          # ob CLI — authenticated core schemes
cmd/obu/         # obu CLI — unauthenticated layer (upcbc, zdcbc)
cmd/obcrypt/     # obcrypt CLI — bytes-in/bytes-out core (internal tooling)
cmd/keygen/      # keygen convenience binary
scripts/         # development utilities
```

[`obcrypt`](https://pkg.go.dev/oboron.org/go/obcrypt) is the
bytes-in / bytes-out cryptographic core (authenticated schemes, no
encoding); [`oboron`](https://pkg.go.dev/oboron.org/go) builds on it to
add obtext encoding and format strings; and
[`obu`](https://pkg.go.dev/oboron.org/go/obu) is the separate,
unauthenticated layer with its own secret and its own crypto. The
dependency runs one way: `obu` → `oboron` → `obcrypt`, and package
`oboron` never imports `obu`.

## Scheme overview

| Scheme    | Algorithm   | Auth. | Det. | Use case                          |
|-----------|-------------|:-----:|:----:|-----------------------------------|
| **dsiv**  | AES-SIV     | ✅    | ✅   | Default: deterministic, compact   |
| **psiv**  | AES-SIV     | ✅    | ❌   | Probabilistic, maximum privacy    |
| **dgcmsiv** | AES-GCM-SIV | ✅  | ✅   | Deterministic; faster on larger input |
| **pgcmsiv** | AES-GCM-SIV | ✅  | ❌   | Probabilistic alternative         |
| **upcbc** | AES-256-CBC | ❌    | ❌   | Unauthenticated (obu layer)       |
| **zdcbc** | AES-128-CBC | ❌    | ✅   | Obfuscation only (obu layer)      |

The four core schemes (`dsiv`, `psiv`, `dgcmsiv`, `pgcmsiv`) are
authenticated and keyed by a 512-bit master key. The obu schemes
(`upcbc`, `zdcbc`) are **not** authenticated encryption — `upcbc` is
confidentiality only and `zdcbc` is reversible obfuscation — and are
keyed by a separate 256-bit secret. Each scheme combines with any of
four encodings: `c32` (Crockford base32, the default), `b32` (RFC 4648
base32), `b64` (URL-safe base64), and `hex`. See the
[protocol specification](https://oboron.org) for the full definitions.

## Quick start

### Library

```bash
go get oboron.org/go
```

```go
import "oboron.org/go/oboron"

// Generate a 512-bit master key (128-char hex).
key := oboron.GenerateKey()

ob, _ := oboron.NewDsivC32(key)           // fixed-format codec
obtext, _ := ob.Enc("/warehouse/bin-42")  // encrypt + encode
original, _ := ob.Dec(obtext)             // decode + decrypt
```

Need a key without importing the library? Generate one with the
convenience binary:

```bash
go run oboron.org/go/cmd/keygen
```

### CLI

```bash
# Install the CLIs (ob, obu, obcrypt).
bash INSTALL-CLI.sh

# Generate a key and encrypt/decrypt a value.
export OBORON_KEY=$(ob keygen)
ob enc "hello world"
ob dec <obtext>

# Unauthenticated/obfuscation layer (obu), keyed by a separate secret.
export OBORON_SECRET=$(obu secretgen)
obu enc "hello world"
obu dec <obtext>
```

All implementations produce identical obtext for the same key and
plaintext under the deterministic schemes; the probabilistic schemes
(`psiv`, `pgcmsiv`, `upcbc`) draw a fresh random nonce/IV per
encryption, so their obtexts differ but remain mutually decryptable.

## Library API

The API comes in three shapes, mirroring the Rust and Python
implementations: fixed types (`DsivC32`, …) bake the format into the
type name; `Ob` carries one runtime-chosen format; `Omnib` takes a
format per operation.

```go
import (
	"oboron.org/go/oboron"
	"oboron.org/go/obu"
)

key := oboron.GenerateKey()               // 128-char hex master key

ob, _ := oboron.NewDsivC32(key)           // fixed type
obtext, _ := ob.Enc("data")
plain, _ := ob.Dec(obtext)

ob2, _ := oboron.New("dsiv.b64", key)     // one runtime format
omni, _ := oboron.NewOmnib(key)           // a format per operation
obtext, _ = omni.Enc("data", "dsiv.b64")
plain, _ = omni.Dec(obtext, "dsiv.b64")   // scheme is supplied, never detected

// Or the package-level one-shot helpers (data, format, key).
obtext, _ = oboron.Enc("data", "dgcmsiv.c32", key)
plain, _ = oboron.Dec(obtext, "dgcmsiv.c32", key)
```

The unauthenticated layer lives in the separate `obu` package, keyed
by a 256-bit secret:

```go
secret := obu.GenerateSecret()            // 64-char hex secret

z, _ := obu.NewZdcbcC32(secret)           // fixed type
obtext, _ := z.Enc("data")
plain, _ := z.Dec(obtext)

// obu.NewObu("upcbc.c32", secret) / obu.NewOmnibu(secret) mirror Ob/Omnib.
```

Constructors come in three forms for both layers, matching the spec's
key model: from a hex string (`NewDsivC32`), from raw bytes
(`NewDsivC32FromBytes`), and from the fixed public test key
(`NewDsivC32Keyless`, INSECURE — testing only).

For the cryptographic core without any encoding — raw bytes in, raw
bytes out — depend on `obcrypt` directly:

```go
import "oboron.org/go/obcrypt"

key, _ := obcrypt.KeyFromHex("your-128-char-hex-key")
payload, _ := obcrypt.Encrypt([]byte("data"), obcrypt.Dsiv, key)
plain, _ := obcrypt.Decrypt(payload, obcrypt.Dsiv, key) // scheme supplied
```

## CLI reference

The `ob` and `obu` binaries implement the Oboron CLI contract (the
`enc`, `dec`, and key-generation commands, plus `--help` and
`--version`); a shared test harness runs the same vectors against any
conforming implementation. They also add optional convenience commands
(`init`, `config`, `profile`, `key`/`secret`) that are outside the
conformance contract.

### `ob` — authenticated core schemes

```
ob enc [OPTIONS] [TEXT]     Encrypt+encode a plaintext string
ob dec [OPTIONS] [TEXT]     Decode+decrypt an obtext string
ob keygen                   Print a fresh random key (128-char hex)
```

Key flags: `--key`/`-k` (128 hex chars), `--keyless`/`-K` (fixed
public test key — INSECURE), or the `$OBORON_KEY` environment variable.

Scheme flags: `--dsiv`/`-s`, `--psiv`/`-S`, `--dgcmsiv`/`-g`,
`--pgcmsiv`/`-G`. Encoding flags: `--c32`/`-c`, `--b32`/`-b`,
`--b64`/`-B`, `--hex`/`-x`. Or set both at once with `--format`/`-f`
(e.g. `dsiv.b64`). `--raw`/`-0` disables line framing. The built-in
default format is `dsiv.c32`.

### `obu` — unauthenticated layer (upcbc, zdcbc)

```
obu enc [OPTIONS] [TEXT]    Encode a plaintext string
obu dec [OPTIONS] [TEXT]    Decode an obtext string
obu secretgen               Print a fresh random secret (64-char hex)
```

Secret flags: `--secret` (64 hex chars; no short alias, to avoid
confusion with `ob`'s `-s`), `--keyless`/`-K`, or `$OBORON_SECRET`.
Scheme flags: `--upcbc`/`-u`, `--zdcbc`/`-z`. The encoding flags,
`--format`, and `--raw` match `ob`; the default scheme is `upcbc`.

### `obcrypt` — crypto core (bytes-in/bytes-out)

`obcrypt` is an **internal, non-spec** tool: it operates on raw bytes
with no encoding and exists to drive the cross-implementation
conformance suite. `obcrypt encrypt -s dsiv -x` produces output
identical to `ob enc -f dsiv.hex` — the same framed bytes, just without
the obtext encoding wrapped around them.

## Key management

The canonical key encoding is **hexadecimal**: 128 lowercase hex
characters for the 512-bit master key, 64 for the 256-bit obu secret.
`ob keygen` / `obu secretgen` emit hex, and the key/secret are read
straight from `$OBORON_KEY` / `$OBORON_SECRET`. Hex is the only
accepted form — there is no base64 key form.

- The master key and the obu secret are **independent** key material;
  do not derive one from the other in production.
- `--keyless`/`-K` uses a hardcoded public key — **INSECURE, testing
  only**.
- Not suitable for password hashing (use bcrypt/argon2).

## Installation

### Library

```bash
go get oboron.org/go
```

### CLI tools

```bash
bash INSTALL-CLI.sh
```

Or install individually:

```bash
go install oboron.org/go/cmd/ob@latest
go install oboron.org/go/cmd/obu@latest
go install oboron.org/go/cmd/obcrypt@latest
```

## License

Licensed under either of

- Apache License, Version 2.0
  ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms
or conditions.

---

*For cross-language interoperability see [INTEROP.md](INTEROP.md).*
