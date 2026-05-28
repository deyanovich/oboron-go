# oboron

**String-in / string-out symmetric encryption protocol**

[![Go Reference](https://pkg.go.dev/badge/oboron.org/go.svg)](https://pkg.go.dev/oboron.org/go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

oboron's `enc` takes a plaintext UTF-8 string and returns an
encrypted, encoded string (the *obtext*); `dec` reverses it.
Encryption and encoding are combined into one seamless operation, so
the output is always a compact, URL-safe string — never raw bytes.

This is the Go implementation. It is interoperable with the Rust
reference implementation: both produce byte-identical obtext for the
same key, scheme, and encoding, and both pass the shared
[test vectors](https://gitlab.com/oboron/oboron-test-vectors). The
`ob`, `obz`, and `obcrypt` binaries pass the Rust
`oboron-cli-conformance` suite (v0.2.0) end-to-end — 5,027 checks,
zero failures.

- 🔒 **Authenticated encryption** — `a`-tier schemes provide
  confidentiality and integrity.
- 🎯 **Deterministic or probabilistic** — pick per scheme; the
  deterministic schemes give hash-like, prefix-stable references.
- 📦 **Compact** — ~26 chars for a short ID.
- 🌐 **URL-safe** — Crockford base32, lowercase, no special chars by
  default.
- 🔁 **Cross-language** — identical output to the Rust and Python
  implementations.

## Repository structure

The implementation is layered, mirroring the Rust reference:
[`obcrypt`](https://pkg.go.dev/oboron.org/go/obcrypt) is the
bytes-in / bytes-out cryptographic core (the `a`- and `u`-tier
schemes, no encoding); [`oboron`](https://pkg.go.dev/oboron.org/go)
builds on it to add obtext encoding, format strings, and the `z`-tier
obfuscation schemes. The dependency runs one way: `oboron` imports
`obcrypt`, never the reverse.

```
obcrypt/         # crypto core: bytes-in/bytes-out (a-tier + u-tier)
oboron/          # encoding layer: string-in/string-out, all schemes
cmd/ob/          # ob CLI — secure schemes (a-tier + u-tier)
cmd/obz/         # obz CLI — obfuscation schemes (z-tier)
cmd/obcrypt/     # obcrypt CLI — crypto core (raw bytes, hex on the wire)
scripts/         # Development utilities
```

## Quick start

### Library

```bash
go get oboron.org/go
```

```go
import "oboron.org/go/oboron"

// Encode using the public (testing) key — INSECURE, testing only.
ob, _ := oboron.NewAasvC32Keyless()
encoded, _ := ob.Enc("/warehouse/shelf-A/bin-42")
original, _ := ob.Dec(encoded)
```

### CLI

```bash
# Install the CLIs (ob, obz, obcrypt)
bash INSTALL-CLI.sh

# Generate a key (128-char hex) and initialize a profile
ob keygen
ob init

# Encrypt+encode a value
ob enc "hello world"

# Decode+decrypt a value
ob dec <obtext>

# Z-tier (obfuscation only, no key needed in keyless mode)
obz enc --keyless "hello world"
obz dec --keyless <obtext>
```

## Scheme overview

| Scheme    | Algorithm   | Tier | Auth. | Det. | Use case                           |
|-----------|-------------|------|:-----:|:----:|------------------------------------|
| **aasv**  | AES-SIV     | a    | ✅    | ✅   | Default: deterministic, compact    |
| **apsv**  | AES-SIV     | a    | ✅    | ❌   | Probabilistic, maximum privacy     |
| **aags**  | AES-GCM-SIV | a    | ✅    | ✅   | Deterministic alternative          |
| **apgs**  | AES-GCM-SIV | a    | ✅    | ❌   | Probabilistic alternative          |
| **upbc**  | AES-CBC     | u    | ❌    | ❌   | Unauthenticated (integrity ext.)   |
| **zrbcx** | AES-CBC     | z    | ❌    | ✅   | Obfuscation only (default z-tier)  |
| **legacy**| AES-CBC     | z    | ❌    | ✅   | Legacy compatibility               |

`a`-tier and `u`-tier schemes use a 512-bit master key; `z`-tier
schemes use a 256-bit secret. See the
[protocol specification](https://oboron.org) for the full scheme and
format definitions.

## CLI reference

### `ob` — secure schemes (a-tier + u-tier)

```
ob enc [OPTIONS] [TEXT]     Encrypt+encode a plaintext string
ob dec [OPTIONS] [TEXT]     Decode+decrypt an obtext string
ob init [NAME]              Initialize configuration (default profile: "default")
ob config [show|set]        Manage configuration
ob profile <SUBCMD>         Manage key profiles (list/show/activate/create/delete/rename/set)
ob key                      Output the active encryption key
ob keygen                   Print a fresh random key (128-char hex) and exit
ob completion <SHELL>       Generate shell completion (bash/zsh/fish/powershell)
```

Key flags: `--key`/`-k` (128 hex chars, or legacy 86-char base64),
`--profile`/`-p`, `--keyless`/`-K`

Scheme flags: `--aasv`/`-s`, `--apsv`/`-S`, `--aags`/`-g`,
`--apgs`/`-G`, `--upbc`/`-u`

Encoding flags: `--c32`/`-c`, `--b32`/`-b`, `--b64`/`-B`, `--hex`/`-x`

Format flag: `--format`/`-f` (e.g. `aasv.b64`)

`ob key` output defaults to canonical hex; `--base64`/`-B` opts into
the deprecated base64 form.

Environment: `$OBORON_KEY` — 128-char hex master key (legacy 86-char
base64 also accepted).

### `obz` — z-tier obfuscation schemes

```
obz enc [OPTIONS] [TEXT]    Encode a plaintext string
obz dec [OPTIONS] [TEXT]    Decode an obtext string
obz init [NAME]             Initialize configuration
obz config [show|set]       Manage configuration
obz profile <SUBCMD>        Manage secret profiles
obz secret                  Output the active obfuscation secret
obz secretgen               Print a fresh random secret (64-char hex) and exit
obz completion <SHELL>      Generate shell completion
```

Secret flags: `--secret`/`-s` (64 hex chars, or legacy 43-char
base64), `--profile`/`-p`, `--keyless`/`-K`

Scheme flags: `--zrbcx`/`-r`, `--legacy`/`-l`

Environment: `$OBORON_SECRET` — 64-char hex secret (legacy 43-char
base64 also accepted).

Config stored in: `~/.oboron/` (ob) and `~/.oboron/ztier/` (obz).

### `obcrypt` — crypto core (bytes-in/bytes-out)

`obcrypt` operates on raw bytes with no encoding: it encrypts under
the `a`/`u`-tier schemes and emits the framed payload. Use `-x` for
hex output and `-X` for hex input; otherwise it reads/writes raw
bytes (pipe-friendly).

```
obcrypt encrypt [OPTIONS] [TEXT]   Encrypt plaintext bytes under a scheme
obcrypt decrypt [OPTIONS] [BYTES]  Decrypt (scheme auto-detected if omitted)
obcrypt keygen                     Print a fresh random key (128-char hex)
```

Flags: `--scheme`/`-s` (aasv|apsv|aags|apgs|upbc), `--key`/`-k`
(128 hex chars), `--hex`/`-x` (hex output), `--hex-in`/`-X` (hex
input), `--in`/`--out` (file I/O). Environment: `$OBCRYPT_KEY`.

`obcrypt encrypt -s aasv -x` produces output identical to
`ob enc -f aasv.hex` — the same framed bytes, just without the obtext
encoding wrapped around them.

## Library API

The API comes in three shapes, mirroring the Rust and Python
implementations: fixed types (`AasvC32`, …) bake the encoding into
the type name; `Ob` carries one runtime-chosen format; `Omnib`
takes a format per operation.

```go
import (
	"oboron.org/go/oboron"
	"oboron.org/go/oboron/ztier"
)

// Secure a/u-tier schemes — 512-bit master key (128-char hex).
key := oboron.GenerateKey()

ob, _ := oboron.NewAasvC32(key)          // fixed type
encoded, _ := ob.Enc("data")
decoded, _ := ob.Dec(encoded)

// Or oboron.New("aasv.b32", key) for one runtime-chosen format.
omni, _ := oboron.NewOmnib(key)          // a format per operation
encoded, _ = omni.Enc("data", "aasv.b32")
decoded, _ = omni.Autodec(encoded)       // autodetect scheme

// z-tier obfuscation schemes — 256-bit secret (64-char hex).
secret := oboron.GenerateSecret()
z, _ := ztier.NewZrbcxC32(secret)
encoded, _ = z.Enc("data")
decoded, _ = z.Dec(encoded)
```

The z-tier (zrbcx, legacy) is obfuscation, not encryption; it lives
in the separate `oboron/ztier` package. `New` / `NewOmnib` take a key
string, auto-detecting hex vs. the deprecated base64 form by length;
`NewObFromBytes` accepts raw 64-byte keys.

If you want the cryptographic core without any encoding — raw
bytes-in / bytes-out — depend on `obcrypt` directly:

```go
import "oboron.org/go/obcrypt"

key, _ := obcrypt.KeyFromHex("your-128-char-hex-key")
payload, _ := obcrypt.Encrypt([]byte("data"), obcrypt.Aasv, key)
plaintext, _ := obcrypt.Decrypt(payload, key) // scheme from the marker
```

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
go install oboron.org/go/cmd/obz@latest
go install oboron.org/go/cmd/obcrypt@latest
```

## Key management

The canonical key encoding is **hexadecimal**: 128 lowercase hex
characters for the 512-bit master key, 64 for the 256-bit z-tier
secret. `ob keygen` / `obz secretgen` emit hex, and profiles store
hex. Base64 keys are a deprecated legacy format, still accepted on
input and auto-detected by length.

**Key tiers:**

- **a-tier** (`aasv`, `apsv`, `aags`, `apgs`): authenticated
  encryption, requires a 512-bit master key.
- **u-tier** (`upbc`): unauthenticated encryption, requires a 512-bit
  master key.
- **z-tier** (`zrbcx`, `legacy`): obfuscation only, requires a
  256-bit secret.

**Notes:**

- Always use custom keys in production (`ob init` generates a secure
  random key).
- `--keyless`/`-K` uses a hardcoded public key — **INSECURE, testing
  only**.
- Not suitable for password hashing (use bcrypt/argon2).

## License

MIT — see [LICENSE](LICENSE).

---

*For cross-language interoperability see [INTEROP.md](INTEROP.md).*
