# Changelog

All notable changes to oboron-go are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-06-29

First stable release, conforming to **Oboron protocol v1.0** and the
companion CLI and obu (unauthenticated layer) specifications. Verified
against the canonical
[v1.0.0 test vectors](https://gitlab.com/oboron/oboron-test-vectors)
(core and obu, positive and negative).

### Security

- **Probabilistic nonces now come from `crypto/rand`.** Earlier
  versions drew `psiv`/`pgcmsiv` nonces from a wall-clock-seeded
  `math/rand` source; they are now drawn from the system CSPRNG, and
  `Enc` fails if randomness is unavailable rather than synthesizing a
  nonce (spec §5).

### Added

- Negative-vector conformance: the test suite now drives the canonical
  core and obu negative vectors, asserting each is rejected.
- `oboron.Enc` / `Dec` / `EncKeyless` / `DecKeyless` package-level
  convenience functions, and `oboron.GenerateKeyBytes`.
- `obu.GenerateSecret` / `GenerateSecretBytes` in the obu package.
- `--raw`/`-0` framing flag on `ob`/`obu` enc and dec, for
  byte-exact, newline-preserving I/O.
- The `ob`/`obu` CLIs warn when the fixed public test key/secret is
  supplied via `--key`/`--secret`/env rather than `--keyless`.

### Changed

- Strict canonical decoders: `c32`, `b32`, and `hex` now reject
  non-canonical input (wrong case, Crockford `i`/`l`/`o`/`u` aliases,
  padding, impossible lengths, non-zero trailing bits) instead of
  normalizing it (spec §1.2).
- Strict, case-sensitive format/scheme/encoding parsing: uppercase
  identifiers, surrounding whitespace, the `ob:` prefix, and long-form
  encoding aliases are rejected (spec §1.1).
- Key/secret hex constructors reject uppercase (lowercase only, §3.3).
- CLI exit codes follow the spec: usage errors exit `2`, operation
  failures exit `1` (previously everything exited `1`).
- Every `dec` failure shares one uniform stderr message, so `dec` is
  not a distinguishing oracle (CLI.md §8).
- `--version` emits a bare semver token, e.g.
  `ob oboron-go 1.0.0 protocol=1.0 cli=1.0`; `-V` and a post-command
  `--version` are accepted.
- stdin framing strips exactly one trailing line ending (`\r\n` or
  `\n`) instead of all trailing newlines.
- The obu `--secret` flag no longer has a single-letter `-s` alias
  (OBU.md §6).

### Fixed

- `enc`/`dec` validate UTF-8 (spec §4.1): `Enc` rejects non-UTF-8
  input and `Dec` never returns an unchecked string.
- `zdcbc` enc rejects a plaintext whose final byte is the `0x01` pad
  byte, which previously round-tripped with silent truncation
  (OBU.md §2.1).
- `upcbc`/`zdcbc` dec reject input that strips to zero bytes
  (OBU.md §2.2).
- Conflicting or duplicated CLI flags are now usage errors: `--key`
  with `--keyless`, more than one scheme or encoding flag, `--format`
  combined with scheme/encoding flags, and more than one positional
  argument.
- An explicitly empty `$OBORON_KEY` / `$OBORON_SECRET` is treated as
  an invalid key/secret, not an absent one (CLI.md §6, OBU.md §6.1).
- CI test target and `INSTALL-CLI.sh` referenced a non-existent
  `cmd/obz`; they now build the real `cmd/obu` binary.

[1.0.0]: https://gitlab.com/oboron/oboron-go/-/tags/v1.0.0
