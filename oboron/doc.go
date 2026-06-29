// Package oboron is the string-in / string-out layer of the oboron protocol
// (https://oboron.org/).
//
// Enc takes a plaintext UTF-8 string and returns an encrypted, encoded string
// — the obtext; Dec reverses it. Encryption and encoding are combined into one
// operation, so the output is always a compact, URL-safe string, never raw
// bytes.
//
// oboron builds on the obcrypt package (oboron.org/go/obcrypt): obcrypt
// provides the authenticated byte-level crypto, and oboron adds
//
//   - the obtext encodings — Crockford base32 (the default), RFC 4648 base32,
//     base64url, and hex; and
//   - format strings of the form "scheme.encoding" (e.g. "dsiv.c32").
//
// The dependency runs one way: oboron imports obcrypt, never the reverse.
//
// # Schemes and keys
//
// This package is the authenticated API (dsiv, psiv, dgcmsiv, pgcmsiv): the
// secure schemes, keyed by a 512-bit MasterKey (a type alias for obcrypt.Key)
// supplied as a 128-character hex string. The unauthenticated / obfuscation
// schemes (upcbc, zdcbc) are NOT authenticated encryption and live in a
// separate package, obu, keyed by a 256-bit Secret. Hex is the canonical text
// form for both.
//
// The API has three shapes, mirroring the Rust and Python implementations:
//
//   - fixed types (DsivC32, DsivB64, …) — the encoding is baked into the type
//     name and never optional;
//   - Ob — one runtime-chosen format per instance;
//   - Omnib — a format chosen per operation.
//
// # Quick start
//
//	key := oboron.GenerateKey()              // 128-char hex master key
//
//	ob, _ := oboron.NewDsivC32(key)          // fixed type
//	obtext, _ := ob.Enc("hello, world")
//	plain, _ := ob.Dec(obtext)
//
//	ob2, _ := oboron.New("dsiv.c32", key)    // runtime format
//	omni, _ := oboron.NewOmnib(key)          // per-operation format
//	obtext, _ = omni.Enc("hello, world", "dsiv.c32")
//
// For the obu schemes:
//
//	secret := oboron.GenerateSecret()        // 64-char hex secret
//	z, _ := obu.NewZdcbcC32(secret)
//	obtext, _ = z.Enc("hello, world")
//
// For the raw cryptographic core without any encoding, depend on obcrypt
// directly instead.
package oboron
