// Package oboron is the string-in / string-out layer of the oboron protocol
// (https://oboron.org/).
//
// Enc takes a plaintext UTF-8 string and returns an encrypted, encoded string
// — the obtext; Dec reverses it. Encryption and encoding are combined into one
// operation, so the output is always a compact, URL-safe string, never raw
// bytes.
//
// oboron builds on the obcrypt package (oboron.org/go/obcrypt): obcrypt
// provides the a-tier (authenticated) and u-tier (unauthenticated) byte-level
// crypto, and oboron adds
//
//   - the obtext encodings — Crockford base32 (the default), RFC 4648 base32,
//     base64url, and hex;
//   - format strings of the form "scheme.encoding" (e.g. "aasv.c32"); and
//   - the z-tier obfuscation schemes (zrbcx, legacy), which are not encryption
//     and have no obcrypt equivalent.
//
// The dependency runs one way: oboron imports obcrypt, never the reverse.
//
// # Tiers and keys
//
// This package is the a-tier (aasv, apsv, aags, apgs) and u-tier (upbc) API:
// the secure schemes, keyed by a 512-bit MasterKey (a type alias for
// obcrypt.Key) supplied as a 128-character hex string. The z-tier obfuscation
// schemes (zrbcx, legacy) are NOT encryption and live in a separate, isolated
// subpackage, oboron/ztier, keyed by a 256-bit Secret. Hex is the canonical
// text form for both.
//
// The API has three shapes, mirroring the Rust and Python implementations:
//
//   - fixed types (AasvC32, AasvB64, …) — the encoding is baked into the type
//     name and never optional;
//   - Ob — one runtime-chosen format per instance;
//   - Omnib — a format chosen per operation.
//
// # Quick start
//
//	key := oboron.GenerateKey()              // 128-char hex master key
//
//	ob, _ := oboron.NewAasvC32(key)          // fixed type
//	obtext, _ := ob.Enc("hello, world")
//	plain, _ := ob.Dec(obtext)
//
//	ob2, _ := oboron.New("aasv.c32", key)    // runtime format
//	omni, _ := oboron.NewOmnib(key)          // per-operation format
//	obtext, _ = omni.Enc("hello, world", "aasv.c32")
//
// For the z-tier:
//
//	secret := oboron.GenerateSecret()        // 64-char hex secret
//	z, _ := ztier.NewZrbcxC32(secret)
//	obtext, _ = z.Enc("hello, world")
//
// For the raw cryptographic core without any encoding, depend on obcrypt
// directly instead.
package oboron
