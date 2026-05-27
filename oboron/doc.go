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
// The a-tier (aasv, apsv, aags, apgs) and u-tier (upbc) schemes take a 512-bit
// MasterKey, which is a type alias for obcrypt.Key. The z-tier (zrbcx, legacy)
// schemes take a 256-bit Secret. Hex is the canonical text form for both.
//
// # Quick start
//
//	mk, _ := oboron.MasterKeyFromHex(keyHex)        // 128 hex chars
//	ob, _ := oboron.NewOmnibFromMasterKey(mk)
//	obtext, _ := ob.EncodeWithFormat("hello", "aasv.c32")
//	plain, _ := ob.DecodeWithFormat(obtext, "aasv.c32")
//
// For the raw cryptographic core without any encoding, depend on obcrypt
// directly instead.
package oboron
