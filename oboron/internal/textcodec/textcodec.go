// Package textcodec holds the byte<->text encoding backends used by package
// oboron. It is deliberately dependency-free — in particular it does not import
// oboron — so the Crockford/base32/base64/hex logic can be reused without a
// package cycle. The public oboron.Encoding string values map directly onto the
// Encoding type defined here. (The sibling obu package keeps its own copy of
// the same logic, since it cannot import this internal package.)
package textcodec

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

// Encoding is a text-encoding tag. Its values are the canonical short codes
// that oboron.Encoding also uses ("b32", "c32", "b64", "hex").
type Encoding string

const (
	B32 Encoding = "b32"
	C32 Encoding = "c32"
	B64 Encoding = "b64"
	Hex Encoding = "hex"
)

// crockfordLower is the canonical Oboron Crockford base32 profile: lowercase
// alphabet, no padding, no check symbols, no I/L/O/U aliases (spec §1.2).
var crockfordLower = base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz").WithPadding(base32.NoPadding)

// b32NoPad is the standard RFC 4648 base32 encoding (uppercase) without padding.
var b32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// ErrNonCanonical reports decode input that is well-formed for its base but is
// not the unique canonical encoding the spec mandates (wrong case, a Crockford
// alias, padding, an impossible length, or non-zero unused trailing bits).
var ErrNonCanonical = errors.New("textcodec: non-canonical encoding")

// EncodeToText converts raw bytes to the canonical encoded text string. b32 is
// uppercase (RFC 4648), c32/hex are lowercase, b64 is URL-safe — all unpadded.
func EncodeToText(data []byte, enc Encoding) string {
	switch enc {
	case C32:
		return crockfordLower.EncodeToString(data)
	case B64:
		return base64.RawURLEncoding.EncodeToString(data)
	case Hex:
		return hex.EncodeToString(data)
	default: // B32
		return b32NoPad.EncodeToString(data)
	}
}

// DecodeFromText converts an encoded text string back to raw bytes with a
// strict canonical decoder (spec §1.2 "Decoding"): the input MUST be exactly
// the canonical encoding of the bytes it decodes to. After decoding through the
// case-specific alphabet, the bytes are re-encoded and compared to the input,
// which rejects wrong case, Crockford I/L/O/U aliases, padding, impossible
// lengths, and non-zero unused trailing bits in one check.
func DecodeFromText(s string, enc Encoding) ([]byte, error) {
	var (
		b   []byte
		err error
	)
	switch enc {
	case C32:
		b, err = crockfordLower.DecodeString(s)
	case B64:
		b, err = base64.RawURLEncoding.DecodeString(s)
	case Hex:
		b, err = hex.DecodeString(s)
	default: // B32
		b, err = b32NoPad.DecodeString(s)
	}
	if err != nil {
		return nil, err
	}
	if EncodeToText(b, enc) != s {
		return nil, ErrNonCanonical
	}
	return b, nil
}
