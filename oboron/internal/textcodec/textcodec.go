// Package textcodec holds the byte<->text encoding backends shared by the
// a/u-tier (package oboron) and the z-tier (package oboron/ztier). It is
// deliberately dependency-free — in particular it does not import oboron — so
// that both tiers can reuse the Crockford/base32/base64/hex logic without a
// package cycle. The public oboron.Encoding string values map directly onto
// the Encoding type defined here.
package textcodec

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"strings"
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

// Crockford base32 encoding alphabet: 0123456789ABCDEFGHJKMNPQRSTVWXYZ
var crockfordEncoding = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

// b32NoPad is the standard RFC 4648 base32 encoding without padding.
var b32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// EncodeToText converts raw bytes to an encoded text string.
// b32 output is uppercase (RFC 4648 standard), c32/hex are lowercase, b64 preserves case.
func EncodeToText(data []byte, enc Encoding) string {
	switch enc {
	case C32:
		return strings.ToLower(crockfordEncoding.EncodeToString(data))
	case B64:
		return base64.RawURLEncoding.EncodeToString(data)
	case Hex:
		return hex.EncodeToString(data)
	default: // B32
		return b32NoPad.EncodeToString(data)
	}
}

// DecodeFromText converts an encoded text string back to raw bytes.
func DecodeFromText(s string, enc Encoding) ([]byte, error) {
	switch enc {
	case C32:
		return crockfordEncoding.DecodeString(crockfordNormalize(s))
	case B64:
		return base64.RawURLEncoding.DecodeString(s)
	case Hex:
		return hex.DecodeString(strings.ToLower(s))
	default: // B32
		return b32NoPad.DecodeString(strings.ToUpper(s))
	}
}

// crockfordNormalize normalizes a Crockford base32 string for decoding.
// Maps I/i/L/l → 1, O/o → 0, and uppercases all characters.
func crockfordNormalize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == 'i' || c == 'I' || c == 'l' || c == 'L':
			b.WriteByte('1')
		case c == 'o' || c == 'O':
			b.WriteByte('0')
		case c >= 'a' && c <= 'z':
			b.WriteByte(c - 32) // uppercase
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
