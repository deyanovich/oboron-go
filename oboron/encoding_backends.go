package oboron

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// Crockford base32 encoding alphabet: 0123456789ABCDEFGHJKMNPQRSTVWXYZ
var crockfordEncoding = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

// b32NoPad is the standard RFC 4648 base32 encoding without padding.
var b32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// encodeToText converts raw bytes to an encoded text string.
// b32 output is uppercase (RFC 4648 standard), c32/hex are lowercase, b64 preserves case.
func encodeToText(data []byte, enc Encoding) string {
	switch enc {
	case EncodingC32:
		return strings.ToLower(crockfordEncoding.EncodeToString(data))
	case EncodingB64:
		return base64.RawURLEncoding.EncodeToString(data)
	case EncodingHex:
		return hex.EncodeToString(data)
	default: // EncodingB32
		return b32NoPad.EncodeToString(data)
	}
}

// decodeFromText converts an encoded text string back to raw bytes.
func decodeFromText(s string, enc Encoding) ([]byte, error) {
	switch enc {
	case EncodingC32:
		return crockfordEncoding.DecodeString(crockfordNormalize(s))
	case EncodingB64:
		return base64.RawURLEncoding.DecodeString(s)
	case EncodingHex:
		return hex.DecodeString(strings.ToLower(s))
	default: // EncodingB32
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
