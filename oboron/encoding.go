package oboron

import "strings"

// Encoding represents a text encoding for oboron output.
type Encoding string

const (
	// EncodingB32 is RFC 4648 standard base32.
	EncodingB32 Encoding = "b32"
	// EncodingC32 is Crockford base32 (default; human-friendly, no I/L/O/U ambiguity).
	EncodingC32 Encoding = "c32"
	// EncodingB64 is URL-safe base64 (RFC 4648 base64url, no padding).
	EncodingB64 Encoding = "b64"
	// EncodingHex is lowercase hexadecimal (no prefix).
	EncodingHex Encoding = "hex"
)

// DefaultEncoding is the default encoding used when none is specified.
// Matches the CLI specification (CLI.md §3): both `ob` and `obz` default to c32.
const DefaultEncoding = EncodingC32

func (e Encoding) String() string {
	return string(e)
}

// LongName returns the full descriptive name for the encoding.
func (e Encoding) LongName() string {
	switch e {
	case EncodingB32:
		return "base32rfc"
	case EncodingC32:
		return "base32crockford"
	case EncodingB64:
		return "base64"
	case EncodingHex:
		return "hex"
	default:
		return string(e)
	}
}

// ParseEncoding parses an encoding string (case-insensitive).
// Accepts both short ("b32") and long ("base32rfc") forms.
func ParseEncoding(s string) (Encoding, error) {
	switch strings.ToLower(s) {
	case "b32", "base32rfc", "base32":
		return EncodingB32, nil
	case "c32", "base32crockford", "crockford":
		return EncodingC32, nil
	case "b64", "base64", "base64url":
		return EncodingB64, nil
	case "hex", "hexadecimal":
		return EncodingHex, nil
	default:
		return "", ErrUnknownEncoding
	}
}
