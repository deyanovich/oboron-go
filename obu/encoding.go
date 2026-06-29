package obu

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"oboron.org/go/oboron"
)

// The obu package is a sibling of oboron, so it cannot import the
// oboron/internal/textcodec package (Go internal-import rules). These helpers
// replicate the same strict byte<->text logic for the obu codec. The behaviour
// must match textcodec exactly: b32 uppercase (RFC 4648, no padding), c32
// Crockford lowercase, b64 url-safe no padding, hex lowercase — all decoded
// with a strict canonical check (spec §1.2 "Decoding").

// crockfordLower is the canonical Oboron Crockford base32 profile: lowercase,
// no padding, no I/L/O/U aliases.
var crockfordLower = base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz").WithPadding(base32.NoPadding)

// b32NoPad is RFC 4648 base32 (uppercase) without padding.
var b32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// errNonCanonical reports decode input that is not the unique canonical
// encoding of the bytes it decodes to.
var errNonCanonical = errors.New("obu: non-canonical encoding")

// encodeToText converts raw bytes to the canonical encoded text string.
func encodeToText(data []byte, enc oboron.Encoding) string {
	switch enc {
	case oboron.EncodingC32:
		return crockfordLower.EncodeToString(data)
	case oboron.EncodingB64:
		return base64.RawURLEncoding.EncodeToString(data)
	case oboron.EncodingHex:
		return hex.EncodeToString(data)
	default: // b32
		return b32NoPad.EncodeToString(data)
	}
}

// decodeFromText converts an encoded text string back to raw bytes with a
// strict canonical decoder: the input must re-encode to itself, rejecting wrong
// case, Crockford aliases, padding, impossible lengths, and non-zero trailing
// bits (spec §1.2 "Decoding").
func decodeFromText(s string, enc oboron.Encoding) ([]byte, error) {
	var (
		b   []byte
		err error
	)
	switch enc {
	case oboron.EncodingC32:
		b, err = crockfordLower.DecodeString(s)
	case oboron.EncodingB64:
		b, err = base64.RawURLEncoding.DecodeString(s)
	case oboron.EncodingHex:
		b, err = hex.DecodeString(s)
	default: // b32
		b, err = b32NoPad.DecodeString(s)
	}
	if err != nil {
		return nil, err
	}
	if encodeToText(b, enc) != s {
		return nil, errNonCanonical
	}
	return b, nil
}
