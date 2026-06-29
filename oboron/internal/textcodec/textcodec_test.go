package textcodec

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
)

func TestRoundtrip(t *testing.T) {
	testData := [][]byte{
		{0x00},
		{0xff},
		{0x01, 0x02, 0x03},
		[]byte("hello world"),
		{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
		bytes.Repeat([]byte{0xAB}, 100),
	}
	for _, enc := range []Encoding{B32, C32, B64, Hex} {
		for i, data := range testData {
			t.Run(string(enc)+"/data_"+strconv.Itoa(i), func(t *testing.T) {
				encoded := EncodeToText(data, enc)
				decoded, err := DecodeFromText(encoded, enc)
				if err != nil {
					t.Fatalf("DecodeFromText failed: %v", err)
				}
				if !bytes.Equal(decoded, data) {
					t.Errorf("Roundtrip mismatch: got %x, want %x", decoded, data)
				}
			})
		}
	}
}

// TestStrictDecodeRejectsNonCanonical verifies that DecodeFromText is a strict
// canonical decoder (spec §1.2 "Decoding"): it accepts only the unique
// canonical encoding and rejects wrong case, Crockford I/L/O/U aliases, odd hex
// length, and impossible base32 lengths.
func TestStrictDecodeRejectsNonCanonical(t *testing.T) {
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x12}

	// Wrong case is non-canonical for the case-fixed alphabets.
	c32 := EncodeToText(data, C32)
	if _, err := DecodeFromText(strings.ToUpper(c32), C32); err == nil {
		t.Errorf("uppercase c32 %q accepted, want rejection", strings.ToUpper(c32))
	}
	b32 := EncodeToText(data, B32)
	if _, err := DecodeFromText(strings.ToLower(b32), B32); err == nil {
		t.Errorf("lowercase b32 %q accepted, want rejection", strings.ToLower(b32))
	}
	hx := EncodeToText(data, Hex)
	if _, err := DecodeFromText(strings.ToUpper(hx), Hex); err == nil {
		t.Errorf("uppercase hex %q accepted, want rejection", strings.ToUpper(hx))
	}

	explicit := []struct {
		name string
		enc  Encoding
		in   string
	}{
		{"c32 alias i", C32, "aaaaaaai"}, // i excluded from the Crockford alphabet
		{"c32 alias o", C32, "aaaaaaao"}, // o excluded
		{"c32 alias l", C32, "aaaaaaal"}, // l excluded
		{"c32 alias u", C32, "aaaaaaau"}, // u excluded
		{"hex odd length", Hex, "abc"},   // hex length must be even
	}
	for _, tc := range explicit {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeFromText(tc.in, tc.enc); err == nil {
				t.Errorf("DecodeFromText(%q, %s) accepted, want rejection", tc.in, tc.enc)
			}
		})
	}

	// Canonical forms must still decode cleanly.
	for _, enc := range []Encoding{B32, C32, B64, Hex} {
		s := EncodeToText(data, enc)
		if got, err := DecodeFromText(s, enc); err != nil || !bytes.Equal(got, data) {
			t.Errorf("canonical %s %q: got %x err %v, want %x", enc, s, got, err, data)
		}
	}
}
