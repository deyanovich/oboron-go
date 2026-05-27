package oboron

import (
	"bytes"
	"strconv"
	"testing"
)

// TestParseEncoding verifies encoding string parsing
func TestParseEncoding(t *testing.T) {
	tests := []struct {
		input   string
		want    Encoding
		wantErr bool
	}{
		// Short forms
		{"b32", EncodingB32, false},
		{"c32", EncodingC32, false},
		{"b64", EncodingB64, false},
		{"hex", EncodingHex, false},

		// Long forms
		{"base32rfc", EncodingB32, false},
		{"base32crockford", EncodingC32, false},
		{"base64", EncodingB64, false},
		{"hexadecimal", EncodingHex, false},

		// Case-insensitive
		{"B32", EncodingB32, false},
		{"C32", EncodingC32, false},
		{"B64", EncodingB64, false},
		{"HEX", EncodingHex, false},
		{"Base32RFC", EncodingB32, false},

		// Aliases
		{"base32", EncodingB32, false},
		{"crockford", EncodingC32, false},
		{"base64url", EncodingB64, false},

		// Errors
		{"", "", true},
		{"unknown", "", true},
		{"b33", "", true},
		{"base128", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseEncoding(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseEncoding(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseEncoding(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestEncodingString verifies encoding String() and LongName()
func TestEncodingString(t *testing.T) {
	tests := []struct {
		enc      Encoding
		short    string
		longName string
	}{
		{EncodingB32, "b32", "base32rfc"},
		{EncodingC32, "c32", "base32crockford"},
		{EncodingB64, "b64", "base64"},
		{EncodingHex, "hex", "hex"},
	}

	for _, tt := range tests {
		if tt.enc.String() != tt.short {
			t.Errorf("Encoding.String() = %q, want %q", tt.enc.String(), tt.short)
		}
		if tt.enc.LongName() != tt.longName {
			t.Errorf("Encoding.LongName() = %q, want %q", tt.enc.LongName(), tt.longName)
		}
	}
}

// TestParseFormat verifies format string parsing
func TestParseFormat(t *testing.T) {
	tests := []struct {
		input      string
		wantScheme Scheme
		wantEnc    Encoding
		wantErr    bool
	}{
		// Scheme only — spec-conformant schemes default to c32 (CLI.md §3);
		// legacy keeps its historical b32 encoding.
		{"legacy", SchemeLegacy, EncodingB32, false},
		{"zrbcx", SchemeZrbcx, EncodingC32, false},
		{"aags", SchemeAags, EncodingC32, false},
		{"aasv", SchemeAasv, EncodingC32, false},
		{"apgs", SchemeApgs, EncodingC32, false},
		{"apsv", SchemeApsv, EncodingC32, false},
		{"upbc", SchemeUpbc, EncodingC32, false},

		// Scheme + encoding
		{"aasv.c32", SchemeAasv, EncodingC32, false},
		{"aasv.b32", SchemeAasv, EncodingB32, false},
		{"aasv.b64", SchemeAasv, EncodingB64, false},
		{"aasv.hex", SchemeAasv, EncodingHex, false},
		{"legacy.c32", SchemeLegacy, EncodingC32, false},
		{"zrbcx.hex", SchemeZrbcx, EncodingHex, false},
		{"apgs.b64", SchemeApgs, EncodingB64, false},

		// Case-insensitive
		{"AASV.C32", SchemeAasv, EncodingC32, false},
		{"Aags.Hex", SchemeAags, EncodingHex, false},

		// Errors
		{"", Scheme(""), Encoding(""), true},
		{"unknown", Scheme(""), Encoding(""), true},
		{"aasv.unknown", Scheme(""), Encoding(""), true},
		{"unknown.b32", Scheme(""), Encoding(""), true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseFormat(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseFormat(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.Scheme() != tt.wantScheme {
					t.Errorf("ParseFormat(%q).Scheme() = %q, want %q", tt.input, got.Scheme(), tt.wantScheme)
				}
				if got.Encoding() != tt.wantEnc {
					t.Errorf("ParseFormat(%q).Encoding() = %q, want %q", tt.input, got.Encoding(), tt.wantEnc)
				}
			}
		})
	}
}

// TestFormatString verifies Format.String() output. The encoding suffix is
// always emitted so the result round-trips through ParseFormat.
func TestFormatString(t *testing.T) {
	tests := []struct {
		format Format
		want   string
	}{
		{NewFormat(SchemeAasv, EncodingB32), "aasv.b32"},
		{NewFormat(SchemeAasv, EncodingC32), "aasv.c32"},
		{NewFormat(SchemeAasv, EncodingB64), "aasv.b64"},
		{NewFormat(SchemeAasv, EncodingHex), "aasv.hex"},
		{NewFormat(SchemeLegacy, EncodingB32), "legacy.b32"},
		{NewFormat(SchemeLegacy, EncodingC32), "legacy.c32"},
		{NewFormat(SchemeUpbc, EncodingHex), "upbc.hex"},
	}

	for _, tt := range tests {
		if got := tt.format.String(); got != tt.want {
			t.Errorf("Format.String() = %q, want %q", got, tt.want)
		}
	}
}

// TestParseScheme verifies scheme parsing
func TestParseScheme(t *testing.T) {
	tests := []struct {
		input   string
		want    Scheme
		wantErr bool
	}{
		{"legacy", SchemeLegacy, false},
		{"zrbcx", SchemeZrbcx, false},
		{"aags", SchemeAags, false},
		{"aasv", SchemeAasv, false},
		{"apgs", SchemeApgs, false},
		{"apsv", SchemeApsv, false},
		{"upbc", SchemeUpbc, false},
		{"unknown", "", true},
		{"", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseScheme(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseScheme(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseScheme(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestEncodingBackendsRoundtrip verifies encode/decode roundtrip for all encodings
func TestEncodingBackendsRoundtrip(t *testing.T) {
	testData := [][]byte{
		{0x00},
		{0xff},
		{0x01, 0x02, 0x03},
		[]byte("hello world"),
		{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
		bytes.Repeat([]byte{0xAB}, 100),
	}

	encodings := []Encoding{EncodingB32, EncodingC32, EncodingB64, EncodingHex}

	for _, enc := range encodings {
		for i, data := range testData {
			t.Run(enc.String()+"/data_"+strconv.Itoa(i), func(t *testing.T) {
				encoded := encodeToText(data, enc)
				decoded, err := decodeFromText(encoded, enc)
				if err != nil {
					t.Fatalf("decodeFromText failed: %v", err)
				}
				if !bytes.Equal(decoded, data) {
					t.Errorf("Roundtrip mismatch: got %x, want %x", decoded, data)
				}
			})
		}
	}
}

// TestCrockfordNormalize verifies Crockford normalization
func TestCrockfordNormalize(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"abc123", "ABC123"},
		{"Io1l", "1011"},     // I→1, o→0, l→1
		{"OoIiLl", "001111"}, // O→0, o→0, I→1, i→1, L→1, l→1
		{"HELLO", "HE110"},   // L→1, O→0 (Crockford mapping)
		{"hello", "HE110"},   // same in lowercase
		{"0123456789", "0123456789"},
	}

	for _, tt := range tests {
		got := crockfordNormalize(tt.input)
		if got != tt.want {
			t.Errorf("crockfordNormalize(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// TestEncodingOutputFormat verifies output format for each encoding
func TestEncodingOutputFormat(t *testing.T) {
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	// B32 should be uppercase per RFC 4648 and only contain base32 chars
	b32 := encodeToText(data, EncodingB32)
	for _, c := range b32 {
		if !((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7')) {
			t.Errorf("B32 output contains unexpected char %q in %q", string(c), b32)
		}
	}

	// C32 should be lowercase and use Crockford alphabet (0-9, a-v, no i/l/o/u)
	c32 := encodeToText(data, EncodingC32)
	for _, c := range c32 {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')) {
			t.Errorf("C32 output contains unexpected char %q in %q", string(c), c32)
		}
	}

	// B64 should be URL-safe base64 (no padding)
	b64 := encodeToText(data, EncodingB64)
	for _, c := range b64 {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			t.Errorf("B64 output contains unexpected char %q in %q", string(c), b64)
		}
	}

	// Hex should be lowercase hex
	hexStr := encodeToText(data, EncodingHex)
	if hexStr != "deadbeef" {
		t.Errorf("Hex output = %q, want %q", hexStr, "deadbeef")
	}
}
