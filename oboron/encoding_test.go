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
		// Canonical short codes — the only accepted forms (closed set, §1.2).
		{"b32", EncodingB32, false},
		{"c32", EncodingC32, false},
		{"b64", EncodingB64, false},
		{"hex", EncodingHex, false},

		// Long forms / aliases are no longer accepted.
		{"base32rfc", "", true},
		{"base32crockford", "", true},
		{"base64", "", true},
		{"hexadecimal", "", true},
		{"base32", "", true},
		{"crockford", "", true},
		{"base64url", "", true},

		// Uppercase is rejected — codes are lowercase ASCII, case-sensitive.
		{"B32", "", true},
		{"C32", "", true},
		{"B64", "", true},
		{"HEX", "", true},
		{"Base32RFC", "", true},

		// Other errors
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

// TestParseFormat verifies strict format-string parsing: there is no
// library-level default encoding, so every scheme must carry an explicit
// encoding suffix.
func TestParseFormat(t *testing.T) {
	tests := []struct {
		input      string
		wantScheme Scheme
		wantEnc    Encoding
		wantErr    bool
	}{
		// Bare scheme names (no encoding) error — no default applies.
		{"zdcbc", Scheme(""), Encoding(""), true},
		{"dgcmsiv", Scheme(""), Encoding(""), true},
		{"dsiv", Scheme(""), Encoding(""), true},
		{"pgcmsiv", Scheme(""), Encoding(""), true},
		{"psiv", Scheme(""), Encoding(""), true},
		{"upcbc", Scheme(""), Encoding(""), true},

		// Scheme + encoding
		{"dsiv.c32", SchemeDsiv, EncodingC32, false},
		{"dsiv.b32", SchemeDsiv, EncodingB32, false},
		{"dsiv.b64", SchemeDsiv, EncodingB64, false},
		{"dsiv.hex", SchemeDsiv, EncodingHex, false},
		{"zdcbc.hex", SchemeZdcbc, EncodingHex, false},
		{"upcbc.c32", SchemeUpcbc, EncodingC32, false},
		{"pgcmsiv.b64", SchemePgcmsiv, EncodingB64, false},

		// Uppercase identifiers are rejected — format ids are lowercase ASCII
		// and case-sensitive (spec §1.1).
		{"DSIV.C32", Scheme(""), Encoding(""), true},
		{"Dgcmsiv.Hex", Scheme(""), Encoding(""), true},

		// Errors
		{"", Scheme(""), Encoding(""), true},
		{"unknown", Scheme(""), Encoding(""), true},
		{"dsiv.unknown", Scheme(""), Encoding(""), true},
		{"unknown.b32", Scheme(""), Encoding(""), true},
		{"legacy", Scheme(""), Encoding(""), true},      // legacy is dropped
		{"legacy.b32", Scheme(""), Encoding(""), true},  // legacy is dropped
		{"zdcbc.", Scheme(""), Encoding(""), true},      // empty encoding
		{".c32", Scheme(""), Encoding(""), true},        // empty scheme
		{"ob:dsiv.c32", Scheme(""), Encoding(""), true}, // ob: prefix rejected
		{" dsiv.c32", Scheme(""), Encoding(""), true},   // leading whitespace
		{"dsiv.c32 ", Scheme(""), Encoding(""), true},   // trailing whitespace
		{"dsiv.c32.x", Scheme(""), Encoding(""), true},  // extra separator
		{"dsiv.base32", Scheme(""), Encoding(""), true}, // long encoding alias
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

// TestFormatString verifies Format.String() output. Every format emits the
// encoding suffix so it round-trips through ParseFormat.
func TestFormatString(t *testing.T) {
	tests := []struct {
		format Format
		want   string
	}{
		{NewFormat(SchemeDsiv, EncodingB32), "dsiv.b32"},
		{NewFormat(SchemeDsiv, EncodingC32), "dsiv.c32"},
		{NewFormat(SchemeDsiv, EncodingB64), "dsiv.b64"},
		{NewFormat(SchemeDsiv, EncodingHex), "dsiv.hex"},
		{NewFormat(SchemeZdcbc, EncodingB32), "zdcbc.b32"},
		{NewFormat(SchemeUpcbc, EncodingHex), "upcbc.hex"},
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
		{"zdcbc", SchemeZdcbc, false},
		{"dgcmsiv", SchemeDgcmsiv, false},
		{"dsiv", SchemeDsiv, false},
		{"pgcmsiv", SchemePgcmsiv, false},
		{"psiv", SchemePsiv, false},
		{"upcbc", SchemeUpcbc, false},
		{"legacy", "", true},
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
