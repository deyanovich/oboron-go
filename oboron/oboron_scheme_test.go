package oboron

import (
	"encoding/base32"
	"strings"
	"testing"

	"oboron.org/go/obcrypt"
)

// TestSchemeRoundtrip verifies encode/decode roundtrip for all schemes
func TestSchemeRoundtrip(t *testing.T) {
	inputs := []string{"a", "hello", "test123", "abcdefghijklmnop", "the quick brown fox", "日本語"}

	tests := []struct {
		name   string
		scheme Scheme
		encode func(*Omnib, string) (string, error)
		decode func(*Omnib, string) (string, error)
	}{
		{"legacy", SchemeLegacy, (*Omnib).EncodeLegacy, (*Omnib).DecodeLegacy},
		{"zrbcx", SchemeZrbcx, (*Omnib).EncodeZrbcx, (*Omnib).DecodeZrbcx},
		{"aags", SchemeAags, (*Omnib).EncodeAags, (*Omnib).DecodeAags},
		{"aasv", SchemeAasv, (*Omnib).EncodeAasv, (*Omnib).DecodeAasv},
		{"apgs", SchemeApgs, (*Omnib).EncodeApgs, (*Omnib).DecodeApgs},
		{"apsv", SchemeApsv, (*Omnib).EncodeApsv, (*Omnib).DecodeApsv},
		{"upbc", SchemeUpbc, (*Omnib).EncodeUpbc, (*Omnib).DecodeUpbc},
	}

	ob, err := NewOmnibKeyless()
	if err != nil {
		t.Fatalf("NewOmnibKeyless failed: %v", err)
	}

	for _, tt := range tests {
		for _, input := range inputs {
			t.Run(tt.name+"/"+input, func(t *testing.T) {
				encoded, err := tt.encode(ob, input)
				if err != nil {
					t.Fatalf("Encode failed: %v", err)
				}
				decoded, err := tt.decode(ob, encoded)
				if err != nil {
					t.Fatalf("Decode failed for encoded=%q: %v", encoded, err)
				}
				if decoded != input {
					t.Errorf("Roundtrip mismatch: got %q, want %q", decoded, input)
				}
			})
		}
	}
}

// TestAutodetectAllSchemes verifies that autodetect works for all schemes
func TestAutodetectAllSchemes(t *testing.T) {
	inputs := []string{"a", "hello world", "test123456"}

	tests := []struct {
		name   string
		encode func(*Omnib, string) (string, error)
	}{
		{"legacy", (*Omnib).EncodeLegacy},
		{"zrbcx", (*Omnib).EncodeZrbcx},
		{"aags", (*Omnib).EncodeAags},
		{"aasv", (*Omnib).EncodeAasv},
		{"apgs", (*Omnib).EncodeApgs},
		{"apsv", (*Omnib).EncodeApsv},
		{"upbc", (*Omnib).EncodeUpbc},
	}

	ob, err := NewOmnibKeyless()
	if err != nil {
		t.Fatalf("NewOmnibKeyless failed: %v", err)
	}

	for _, tt := range tests {
		for _, input := range inputs {
			t.Run(tt.name+"/"+input, func(t *testing.T) {
				encoded, err := tt.encode(ob, input)
				if err != nil {
					t.Fatalf("Encode failed: %v", err)
				}
				decoded, err := ob.Decode(encoded)
				if err != nil {
					t.Fatalf("Autodetect decode failed: %v", err)
				}
				if decoded != input {
					t.Errorf("Autodetect mismatch: got %q, want %q", decoded, input)
				}
			})
		}
	}
}

// TestDeterministicSchemes verifies that deterministic schemes produce consistent output
func TestDeterministicSchemes(t *testing.T) {
	ob, err := NewOmnibKeyless()
	if err != nil {
		t.Fatalf("NewOmnibKeyless failed: %v", err)
	}

	deterministicTests := []struct {
		name   string
		encode func(*Omnib, string) (string, error)
	}{
		{"legacy", (*Omnib).EncodeLegacy},
		{"zrbcx", (*Omnib).EncodeZrbcx},
		{"aags", (*Omnib).EncodeAags},
		{"aasv", (*Omnib).EncodeAasv},
	}

	for _, tt := range deterministicTests {
		t.Run(tt.name, func(t *testing.T) {
			e1, _ := tt.encode(ob, "hello")
			e2, _ := tt.encode(ob, "hello")
			if e1 != e2 {
				t.Errorf("%s not deterministic: %q != %q", tt.name, e1, e2)
			}
		})
	}
}

// TestMarker2Byte verifies the 2-byte marker format with XOR mixing
func TestMarker2Byte(t *testing.T) {
	ob, err := NewOmnibKeyless()
	if err != nil {
		t.Fatalf("NewOmnibKeyless failed: %v", err)
	}

	tests := []struct {
		name   string
		marker [2]byte
		encode func(*Omnib, string) (string, error)
	}{
		{"zrbcx", zrbcxMarker, (*Omnib).EncodeZrbcx},
		{"aags", obcrypt.Aags.Marker(), (*Omnib).EncodeAags},
		{"aasv", obcrypt.Aasv.Marker(), (*Omnib).EncodeAasv},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := tt.encode(ob, "test")
			if err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			// Base32 decode the output to inspect raw bytes
			upper := strings.ToUpper(encoded)
			if m := len(upper) % 8; m != 0 {
				upper += strings.Repeat("=", 8-m)
			}
			raw, err := base32.StdEncoding.DecodeString(upper)
			if err != nil {
				t.Fatalf("Base32 decode failed: %v", err)
			}

			// Last 2 bytes should be XORed marker
			n := len(raw)
			if n < MarkerSize {
				t.Fatalf("Raw data too short: %d bytes", n)
			}

			// Recover marker by XORing with first byte
			recoveredMarker := [2]byte{
				raw[n-2] ^ raw[0],
				raw[n-1] ^ raw[0],
			}

			if recoveredMarker != tt.marker {
				t.Errorf("Marker mismatch: got %x, want %x", recoveredMarker, tt.marker)
			}

			// Verify autodetect can decode it
			decoded, err := ob.Decode(encoded)
			if err != nil {
				t.Fatalf("Autodetect decode failed: %v", err)
			}
			if decoded != "test" {
				t.Errorf("Decoded mismatch: got %q, want %q", decoded, "test")
			}
		})
	}
}

// TestSchemeConstants verifies scheme constant values
func TestSchemeConstants(t *testing.T) {
	tests := []struct {
		scheme Scheme
		value  string
	}{
		{SchemeLegacy, "legacy"},
		{SchemeZrbcx, "zrbcx"},
		{SchemeAags, "aags"},
		{SchemeAasv, "aasv"},
		{SchemeApgs, "apgs"},
		{SchemeApsv, "apsv"},
		{SchemeUpbc, "upbc"},
	}

	for _, tt := range tests {
		if string(tt.scheme) != tt.value {
			t.Errorf("Scheme %q value mismatch: got %q", tt.value, string(tt.scheme))
		}
	}
}

// TestMarkerValues verifies marker byte values match oboron-rs
func TestMarkerValues(t *testing.T) {
	tests := []struct {
		name   string
		marker [2]byte
		byte1  byte
		byte2  byte
	}{
		{"aags", obcrypt.Aags.Marker(), 0x01, 0x12},
		{"apgs", obcrypt.Apgs.Marker(), 0x01, 0x02},
		{"aasv", obcrypt.Aasv.Marker(), 0x01, 0x13},
		{"apsv", obcrypt.Apsv.Marker(), 0x01, 0x03},
		{"upbc", obcrypt.Upbc.Marker(), 0x02, 0x01},
		{"zrbcx", zrbcxMarker, 0x06, 0x21},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.marker[0] != tt.byte1 || tt.marker[1] != tt.byte2 {
				t.Errorf("Marker mismatch: got [%02x, %02x], want [%02x, %02x]",
					tt.marker[0], tt.marker[1], tt.byte1, tt.byte2)
			}
		})
	}
}

// TestUpbcScheme verifies the new upbc scheme works correctly
func TestUpbcScheme(t *testing.T) {
	ob, err := NewUpbcKeyless()
	if err != nil {
		t.Fatalf("NewUpbcKeyless failed: %v", err)
	}

	inputs := []string{"a", "hello", "test123456", "abcdefghijklmnop"}
	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			encoded, err := ob.Encode(input)
			if err != nil {
				t.Fatalf("Encode failed: %v", err)
			}
			decoded, err := ob.Decode(encoded)
			if err != nil {
				t.Fatalf("Decode failed: %v", err)
			}
			if decoded != input {
				t.Errorf("Roundtrip mismatch: got %q, want %q", decoded, input)
			}

			// Upbc is probabilistic - encoding same input should produce different output
			encoded2, err := ob.Encode(input)
			if err != nil {
				t.Fatalf("Second encode failed: %v", err)
			}
			if encoded == encoded2 {
				t.Logf("Warning: upbc produced same output (unlikely but possible)")
			}
		})
	}
}

// TestOboronConstructors verifies all Oboron constructors work
func TestOboronConstructors(t *testing.T) {
	tests := []struct {
		name   string
		create func() (*Oboron, error)
		scheme Scheme
	}{
		{"NewLegacyKeyless", NewLegacyKeyless, SchemeLegacy},
		{"NewZrbcxKeyless", NewZrbcxKeyless, SchemeZrbcx},
		{"NewAagsKeyless", NewAagsKeyless, SchemeAags},
		{"NewAasvKeyless", NewAasvKeyless, SchemeAasv},
		{"NewApgsKeyless", NewApgsKeyless, SchemeApgs},
		{"NewApsvKeyless", NewApsvKeyless, SchemeApsv},
		{"NewUpbcKeyless", NewUpbcKeyless, SchemeUpbc},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ob, err := tt.create()
			if err != nil {
				t.Fatalf("Constructor failed: %v", err)
			}
			if ob.Scheme() != tt.scheme {
				t.Errorf("Scheme mismatch: got %q, want %q", ob.Scheme(), tt.scheme)
			}

			encoded, err := ob.Encode("test")
			if err != nil {
				t.Fatalf("Encode failed: %v", err)
			}
			decoded, err := ob.Decode(encoded)
			if err != nil {
				t.Fatalf("Decode failed: %v", err)
			}
			if decoded != "test" {
				t.Errorf("Roundtrip failed: got %q", decoded)
			}
		})
	}
}

// TestMultiEncodingRoundtrip verifies encode/decode roundtrip for all scheme+encoding combinations
func TestMultiEncodingRoundtrip(t *testing.T) {
	inputs := []string{"a", "hello", "test123", "the quick brown fox", "日本語"}

	encodings := []Encoding{EncodingB32, EncodingC32, EncodingB64, EncodingHex}

	schemes := []struct {
		name   string
		scheme Scheme
		encode func(*codec, string, Encoding) (string, error)
		decode func(*codec, string, Encoding) (string, error)
	}{
		{"legacy", SchemeLegacy, (*codec).encodeLegacyWith, (*codec).decodeLegacyWith},
		{"zrbcx", SchemeZrbcx, (*codec).encodeZrbcxWith, (*codec).decodeZrbcxWith},
		{"aags", SchemeAags, (*codec).encodeAagsWith, (*codec).decodeAagsWith},
		{"aasv", SchemeAasv, (*codec).encodeAasvWith, (*codec).decodeAasvWith},
		{"apgs", SchemeApgs, (*codec).encodeApgsWith, (*codec).decodeApgsWith},
		{"apsv", SchemeApsv, (*codec).encodeApsvWith, (*codec).decodeApsvWith},
		{"upbc", SchemeUpbc, (*codec).encodeUpbcWith, (*codec).decodeUpbcWith},
	}

	ob, err := NewOmnibKeyless()
	if err != nil {
		t.Fatalf("NewOmnibKeyless failed: %v", err)
	}

	for _, scheme := range schemes {
		for _, enc := range encodings {
			for _, input := range inputs {
				name := scheme.name + "." + string(enc) + "/" + input
				t.Run(name, func(t *testing.T) {
					encoded, err := scheme.encode(ob.codec, input, enc)
					if err != nil {
						t.Fatalf("Encode failed: %v", err)
					}
					decoded, err := scheme.decode(ob.codec, encoded, enc)
					if err != nil {
						t.Fatalf("Decode failed for encoded=%q: %v", encoded, err)
					}
					if decoded != input {
						t.Errorf("Roundtrip mismatch: got %q, want %q", decoded, input)
					}
				})
			}
		}
	}
}

// TestMultiEncodingAutodetect verifies that autodetect works with different encodings
func TestMultiEncodingAutodetect(t *testing.T) {
	inputs := []string{"hello", "test123", "日本語"}

	encodings := []Encoding{EncodingB32, EncodingC32, EncodingB64, EncodingHex}

	schemeEncoders := []struct {
		name   string
		encode func(*codec, string, Encoding) (string, error)
	}{
		{"zrbcx", (*codec).encodeZrbcxWith},
		{"aags", (*codec).encodeAagsWith},
		{"aasv", (*codec).encodeAasvWith},
		{"apgs", (*codec).encodeApgsWith},
		{"apsv", (*codec).encodeApsvWith},
		{"upbc", (*codec).encodeUpbcWith},
		{"legacy", (*codec).encodeLegacyWith},
	}

	ob, err := NewOmnibKeyless()
	if err != nil {
		t.Fatalf("NewOmnibKeyless failed: %v", err)
	}

	for _, scheme := range schemeEncoders {
		for _, enc := range encodings {
			for _, input := range inputs {
				name := scheme.name + "." + string(enc) + "/" + input
				t.Run(name, func(t *testing.T) {
					encoded, err := scheme.encode(ob.codec, input, enc)
					if err != nil {
						t.Fatalf("Encode failed: %v", err)
					}

					// Autodetect with known encoding
					decoded, err := ob.codec.decodeAutodetectWith(encoded, enc)
					if err != nil {
						t.Fatalf("decodeAutodetectWith failed: %v", err)
					}
					if decoded != input {
						t.Errorf("Autodetect mismatch: got %q, want %q", decoded, input)
					}
				})
			}
		}
	}
}

// TestNewFormatConstructor verifies the New() format-based constructor
func TestNewFormatConstructor(t *testing.T) {
	tests := []struct {
		format string
		scheme Scheme
		enc    Encoding
	}{
		{"aasv.c32", SchemeAasv, EncodingC32},
		{"aags.hex", SchemeAags, EncodingHex},
		{"legacy.b64", SchemeLegacy, EncodingB64},
		{"upbc", SchemeUpbc, EncodingC32},     // schemes default to c32 per CLI.md §3
		{"legacy", SchemeLegacy, EncodingB32}, // legacy keeps b32 (its only encoding)
		{"zrbcx.c32", SchemeZrbcx, EncodingC32},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			ob, err := New(tt.format, HardcodedKey)
			if err != nil {
				t.Fatalf("New(%q) failed: %v", tt.format, err)
			}

			if ob.Scheme() != tt.scheme {
				t.Errorf("Scheme: got %q, want %q", ob.Scheme(), tt.scheme)
			}
			if ob.Encoding() != tt.enc {
				t.Errorf("Encoding: got %q, want %q", ob.Encoding(), tt.enc)
			}

			// Roundtrip
			encoded, err := ob.Encode("hello")
			if err != nil {
				t.Fatalf("Encode failed: %v", err)
			}
			decoded, err := ob.Decode(encoded)
			if err != nil {
				t.Fatalf("Decode failed: %v", err)
			}
			if decoded != "hello" {
				t.Errorf("Roundtrip: got %q, want %q", decoded, "hello")
			}
		})
	}
}

// TestOmnibEncodeWithFormat verifies Omnib.EncodeWithFormat/DecodeWithFormat
func TestOmnibEncodeWithFormat(t *testing.T) {
	ob, err := NewOmnibKeyless()
	if err != nil {
		t.Fatalf("NewOmnibKeyless failed: %v", err)
	}

	formats := []string{
		"aasv.c32", "aasv.b64", "aasv.hex", "aasv.b32",
		"aags.c32", "aags.hex",
		"legacy.c32", "legacy.hex",
		"zrbcx.b64", "upbc.c32",
	}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			encoded, err := ob.EncodeWithFormat("hello world", format)
			if err != nil {
				t.Fatalf("EncodeWithFormat(%q) failed: %v", format, err)
			}

			decoded, err := ob.DecodeWithFormat(encoded, format)
			if err != nil {
				t.Fatalf("DecodeWithFormat(%q) failed: %v", format, err)
			}

			if decoded != "hello world" {
				t.Errorf("Roundtrip: got %q, want %q", decoded, "hello world")
			}
		})
	}
}

// TestDeterministicWithDifferentEncodings verifies same plaintext produces consistent output for different encodings
func TestDeterministicWithDifferentEncodings(t *testing.T) {
	ob, err := NewOmnibKeyless()
	if err != nil {
		t.Fatalf("NewOmnibKeyless failed: %v", err)
	}

	// Deterministic schemes should produce the same output for same input
	deterministicSchemes := []struct {
		name   string
		encode func(*codec, string, Encoding) (string, error)
	}{
		{"aags", (*codec).encodeAagsWith},
		{"aasv", (*codec).encodeAasvWith},
		{"legacy", (*codec).encodeLegacyWith},
		{"zrbcx", (*codec).encodeZrbcxWith},
	}

	encodings := []Encoding{EncodingB32, EncodingC32, EncodingB64, EncodingHex}

	for _, scheme := range deterministicSchemes {
		for _, enc := range encodings {
			t.Run(scheme.name+"."+string(enc), func(t *testing.T) {
				e1, _ := scheme.encode(ob.codec, "deterministic test", enc)
				e2, _ := scheme.encode(ob.codec, "deterministic test", enc)
				if e1 != e2 {
					t.Errorf("Not deterministic: %q != %q", e1, e2)
				}
			})
		}
	}
}

// TestB32DefaultBackwardCompat verifies that default B32 encoding produces identical output to original
func TestB32DefaultBackwardCompat(t *testing.T) {
	ob, err := NewOmnibKeyless()
	if err != nil {
		t.Fatalf("NewOmnibKeyless failed: %v", err)
	}

	input := "hello world"

	// Legacy: Compare default encode with explicit B32 encode
	legacyDefault, _ := ob.codec.encodeLegacy(input)
	legacyB32, _ := ob.codec.encodeLegacyWith(input, EncodingB32)
	if legacyDefault != legacyB32 {
		t.Errorf("Legacy backward compat: default=%q, B32=%q", legacyDefault, legacyB32)
	}

	// Aags: Compare default with explicit B32
	aagsDefault, _ := ob.codec.encodeAags(input)
	aagsB32, _ := ob.codec.encodeAagsWith(input, EncodingB32)
	if aagsDefault != aagsB32 {
		t.Errorf("Aags backward compat: default=%q, B32=%q", aagsDefault, aagsB32)
	}

	// Aasv: Compare default with explicit B32
	aasvDefault, _ := ob.codec.encodeAasv(input)
	aasvB32, _ := ob.codec.encodeAasvWith(input, EncodingB32)
	if aasvDefault != aasvB32 {
		t.Errorf("Aasv backward compat: default=%q, B32=%q", aasvDefault, aasvB32)
	}

	// Zrbcx: Compare default with explicit B32
	zrbcxDefault, _ := ob.codec.encodeZrbcx(input)
	zrbcxB32, _ := ob.codec.encodeZrbcxWith(input, EncodingB32)
	if zrbcxDefault != zrbcxB32 {
		t.Errorf("Zrbcx backward compat: default=%q, B32=%q", zrbcxDefault, zrbcxB32)
	}
}

// TestOboronFormatAccessors verifies Format/Encoding/Scheme accessors on Oboron
func TestOboronFormatAccessors(t *testing.T) {
	ob, err := New("aasv.c32", HardcodedKey)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	if ob.Scheme() != SchemeAasv {
		t.Errorf("Scheme: got %q, want %q", ob.Scheme(), SchemeAasv)
	}
	if ob.Encoding() != EncodingC32 {
		t.Errorf("Encoding: got %q, want %q", ob.Encoding(), EncodingC32)
	}

	f := ob.Format()
	if f.Scheme() != SchemeAasv || f.Encoding() != EncodingC32 {
		t.Errorf("Format: got %v, want aasv.c32", f)
	}
	if f.String() != "aasv.c32" {
		t.Errorf("Format.String(): got %q, want %q", f.String(), "aasv.c32")
	}
}

// TestDecodeAnyEncoding verifies DecodeAny tries all encodings
func TestDecodeAnyEncoding(t *testing.T) {
	ob, err := NewOmnibKeyless()
	if err != nil {
		t.Fatalf("NewOmnibKeyless failed: %v", err)
	}

	input := "hello world"

	encodings := []Encoding{EncodingB32, EncodingC32, EncodingB64, EncodingHex}
	for _, enc := range encodings {
		t.Run(string(enc), func(t *testing.T) {
			encoded, err := ob.codec.encodeAagsWith(input, enc)
			if err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			decoded, err := ob.DecodeAny(encoded)
			if err != nil {
				t.Fatalf("DecodeAny failed for enc=%s, encoded=%q: %v", enc, encoded, err)
			}
			if decoded != input {
				t.Errorf("DecodeAny mismatch: got %q, want %q", decoded, input)
			}
		})
	}
}

// TestNewKeylessFromFormat verifies the NewKeylessFromFormat constructor.
func TestNewKeylessFromFormat(t *testing.T) {
	ob, err := NewKeylessFromFormat("aasv.hex")
	if err != nil {
		t.Fatalf("NewKeylessFromFormat failed: %v", err)
	}

	if ob.Scheme() != SchemeAasv || ob.Encoding() != EncodingHex {
		t.Errorf("Unexpected format: got scheme=%q encoding=%q", ob.Scheme(), ob.Encoding())
	}

	encoded, err := ob.Encode("test")
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	decoded, err := ob.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}
	if decoded != "test" {
		t.Errorf("Roundtrip: got %q, want %q", decoded, "test")
	}
}

// TestOmnibEncDecAutodec verifies the Enc/Dec/Autodec methods on Omnib.
func TestOmnibEncDecAutodec(t *testing.T) {
	ob, err := NewOmnibKeyless()
	if err != nil {
		t.Fatalf("NewOmnibKeyless failed: %v", err)
	}

	input := "hello world"

	t.Run("Enc_Dec_roundtrip", func(t *testing.T) {
		formats := []string{
			"aasv.c32", "aasv.b64", "aags.hex", "legacy.b32",
			"zrbcx.c32", "upbc.b64",
		}
		for _, format := range formats {
			t.Run(format, func(t *testing.T) {
				encoded, err := ob.Enc(input, format)
				if err != nil {
					t.Fatalf("Enc(%q) failed: %v", format, err)
				}
				decoded, err := ob.Dec(encoded, format)
				if err != nil {
					t.Fatalf("Dec(%q) failed: %v", format, err)
				}
				if decoded != input {
					t.Errorf("Enc/Dec roundtrip: got %q, want %q", decoded, input)
				}
			})
		}
	})

	t.Run("Autodec_across_encodings", func(t *testing.T) {
		// Encode with various formats, then Autodec should handle all
		formats := []string{"aasv.b32", "aags.hex", "aasv.c32", "aasv.b64"}
		for _, format := range formats {
			t.Run(format, func(t *testing.T) {
				encoded, err := ob.Enc(input, format)
				if err != nil {
					t.Fatalf("Enc(%q) failed: %v", format, err)
				}
				decoded, err := ob.Autodec(encoded)
				if err != nil {
					t.Fatalf("Autodec for format=%q failed: %v", format, err)
				}
				if decoded != input {
					t.Errorf("Autodec mismatch: got %q, want %q", decoded, input)
				}
			})
		}
	})
}

// TestOboronEncDecAutodec verifies the Enc/Dec/Autodec methods on Oboron.
func TestOboronEncDecAutodec(t *testing.T) {
	t.Run("Enc_is_Encode_alias", func(t *testing.T) {
		ob, err := NewAasvKeyless()
		if err != nil {
			t.Fatalf("NewAasvKeyless failed: %v", err)
		}
		e1, err := ob.Enc("test")
		if err != nil {
			t.Fatalf("Enc failed: %v", err)
		}
		// Aasv is deterministic, so Encode should match
		e2, err := ob.Encode("test")
		if err != nil {
			t.Fatalf("Encode failed: %v", err)
		}
		if e1 != e2 {
			t.Errorf("Enc != Encode: %q vs %q", e1, e2)
		}
	})

	t.Run("Dec_strict_decode", func(t *testing.T) {
		schemes := []struct {
			name   string
			create func() (*Oboron, error)
		}{
			{"legacy", NewLegacyKeyless},
			{"zrbcx", NewZrbcxKeyless},
			{"aags", NewAagsKeyless},
			{"aasv", NewAasvKeyless},
			{"upbc", NewUpbcKeyless},
		}
		for _, tt := range schemes {
			t.Run(tt.name, func(t *testing.T) {
				ob, err := tt.create()
				if err != nil {
					t.Fatalf("Constructor failed: %v", err)
				}
				encoded, err := ob.Enc("test input")
				if err != nil {
					t.Fatalf("Enc failed: %v", err)
				}
				decoded, err := ob.Dec(encoded)
				if err != nil {
					t.Fatalf("Dec failed: %v", err)
				}
				if decoded != "test input" {
					t.Errorf("Dec mismatch: got %q, want %q", decoded, "test input")
				}
			})
		}
	})

	t.Run("Autodec_autodetects_scheme", func(t *testing.T) {
		// Encode with aags, decode with aasv instance (autodec should still work)
		aags, err := NewAagsKeyless()
		if err != nil {
			t.Fatalf("NewAagsKeyless failed: %v", err)
		}
		aasv, err := NewAasvKeyless()
		if err != nil {
			t.Fatalf("NewAasvKeyless failed: %v", err)
		}

		encoded, err := aags.Enc("hello")
		if err != nil {
			t.Fatalf("Enc failed: %v", err)
		}
		// Autodec on aasv instance should detect aags marker and succeed
		decoded, err := aasv.Autodec(encoded)
		if err != nil {
			t.Fatalf("Autodec failed: %v", err)
		}
		if decoded != "hello" {
			t.Errorf("Autodec mismatch: got %q, want %q", decoded, "hello")
		}
	})
}

// TestZrbcxXorAlgorithm verifies the new XOR first/last block algorithm for zrbcx.
func TestZrbcxXorAlgorithm(t *testing.T) {
	ob, err := NewOmnibKeyless()
	if err != nil {
		t.Fatalf("NewOmnibKeyless failed: %v", err)
	}

	// Test that both single-block and multi-block inputs are encoded/decoded correctly.
	// Single-block: no XOR is applied. Multi-block: XOR first block with last block.
	inputs := []string{
		"a",                   // single block (1 char, padded to 16)
		"abcdefghijklmnop",    // single block (exactly 16 chars)
		"abcdefghijklmnopq",   // two blocks (17 chars)
		"the quick brown fox", // two blocks
		"this is a longer input that spans multiple blocks for sure",
	}

	for _, input := range inputs {
		name := input
		if len(name) > 20 {
			name = name[:20]
		}
		t.Run(name, func(t *testing.T) {
			encoded, err := ob.EncodeZrbcx(input)
			if err != nil {
				t.Fatalf("EncodeZrbcx failed: %v", err)
			}
			decoded, err := ob.DecodeZrbcx(encoded)
			if err != nil {
				t.Fatalf("DecodeZrbcx failed for %q: encoded=%q, err=%v", input, encoded, err)
			}
			if decoded != input {
				t.Errorf("Roundtrip mismatch: got %q, want %q", decoded, input)
			}
		})
	}
}
