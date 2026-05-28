package oboron

import (
	"encoding/base32"
	"strings"
	"testing"

	"oboron.org/go/obcrypt"
)

var auSchemes = []Scheme{SchemeAags, SchemeAasv, SchemeApgs, SchemeApsv, SchemeUpbc}

// TestSchemeRoundtrip exercises Enc/Dec for every a/u scheme via Omnib.
func TestSchemeRoundtrip(t *testing.T) {
	om, _ := NewOmnibKeyless()
	for _, scheme := range auSchemes {
		format := string(scheme) + ".c32"
		t.Run(string(scheme), func(t *testing.T) {
			ot, err := om.Enc("hello, world", format)
			if err != nil {
				t.Fatalf("Enc failed: %v", err)
			}
			pt, err := om.Dec(ot, format)
			if err != nil {
				t.Fatalf("Dec failed: %v", err)
			}
			if pt != "hello, world" {
				t.Errorf("roundtrip: got %q", pt)
			}
		})
	}
}

// TestAutodetectAllSchemes verifies Omnib.Autodec recovers every a/u scheme.
func TestAutodetectAllSchemes(t *testing.T) {
	om, _ := NewOmnibKeyless()
	for _, scheme := range auSchemes {
		t.Run(string(scheme), func(t *testing.T) {
			ot, _ := om.Enc("autodetect me", string(scheme)+".c32")
			pt, err := om.Autodec(ot)
			if err != nil {
				t.Fatalf("Autodec failed: %v", err)
			}
			if pt != "autodetect me" {
				t.Errorf("autodec: got %q", pt)
			}
		})
	}
}

// TestDeterministicSchemes verifies deterministic a-tier schemes produce stable
// output and probabilistic ones vary.
func TestDeterministicSchemes(t *testing.T) {
	om, _ := NewOmnibKeyless()
	for _, scheme := range auSchemes {
		format := string(scheme) + ".c32"
		a, _ := om.Enc("same input here", format)
		b, _ := om.Enc("same input here", format)
		stable := a == b
		if isProbabilistic(scheme) && stable {
			t.Errorf("%s: probabilistic scheme produced identical output", scheme)
		}
		if !isProbabilistic(scheme) && !stable {
			t.Errorf("%s: deterministic scheme produced differing output", scheme)
		}
	}
}

// TestMarker2Byte verifies the appended 2-byte XOR marker for a/u schemes.
func TestMarker2Byte(t *testing.T) {
	om, _ := NewOmnibKeyless()
	tests := []struct {
		scheme Scheme
		marker [2]byte
	}{
		{SchemeAags, obcrypt.Aags.Marker()},
		{SchemeAasv, obcrypt.Aasv.Marker()},
		{SchemeUpbc, obcrypt.Upbc.Marker()},
	}
	for _, tt := range tests {
		t.Run(string(tt.scheme), func(t *testing.T) {
			encoded, err := om.Enc("test", string(tt.scheme)+".b32")
			if err != nil {
				t.Fatalf("Enc failed: %v", err)
			}
			upper := strings.ToUpper(encoded)
			if m := len(upper) % 8; m != 0 {
				upper += strings.Repeat("=", 8-m)
			}
			raw, err := base32.StdEncoding.DecodeString(upper)
			if err != nil {
				t.Fatalf("base32 decode failed: %v", err)
			}
			n := len(raw)
			recovered := [2]byte{raw[n-2] ^ raw[0], raw[n-1] ^ raw[0]}
			if recovered != tt.marker {
				t.Errorf("marker mismatch: got %x, want %x", recovered, tt.marker)
			}
		})
	}
}

// TestNewRejectsZTier verifies the a/u-tier constructors reject z-tier formats.
func TestNewRejectsZTier(t *testing.T) {
	key := GenerateKey()
	for _, format := range []string{"zrbcx.c32", "legacy"} {
		if _, err := New(format, key); err != ErrInvalidFormat {
			t.Errorf("New(%q) error = %v, want ErrInvalidFormat", format, err)
		}
	}
}

// TestNewStrictFormat verifies New requires an explicit encoding (no default).
func TestNewStrictFormat(t *testing.T) {
	key := GenerateKey()
	if _, err := New("aasv", key); err != ErrInvalidFormat {
		t.Errorf("New(\"aasv\") error = %v, want ErrInvalidFormat", err)
	}
	if _, err := New("aasv.c32", key); err != nil {
		t.Errorf("New(\"aasv.c32\") unexpected error: %v", err)
	}
}

// TestObAccessorsAndSetters covers Ob's format accessors and runtime setters.
func TestObAccessorsAndSetters(t *testing.T) {
	ob, err := New("aasv.c32", GenerateKey())
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if ob.Scheme() != SchemeAasv || ob.Encoding() != EncodingC32 {
		t.Fatalf("accessors: got %s/%s", ob.Scheme(), ob.Encoding())
	}
	if ob.Format().String() != "aasv.c32" {
		t.Errorf("Format().String() = %q", ob.Format().String())
	}

	if err := ob.SetEncoding(EncodingB64); err != nil || ob.Encoding() != EncodingB64 {
		t.Errorf("SetEncoding: err=%v enc=%s", err, ob.Encoding())
	}
	if err := ob.SetScheme(SchemeApsv); err != nil || ob.Scheme() != SchemeApsv {
		t.Errorf("SetScheme: err=%v scheme=%s", err, ob.Scheme())
	}
	if err := ob.SetScheme(SchemeZrbcx); err != ErrInvalidFormat {
		t.Errorf("SetScheme(zrbcx) error = %v, want ErrInvalidFormat", err)
	}
	if err := ob.SetFormat("aags.hex"); err != nil || ob.Format().String() != "aags.hex" {
		t.Errorf("SetFormat: err=%v fmt=%s", err, ob.Format().String())
	}
}

// TestEmptyPlaintextRejected verifies enc rejects empty input (spec §4.1).
func TestEmptyPlaintextRejected(t *testing.T) {
	ob, _ := NewObKeyless("aasv.c32")
	if _, err := ob.Enc(""); err != ErrEmptyString {
		t.Errorf("Enc(\"\") error = %v, want ErrEmptyString", err)
	}
}

// TestFixedTypes round-trips a representative fixed type per scheme and verifies
// the baked-in format.
func TestFixedTypes(t *testing.T) {
	key := GenerateKey()

	aasv, err := NewAasvC32(key)
	if err != nil {
		t.Fatalf("NewAasvC32 failed: %v", err)
	}
	if aasv.Format().String() != "aasv.c32" {
		t.Errorf("AasvC32 format = %q", aasv.Format().String())
	}
	ot, err := aasv.Enc("fixed type")
	if err != nil {
		t.Fatalf("Enc failed: %v", err)
	}
	if pt, _ := aasv.Dec(ot); pt != "fixed type" {
		t.Errorf("AasvC32 roundtrip: got %q", pt)
	}

	hexCodec, _ := NewUpbcHex(key)
	if hexCodec.Encoding() != EncodingHex {
		t.Errorf("UpbcHex encoding = %s", hexCodec.Encoding())
	}
}

// TestCodecInterface verifies *Ob and the fixed types satisfy Codec.
func TestCodecInterface(t *testing.T) {
	key := GenerateKey()
	ob, _ := New("aasv.c32", key)
	aasv, _ := NewAasvC32(key)
	var codecs []Codec = []Codec{ob, aasv}
	for _, c := range codecs {
		ot, err := c.Enc("via interface")
		if err != nil {
			t.Fatalf("Enc via Codec failed: %v", err)
		}
		if pt, _ := c.Dec(ot); pt != "via interface" {
			t.Errorf("Codec roundtrip: got %q", pt)
		}
	}
}

// TestGenerateKey verifies GenerateKey produces a usable 128-hex master key.
func TestGenerateKey(t *testing.T) {
	key := GenerateKey()
	if len(key) != 128 {
		t.Fatalf("GenerateKey len = %d, want 128", len(key))
	}
	if _, err := New("aasv.c32", key); err != nil {
		t.Errorf("generated key rejected by New: %v", err)
	}
}
