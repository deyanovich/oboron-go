package oboron

import (
	"testing"
)

var auSchemes = []Scheme{SchemeDgcmsiv, SchemeDsiv, SchemePgcmsiv, SchemePsiv}

// TestSchemeRoundtrip exercises Enc/Dec for every authenticated scheme via Omnib.
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

// TestDeterministicSchemes verifies deterministic schemes produce stable output
// and probabilistic ones vary.
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

// TestNewRejectsObu verifies the authenticated constructors reject obu formats.
func TestNewRejectsObu(t *testing.T) {
	key := GenerateKey()
	for _, format := range []string{"zdcbc.c32", "upcbc.b32"} {
		if _, err := New(format, key); err != ErrInvalidFormat {
			t.Errorf("New(%q) error = %v, want ErrInvalidFormat", format, err)
		}
	}
}

// TestNewStrictFormat verifies New requires an explicit encoding (no default).
func TestNewStrictFormat(t *testing.T) {
	key := GenerateKey()
	if _, err := New("dsiv", key); err != ErrInvalidFormat {
		t.Errorf("New(\"dsiv\") error = %v, want ErrInvalidFormat", err)
	}
	if _, err := New("dsiv.c32", key); err != nil {
		t.Errorf("New(\"dsiv.c32\") unexpected error: %v", err)
	}
}

// TestObAccessorsAndSetters covers Ob's format accessors and runtime setters.
func TestObAccessorsAndSetters(t *testing.T) {
	ob, err := New("dsiv.c32", GenerateKey())
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if ob.Scheme() != SchemeDsiv || ob.Encoding() != EncodingC32 {
		t.Fatalf("accessors: got %s/%s", ob.Scheme(), ob.Encoding())
	}
	if ob.Format().String() != "dsiv.c32" {
		t.Errorf("Format().String() = %q", ob.Format().String())
	}

	if err := ob.SetEncoding(EncodingB64); err != nil || ob.Encoding() != EncodingB64 {
		t.Errorf("SetEncoding: err=%v enc=%s", err, ob.Encoding())
	}
	if err := ob.SetScheme(SchemePsiv); err != nil || ob.Scheme() != SchemePsiv {
		t.Errorf("SetScheme: err=%v scheme=%s", err, ob.Scheme())
	}
	if err := ob.SetScheme(SchemeZdcbc); err != ErrInvalidFormat {
		t.Errorf("SetScheme(zdcbc) error = %v, want ErrInvalidFormat", err)
	}
	if err := ob.SetFormat("dgcmsiv.hex"); err != nil || ob.Format().String() != "dgcmsiv.hex" {
		t.Errorf("SetFormat: err=%v fmt=%s", err, ob.Format().String())
	}
}

// TestEmptyPlaintextRejected verifies enc rejects empty input (spec §4.1).
func TestEmptyPlaintextRejected(t *testing.T) {
	ob, _ := NewObKeyless("dsiv.c32")
	if _, err := ob.Enc(""); err != ErrEmptyString {
		t.Errorf("Enc(\"\") error = %v, want ErrEmptyString", err)
	}
}

// TestFixedTypes round-trips a representative fixed type per scheme and verifies
// the baked-in format.
func TestFixedTypes(t *testing.T) {
	key := GenerateKey()

	dsiv, err := NewDsivC32(key)
	if err != nil {
		t.Fatalf("NewDsivC32 failed: %v", err)
	}
	if dsiv.Format().String() != "dsiv.c32" {
		t.Errorf("DsivC32 format = %q", dsiv.Format().String())
	}
	ot, err := dsiv.Enc("fixed type")
	if err != nil {
		t.Fatalf("Enc failed: %v", err)
	}
	if pt, _ := dsiv.Dec(ot); pt != "fixed type" {
		t.Errorf("DsivC32 roundtrip: got %q", pt)
	}

	hexCodec, _ := NewPsivHex(key)
	if hexCodec.Encoding() != EncodingHex {
		t.Errorf("PsivHex encoding = %s", hexCodec.Encoding())
	}
}

// TestCodecInterface verifies *Ob and the fixed types satisfy Codec.
func TestCodecInterface(t *testing.T) {
	key := GenerateKey()
	ob, _ := New("dsiv.c32", key)
	dsiv, _ := NewDsivC32(key)
	var codecs []Codec = []Codec{ob, dsiv}
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
	if _, err := New("dsiv.c32", key); err != nil {
		t.Errorf("generated key rejected by New: %v", err)
	}
}
