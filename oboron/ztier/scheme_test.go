package ztier

import (
	"encoding/base32"
	"strings"
	"testing"

	"oboron.org/go/oboron"
)

// TestZtierRoundtrip exercises Enc/Dec for the z-tier schemes via Omnibz.
func TestZtierRoundtrip(t *testing.T) {
	om, _ := NewOmnibzKeyless()
	for _, format := range []string{"zrbcx.c32", "zrbcx.b32", "zrbcx.b64", "zrbcx.hex", "legacy"} {
		t.Run(format, func(t *testing.T) {
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

// TestZrbcxAutodetect verifies Omnibz.Autodec recovers a zrbcx obtext.
func TestZrbcxAutodetect(t *testing.T) {
	om, _ := NewOmnibzKeyless()
	for _, enc := range []string{"b32", "c32"} {
		ot, _ := om.Enc("detect zrbcx", "zrbcx."+enc)
		pt, err := om.Autodec(ot)
		if err != nil {
			t.Fatalf("Autodec(%s) failed: %v", enc, err)
		}
		if pt != "detect zrbcx" {
			t.Errorf("autodec: got %q", pt)
		}
	}
}

// TestZrbcxDeterministic verifies zrbcx is deterministic.
func TestZrbcxDeterministic(t *testing.T) {
	om, _ := NewOmnibzKeyless()
	a, _ := om.Enc("stable", "zrbcx.c32")
	b, _ := om.Enc("stable", "zrbcx.c32")
	if a != b {
		t.Errorf("zrbcx not deterministic: %q != %q", a, b)
	}
}

// TestZrbcxMarker verifies the appended 2-byte XOR marker for zrbcx.
func TestZrbcxMarker(t *testing.T) {
	om, _ := NewOmnibzKeyless()
	encoded, err := om.Enc("test", "zrbcx.b32")
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
	if recovered != zrbcxMarker {
		t.Errorf("marker mismatch: got %x, want %x", recovered, zrbcxMarker)
	}
	if recovered[0] != 0x06 || recovered[1] != 0x21 {
		t.Errorf("zrbcx marker = [%02x,%02x], want [06,21]", recovered[0], recovered[1])
	}
}

// TestObzRejectsAUTier verifies the z-tier constructors reject a/u formats.
func TestObzRejectsAUTier(t *testing.T) {
	secret := oboron.GenerateSecret()
	for _, format := range []string{"aasv.c32", "upbc.b32"} {
		if _, err := NewObz(format, secret); err != oboron.ErrInvalidFormat {
			t.Errorf("NewObz(%q) error = %v, want ErrInvalidFormat", format, err)
		}
	}
}

// TestObzAccessorsAndSetters covers Obz's accessors and runtime setters.
func TestObzAccessorsAndSetters(t *testing.T) {
	ob, err := NewObz("zrbcx.c32", oboron.GenerateSecret())
	if err != nil {
		t.Fatalf("NewObz failed: %v", err)
	}
	if ob.Scheme() != oboron.SchemeZrbcx || ob.Encoding() != oboron.EncodingC32 {
		t.Fatalf("accessors: got %s/%s", ob.Scheme(), ob.Encoding())
	}
	if err := ob.SetEncoding(oboron.EncodingHex); err != nil || ob.Encoding() != oboron.EncodingHex {
		t.Errorf("SetEncoding: err=%v enc=%s", err, ob.Encoding())
	}
	if err := ob.SetScheme(oboron.SchemeAasv); err != oboron.ErrInvalidFormat {
		t.Errorf("SetScheme(aasv) error = %v, want ErrInvalidFormat", err)
	}
	if err := ob.SetScheme(oboron.SchemeLegacy); err != nil || ob.Scheme() != oboron.SchemeLegacy {
		t.Errorf("SetScheme(legacy): err=%v scheme=%s", err, ob.Scheme())
	}
}

// TestZFixedTypes round-trips the z-tier fixed types and verifies Codec.
func TestZFixedTypes(t *testing.T) {
	secret := oboron.GenerateSecret()

	z, err := NewZrbcxC32(secret)
	if err != nil {
		t.Fatalf("NewZrbcxC32 failed: %v", err)
	}
	if z.Format().String() != "zrbcx.c32" {
		t.Errorf("ZrbcxC32 format = %q", z.Format().String())
	}
	ot, _ := z.Enc("fixed z")
	if pt, _ := z.Dec(ot); pt != "fixed z" {
		t.Errorf("ZrbcxC32 roundtrip: got %q", pt)
	}

	leg, err := NewLegacy(secret)
	if err != nil {
		t.Fatalf("NewLegacy failed: %v", err)
	}
	if leg.Format().String() != "legacy" || leg.Scheme() != oboron.SchemeLegacy {
		t.Errorf("Legacy format = %q scheme = %s", leg.Format().String(), leg.Scheme())
	}
	ot2, _ := leg.Enc("legacy fixed")
	if pt, _ := leg.Dec(ot2); pt != "legacy fixed" {
		t.Errorf("Legacy roundtrip: got %q", pt)
	}

	// Fixed types satisfy oboron.Codec.
	var _ oboron.Codec = z
	var _ oboron.Codec = leg
}

// TestEmptyPlaintextRejected verifies enc rejects empty input (spec §4.1).
func TestEmptyPlaintextRejected(t *testing.T) {
	z, _ := NewZrbcxC32Keyless()
	if _, err := z.Enc(""); err != oboron.ErrEmptyString {
		t.Errorf("Enc(\"\") error = %v, want ErrEmptyString", err)
	}
}

func BenchmarkZtierEnc(b *testing.B) {
	om, _ := NewOmnibzKeyless()
	for _, format := range []string{"zrbcx.c32", "legacy"} {
		b.Run(format, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := om.Enc("hello, world", format); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
