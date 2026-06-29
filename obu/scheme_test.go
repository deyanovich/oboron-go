package obu

import (
	"testing"

	"oboron.org/go/oboron"
)

// TestObuRoundtrip exercises Enc/Dec for the obu schemes via Omnibu.
func TestObuRoundtrip(t *testing.T) {
	om, _ := NewOmnibuKeyless()
	for _, format := range []string{
		"upcbc.c32", "upcbc.b32", "upcbc.b64", "upcbc.hex",
		"zdcbc.c32", "zdcbc.b32", "zdcbc.b64", "zdcbc.hex",
	} {
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

// TestZdcbcDeterministic verifies zdcbc is deterministic.
func TestZdcbcDeterministic(t *testing.T) {
	om, _ := NewOmnibuKeyless()
	a, _ := om.Enc("stable", "zdcbc.c32")
	b, _ := om.Enc("stable", "zdcbc.c32")
	if a != b {
		t.Errorf("zdcbc not deterministic: %q != %q", a, b)
	}
}

// TestUpcbcProbabilistic verifies upcbc produces fresh ciphertext per call.
func TestUpcbcProbabilistic(t *testing.T) {
	om, _ := NewOmnibuKeyless()
	a, _ := om.Enc("varies", "upcbc.c32")
	b, _ := om.Enc("varies", "upcbc.c32")
	if a == b {
		t.Errorf("upcbc produced identical output for two calls")
	}
}

// TestUpcbcRejectsPadByteTail verifies a plaintext ending in 0x01 is rejected
// (the pad byte would be indistinguishable on decode).
func TestUpcbcRejectsPadByteTail(t *testing.T) {
	om, _ := NewOmnibuKeyless()
	if _, err := om.Enc("ok\x01", "upcbc.c32"); err == nil {
		t.Error("Enc(plaintext ending in 0x01) expected error, got nil")
	}
}

// TestObuRejectsAuthScheme verifies the obu constructors reject authenticated
// formats.
func TestObuRejectsAuthScheme(t *testing.T) {
	secret := oboron.GenerateSecret()
	for _, format := range []string{"dsiv.c32", "dgcmsiv.b32"} {
		if _, err := NewObu(format, secret); err != oboron.ErrInvalidFormat {
			t.Errorf("NewObu(%q) error = %v, want ErrInvalidFormat", format, err)
		}
	}
}

// TestObuAccessorsAndSetters covers Obu's accessors and runtime setters.
func TestObuAccessorsAndSetters(t *testing.T) {
	ob, err := NewObu("zdcbc.c32", oboron.GenerateSecret())
	if err != nil {
		t.Fatalf("NewObu failed: %v", err)
	}
	if ob.Scheme() != oboron.SchemeZdcbc || ob.Encoding() != oboron.EncodingC32 {
		t.Fatalf("accessors: got %s/%s", ob.Scheme(), ob.Encoding())
	}
	if err := ob.SetEncoding(oboron.EncodingHex); err != nil || ob.Encoding() != oboron.EncodingHex {
		t.Errorf("SetEncoding: err=%v enc=%s", err, ob.Encoding())
	}
	if err := ob.SetScheme(oboron.SchemeDsiv); err != oboron.ErrInvalidFormat {
		t.Errorf("SetScheme(dsiv) error = %v, want ErrInvalidFormat", err)
	}
	if err := ob.SetScheme(oboron.SchemeUpcbc); err != nil || ob.Scheme() != oboron.SchemeUpcbc {
		t.Errorf("SetScheme(upcbc): err=%v scheme=%s", err, ob.Scheme())
	}
}

// TestObuFixedTypes round-trips the obu fixed types and verifies Codec.
func TestObuFixedTypes(t *testing.T) {
	secret := oboron.GenerateSecret()

	z, err := NewZdcbcC32(secret)
	if err != nil {
		t.Fatalf("NewZdcbcC32 failed: %v", err)
	}
	if z.Format().String() != "zdcbc.c32" {
		t.Errorf("ZdcbcC32 format = %q", z.Format().String())
	}
	ot, _ := z.Enc("fixed z")
	if pt, _ := z.Dec(ot); pt != "fixed z" {
		t.Errorf("ZdcbcC32 roundtrip: got %q", pt)
	}

	u, err := NewUpcbcC32(secret)
	if err != nil {
		t.Fatalf("NewUpcbcC32 failed: %v", err)
	}
	if u.Format().String() != "upcbc.c32" || u.Scheme() != oboron.SchemeUpcbc {
		t.Errorf("UpcbcC32 format = %q scheme = %s", u.Format().String(), u.Scheme())
	}
	ot2, _ := u.Enc("upcbc fixed")
	if pt, _ := u.Dec(ot2); pt != "upcbc fixed" {
		t.Errorf("UpcbcC32 roundtrip: got %q", pt)
	}

	// Fixed types satisfy oboron.Codec.
	var _ oboron.Codec = z
	var _ oboron.Codec = u
}

// TestEmptyPlaintextRejected verifies enc rejects empty input (spec §4.1).
func TestEmptyPlaintextRejected(t *testing.T) {
	z, _ := NewZdcbcC32Keyless()
	if _, err := z.Enc(""); err != oboron.ErrEmptyString {
		t.Errorf("Enc(\"\") error = %v, want ErrEmptyString", err)
	}
}

func BenchmarkObuEnc(b *testing.B) {
	om, _ := NewOmnibuKeyless()
	for _, format := range []string{"upcbc.c32", "zdcbc.c32"} {
		b.Run(format, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := om.Enc("hello, world", format); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
