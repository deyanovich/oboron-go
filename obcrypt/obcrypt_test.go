package obcrypt

import (
	"bytes"
	"testing"
)

var allSchemes = []Scheme{Dsiv, Psiv, Dgcmsiv, Pgcmsiv}

func testKey(t *testing.T) *Key {
	t.Helper()
	k := HardcodedKey()
	if k == nil {
		t.Fatal("HardcodedKey() returned nil")
	}
	return k
}

// TestRoundtrip checks Encrypt → Decrypt for every scheme over a range of
// plaintext lengths.
func TestRoundtrip(t *testing.T) {
	key := testKey(t)
	inputs := [][]byte{
		[]byte("a"),
		[]byte("hello"),
		[]byte("the quick brown fox jumps over the lazy dog"),
		[]byte("日本語"),
		bytes.Repeat([]byte{0x00}, 64),
		bytes.Repeat([]byte{0xff}, 100),
	}

	for _, scheme := range allSchemes {
		for _, in := range inputs {
			payload, err := Encrypt(in, scheme, key)
			if err != nil {
				t.Fatalf("Encrypt(%s, %q) failed: %v", scheme, in, err)
			}

			got, err := Decrypt(payload, scheme, key)
			if err != nil {
				t.Fatalf("Decrypt(%s, %q) failed: %v", scheme, in, err)
			}
			if !bytes.Equal(got, in) {
				t.Errorf("Decrypt(%s) = %q, want %q", scheme, got, in)
			}
		}
	}
}

// TestDeterminism verifies the deterministic schemes produce identical
// payloads and the probabilistic ones do not.
func TestDeterminism(t *testing.T) {
	key := testKey(t)
	pt := []byte("repeatable")

	for _, tc := range []struct {
		scheme        Scheme
		deterministic bool
	}{
		{Dsiv, true},
		{Dgcmsiv, true},
		{Psiv, false},
		{Pgcmsiv, false},
	} {
		a, _ := Encrypt(pt, tc.scheme, key)
		b, _ := Encrypt(pt, tc.scheme, key)
		equal := bytes.Equal(a, b)
		if equal != tc.deterministic {
			t.Errorf("%s: byte-equal=%v, want deterministic=%v", tc.scheme, equal, tc.deterministic)
		}
	}
}

// TestDecryptWrongScheme verifies Decrypt with the wrong scheme fails the AEAD
// tag check.
func TestDecryptWrongScheme(t *testing.T) {
	key := testKey(t)
	payload, err := Encrypt([]byte("hello"), Dsiv, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if _, err := Decrypt(payload, Psiv, key); err != ErrDecryptionFailed {
		t.Errorf("Decrypt(wrong scheme) error = %v, want ErrDecryptionFailed", err)
	}
}

// TestTamperDetection verifies the authenticated schemes reject tampered input.
func TestTamperDetection(t *testing.T) {
	key := testKey(t)
	for _, scheme := range []Scheme{Dsiv, Psiv, Dgcmsiv, Pgcmsiv} {
		payload, _ := Encrypt([]byte("authenticated"), scheme, key)
		// Flip a bit in the first byte.
		payload[0] ^= 0x01
		if _, err := Decrypt(payload, scheme, key); err != ErrDecryptionFailed {
			t.Errorf("%s: tampered payload error = %v, want ErrDecryptionFailed", scheme, err)
		}
	}
}

func TestEmptyPlaintextRejected(t *testing.T) {
	key := testKey(t)
	if _, err := Encrypt(nil, Dsiv, key); err != ErrEmptyPlaintext {
		t.Errorf("Encrypt(empty) error = %v, want ErrEmptyPlaintext", err)
	}
}

func TestKeyHexRoundtrip(t *testing.T) {
	key := testKey(t)
	h := key.Hex()
	if len(h) != KeySize*2 {
		t.Fatalf("Hex() length = %d, want %d", len(h), KeySize*2)
	}
	k2, err := KeyFromHex(h)
	if err != nil {
		t.Fatalf("KeyFromHex failed: %v", err)
	}
	if !bytes.Equal(k2.Bytes(), key.Bytes()) {
		t.Error("KeyFromHex(key.Hex()) did not round-trip")
	}
}

func TestNewKeyInvalidLength(t *testing.T) {
	for _, n := range []int{0, 16, 32, 63, 65, 128} {
		if _, err := NewKey(make([]byte, n)); err != ErrInvalidKeyLength {
			t.Errorf("NewKey(%d bytes) error = %v, want ErrInvalidKeyLength", n, err)
		}
	}
}

func TestZeroize(t *testing.T) {
	key := testKey(t)
	key.Zeroize()
	if !key.IsZeroized() {
		t.Error("IsZeroized() = false after Zeroize()")
	}
	if key.Bytes() != nil {
		t.Error("Bytes() should be nil after Zeroize()")
	}
	if key.Hex() != "" {
		t.Error("Hex() should be empty after Zeroize()")
	}
	if _, err := Encrypt([]byte("x"), Dsiv, key); err != ErrKeyZeroized {
		t.Errorf("Encrypt with zeroized key error = %v, want ErrKeyZeroized", err)
	}
}
