package obcrypt

import (
	"bytes"
	"testing"
)

var allSchemes = []Scheme{Aasv, Apsv, Aags, Apgs, Upbc}

func testKey(t *testing.T) *Key {
	t.Helper()
	k := HardcodedKey()
	if k == nil {
		t.Fatal("HardcodedKey() returned nil")
	}
	return k
}

// TestRoundtrip checks Encrypt → Decrypt and Encrypt → DecryptAs for every
// scheme over a range of plaintext lengths.
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

			got, err := Decrypt(payload, key)
			if err != nil {
				t.Fatalf("Decrypt(%s, %q) failed: %v", scheme, in, err)
			}
			if !bytes.Equal(got, in) {
				t.Errorf("Decrypt(%s) = %q, want %q", scheme, got, in)
			}

			gotAs, err := DecryptAs(payload, scheme, key)
			if err != nil {
				t.Fatalf("DecryptAs(%s, %q) failed: %v", scheme, in, err)
			}
			if !bytes.Equal(gotAs, in) {
				t.Errorf("DecryptAs(%s) = %q, want %q", scheme, gotAs, in)
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
		{Aasv, true},
		{Aags, true},
		{Apsv, false},
		{Apgs, false},
		{Upbc, false},
	} {
		a, _ := Encrypt(pt, tc.scheme, key)
		b, _ := Encrypt(pt, tc.scheme, key)
		equal := bytes.Equal(a, b)
		if equal != tc.deterministic {
			t.Errorf("%s: byte-equal=%v, want deterministic=%v", tc.scheme, equal, tc.deterministic)
		}
	}
}

// TestDecryptDetectsScheme verifies Decrypt recovers the right scheme from the
// marker, and DecryptAs rejects a mismatched scheme.
func TestDecryptWrongScheme(t *testing.T) {
	key := testKey(t)
	payload, err := Encrypt([]byte("hello"), Aasv, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	// DecryptAs with the wrong scheme must fail (marker mismatch).
	if _, err := DecryptAs(payload, Apsv, key); err != ErrDecryptionFailed {
		t.Errorf("DecryptAs(wrong scheme) error = %v, want ErrDecryptionFailed", err)
	}
}

// TestDecryptUnknownMarker verifies a payload whose marker is not an a/u marker
// yields ErrUnknownScheme (the signal oboron uses to try z-tier schemes).
func TestDecryptUnknownMarker(t *testing.T) {
	key := testKey(t)
	// A zrbcx-shaped marker {0x06,0x21} is not an obcrypt scheme.
	body := []byte("0123456789abcdef")
	payload := make([]byte, len(body)+MarkerSize)
	copy(payload, body)
	payload[len(payload)-2] = 0x06 ^ body[0]
	payload[len(payload)-1] = 0x21 ^ body[0]

	if _, err := Decrypt(payload, key); err != ErrUnknownScheme {
		t.Errorf("Decrypt(non-a/u marker) error = %v, want ErrUnknownScheme", err)
	}
}

// TestUpbcUnauthenticated documents that u-tier upbc is unauthenticated: a
// flipped ciphertext bit still decrypts (to different bytes) without error,
// whereas the a-tier schemes reject tampering.
func TestTamperDetection(t *testing.T) {
	key := testKey(t)
	for _, scheme := range []Scheme{Aasv, Apsv, Aags, Apgs} {
		payload, _ := Encrypt([]byte("authenticated"), scheme, key)
		// Flip a bit in the body (before the marker).
		payload[0] ^= 0x01
		if _, err := DecryptAs(payload, scheme, key); err != ErrDecryptionFailed {
			t.Errorf("%s: tampered payload error = %v, want ErrDecryptionFailed", scheme, err)
		}
	}
}

func TestEmptyPlaintextRejected(t *testing.T) {
	key := testKey(t)
	if _, err := Encrypt(nil, Aasv, key); err != ErrEmptyPlaintext {
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
	if _, err := Encrypt([]byte("x"), Aasv, key); err != ErrKeyZeroized {
		t.Errorf("Encrypt with zeroized key error = %v, want ErrKeyZeroized", err)
	}
}
