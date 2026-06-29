package obu

import (
	"encoding/hex"
	"testing"

	"oboron.org/go/oboron"
)

func TestNewSecret(t *testing.T) {
	secret := make([]byte, SecretSize)
	for i := range secret {
		secret[i] = byte(i)
	}
	s, err := NewSecret(secret)
	if err != nil {
		t.Fatalf("NewSecret failed: %v", err)
	}
	got := s.Bytes()
	if len(got) != SecretSize {
		t.Fatalf("Bytes() returned %d bytes, want %d", len(got), SecretSize)
	}
	for i := range got {
		if got[i] != byte(i) {
			t.Errorf("Bytes()[%d] = %d, want %d", i, got[i], i)
		}
	}
}

func TestNewSecretInvalidLength(t *testing.T) {
	for _, tt := range []struct {
		name string
		size int
	}{
		{"empty", 0}, {"too_short_16", 16}, {"too_long_33", 33}, {"too_long_64", 64},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewSecret(make([]byte, tt.size)); err != oboron.ErrInvalidSecretLength {
				t.Errorf("NewSecret(%d bytes) error = %v, want ErrInvalidSecretLength", tt.size, err)
			}
		})
	}
}

func TestSecretFromHex(t *testing.T) {
	secretBytes := HardcodedSecret().Bytes()
	s, err := SecretFromHex(hex.EncodeToString(secretBytes))
	if err != nil {
		t.Fatalf("SecretFromHex failed: %v", err)
	}
	for i, b := range s.Bytes() {
		if b != secretBytes[i] {
			t.Errorf("Bytes()[%d] = %02x, want %02x", i, b, secretBytes[i])
		}
	}
}

func TestSecretFromHexInvalid(t *testing.T) {
	for _, tt := range []struct {
		name string
		hex  string
	}{
		{"too_short", "abcd"},
		{"too_long", hex.EncodeToString(make([]byte, 33))},
		{"invalid_chars", "zzzz" + hex.EncodeToString(make([]byte, 30))},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := SecretFromHex(tt.hex); err == nil {
				t.Errorf("SecretFromHex(%q) expected error, got nil", tt.hex)
			}
		})
	}
}

func TestSecretFromString(t *testing.T) {
	want := HardcodedSecret().Bytes()
	// Hex (64 chars) is the only accepted form.
	s, err := SecretFromString(HardcodedSecret().Hex())
	if err != nil {
		t.Fatalf("SecretFromString(hex) failed: %v", err)
	}
	if hex.EncodeToString(s.Bytes()) != hex.EncodeToString(want) {
		t.Errorf("SecretFromString(hex) mismatch")
	}
	if _, err := SecretFromString("tooshort"); err == nil {
		t.Error("SecretFromString(short) expected error")
	}
	// 43-char base64url is no longer accepted (hex-only).
	if _, err := SecretFromString("bhPDH_hhuTE4Kb2udezEI3qF8MaKnK5ItN7aPkjzxXc"); err == nil {
		t.Error("SecretFromString(base64) expected error (hex-only)")
	}
}

func TestSecretHex(t *testing.T) {
	got := HardcodedSecret().Hex()
	want := hex.EncodeToString(oboron.HardcodedKey[:SecretSize])
	if got != want {
		t.Errorf("Hex() = %q, want %q", got, want)
	}
}

func TestSecretBytesCopy(t *testing.T) {
	s := HardcodedSecret()
	got := s.Bytes()
	got[0] = 0xFF
	if s.Bytes()[0] == 0xFF {
		t.Error("Bytes() should return a copy, not a reference to internal state")
	}
}

func TestHardcodedSecret(t *testing.T) {
	s := HardcodedSecret()
	if s == nil {
		t.Fatal("HardcodedSecret() returned nil")
	}
	for i, b := range s.Bytes() {
		if b != oboron.HardcodedKey[i] {
			t.Errorf("HardcodedSecret().Bytes()[%d] = %02x, want %02x", i, b, oboron.HardcodedKey[i])
		}
	}
}

func TestSecretFromMasterKey(t *testing.T) {
	mk := oboron.HardcodedMasterKey()
	s, err := SecretFromMasterKey(mk)
	if err != nil {
		t.Fatalf("SecretFromMasterKey failed: %v", err)
	}
	mkBytes := mk.Bytes()
	for i, b := range s.Bytes() {
		if b != mkBytes[i] {
			t.Errorf("SecretFromMasterKey().Bytes()[%d] = %02x, want %02x", i, b, mkBytes[i])
		}
	}
}

func TestSecretFromMasterKeyZeroized(t *testing.T) {
	mk := oboron.HardcodedMasterKey()
	mk.Zeroize()
	if _, err := SecretFromMasterKey(mk); err != oboron.ErrMasterKeyZeroized {
		t.Errorf("Expected ErrMasterKeyZeroized, got %v", err)
	}
}

func TestSecretSizeConstant(t *testing.T) {
	if SecretSize != 32 {
		t.Errorf("SecretSize = %d, want 32", SecretSize)
	}
}
