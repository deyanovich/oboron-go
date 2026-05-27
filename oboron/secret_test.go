package oboron

import (
	"encoding/hex"
	"testing"
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
	tests := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"too_short_16", 16},
		{"too_long_33", 33},
		{"too_long_64", 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewSecret(make([]byte, tt.size))
			if err != ErrInvalidSecretLength {
				t.Errorf("NewSecret(%d bytes) error = %v, want ErrInvalidSecretLength", tt.size, err)
			}
		})
	}
}

func TestSecretFromHex(t *testing.T) {
	secretBytes := HardcodedSecret().Bytes()
	secretHex := hex.EncodeToString(secretBytes)

	s, err := SecretFromHex(secretHex)
	if err != nil {
		t.Fatalf("SecretFromHex failed: %v", err)
	}

	got := s.Bytes()
	for i := range got {
		if got[i] != secretBytes[i] {
			t.Errorf("Bytes()[%d] = %02x, want %02x", i, got[i], secretBytes[i])
		}
	}
}

func TestSecretFromHexInvalid(t *testing.T) {
	tests := []struct {
		name string
		hex  string
	}{
		{"too_short", "abcd"},
		{"too_long", hex.EncodeToString(make([]byte, 33))},
		{"invalid_chars", "zzzz" + hex.EncodeToString(make([]byte, 30))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SecretFromHex(tt.hex)
			if err == nil {
				t.Errorf("SecretFromHex(%q) expected error, got nil", tt.hex)
			}
		})
	}
}

func TestSecretHex(t *testing.T) {
	s := HardcodedSecret()
	gotHex := s.Hex()
	expectedHex := hex.EncodeToString(HardcodedKey[:SecretSize])
	if gotHex != expectedHex {
		t.Errorf("Hex() = %q, want %q", gotHex, expectedHex)
	}
}

func TestSecretBytesCopy(t *testing.T) {
	s := HardcodedSecret()

	// Modify the returned bytes - should not affect the internal secret
	got := s.Bytes()
	got[0] = 0xFF

	got2 := s.Bytes()
	if got2[0] == 0xFF {
		t.Error("Bytes() should return a copy, not a reference to internal state")
	}
}

func TestHardcodedSecret(t *testing.T) {
	s := HardcodedSecret()
	if s == nil {
		t.Fatal("HardcodedSecret() returned nil")
	}

	got := s.Bytes()
	for i := range got {
		if got[i] != HardcodedKey[i] {
			t.Errorf("HardcodedSecret().Bytes()[%d] = %02x, want %02x", i, got[i], HardcodedKey[i])
		}
	}
}

func TestSecretFromMasterKey(t *testing.T) {
	mk := HardcodedMasterKey()
	s, err := SecretFromMasterKey(mk)
	if err != nil {
		t.Fatalf("SecretFromMasterKey failed: %v", err)
	}

	// Should be first 32 bytes of MasterKey
	mkBytes := mk.Bytes()
	sBytes := s.Bytes()
	for i := range sBytes {
		if sBytes[i] != mkBytes[i] {
			t.Errorf("SecretFromMasterKey().Bytes()[%d] = %02x, want %02x", i, sBytes[i], mkBytes[i])
		}
	}
}

func TestSecretFromMasterKeyZeroized(t *testing.T) {
	mk := HardcodedMasterKey()
	mk.Zeroize()

	_, err := SecretFromMasterKey(mk)
	if err != ErrMasterKeyZeroized {
		t.Errorf("Expected ErrMasterKeyZeroized, got %v", err)
	}
}

func TestSecretZTierSchemes(t *testing.T) {
	s := HardcodedSecret()

	tests := []struct {
		name   string
		create func(*Secret) (*Oboron, error)
		scheme Scheme
	}{
		{"legacy", NewLegacyFromSecret, SchemeLegacy},
		{"zrbcx", NewZrbcxFromSecret, SchemeZrbcx},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ob, err := tt.create(s)
			if err != nil {
				t.Fatalf("Constructor failed: %v", err)
			}
			if ob.Scheme() != tt.scheme {
				t.Errorf("Scheme() = %q, want %q", ob.Scheme(), tt.scheme)
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
				t.Errorf("Roundtrip failed: got %q, want %q", decoded, "test")
			}
		})
	}
}

func TestSecretCompatibleWithRawKey(t *testing.T) {
	// Z-tier schemes only use first 32 bytes, so Secret-based and raw-key (64-byte)
	// constructors should produce the same results when the last 32 bytes are zero
	s := HardcodedSecret()

	// Build a 64-byte key with the same first 32 bytes and zeros for the rest
	key := make([]byte, 64)
	copy(key, s.Bytes())

	fromSecret, err := NewZrbcxFromSecret(s)
	if err != nil {
		t.Fatalf("NewZrbcxFromSecret failed: %v", err)
	}

	fromRawKey, err := NewZrbcx(key)
	if err != nil {
		t.Fatalf("NewZrbcx failed: %v", err)
	}

	input := "hello"
	secretEncoded, _ := fromSecret.Encode(input)
	rawEncoded, _ := fromRawKey.Encode(input)

	if secretEncoded != rawEncoded {
		t.Errorf("Secret encode %q != raw key encode %q", secretEncoded, rawEncoded)
	}
}

func TestOmnibFromSecret(t *testing.T) {
	s := HardcodedSecret()

	g, err := NewOmnibFromSecret(s)
	if err != nil {
		t.Fatalf("NewOmnibFromSecret failed: %v", err)
	}

	// Test z-tier scheme roundtrip
	encoded, err := g.EncodeZrbcx("test")
	if err != nil {
		t.Fatalf("EncodeZrbcx failed: %v", err)
	}
	decoded, err := g.DecodeZrbcx(encoded)
	if err != nil {
		t.Fatalf("DecodeZrbcx failed: %v", err)
	}
	if decoded != "test" {
		t.Errorf("Roundtrip failed: got %q, want %q", decoded, "test")
	}
}

func TestOmnibFromMasterKey(t *testing.T) {
	mk := HardcodedMasterKey()

	g, err := NewOmnibFromMasterKey(mk)
	if err != nil {
		t.Fatalf("NewOmnibFromMasterKey failed: %v", err)
	}

	// Test a-tier scheme roundtrip
	encoded, err := g.EncodeAags("test")
	if err != nil {
		t.Fatalf("EncodeAags failed: %v", err)
	}
	decoded, err := g.DecodeAags(encoded)
	if err != nil {
		t.Fatalf("DecodeAags failed: %v", err)
	}
	if decoded != "test" {
		t.Errorf("Roundtrip failed: got %q, want %q", decoded, "test")
	}
}

func TestTierConstants(t *testing.T) {
	if TierA != 1 {
		t.Errorf("TierA = %d, want 1", TierA)
	}
	if TierU != 2 {
		t.Errorf("TierU = %d, want 2", TierU)
	}
	if TierZ != 6 {
		t.Errorf("TierZ = %d, want 6", TierZ)
	}
}

func TestSizeConstants(t *testing.T) {
	if MasterKeySize != 64 {
		t.Errorf("MasterKeySize = %d, want 64", MasterKeySize)
	}
	if SecretSize != 32 {
		t.Errorf("SecretSize = %d, want 32", SecretSize)
	}
}
