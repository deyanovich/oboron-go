package oboron

import (
	"encoding/hex"
	"runtime"
	"testing"
)

func TestNewMasterKey(t *testing.T) {
	key := make([]byte, MasterKeySize)
	for i := range key {
		key[i] = byte(i)
	}

	mk, err := NewMasterKey(key)
	if err != nil {
		t.Fatalf("NewMasterKey failed: %v", err)
	}

	got := mk.Bytes()
	if len(got) != MasterKeySize {
		t.Fatalf("Bytes() returned %d bytes, want %d", len(got), MasterKeySize)
	}

	for i := range got {
		if got[i] != byte(i) {
			t.Errorf("Bytes()[%d] = %d, want %d", i, got[i], i)
		}
	}
}

func TestNewMasterKeyInvalidLength(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"too_short_16", 16},
		{"too_short_32", 32},
		{"too_long_65", 65},
		{"too_long_128", 128},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewMasterKey(make([]byte, tt.size))
			if err != ErrInvalidMasterKeyLength {
				t.Errorf("NewMasterKey(%d bytes) error = %v, want ErrInvalidMasterKeyLength", tt.size, err)
			}
		})
	}
}

func TestMasterKeyFromHex(t *testing.T) {
	// Use HardcodedKey as the source
	keyHex := hex.EncodeToString(HardcodedKey)
	mk, err := MasterKeyFromHex(keyHex)
	if err != nil {
		t.Fatalf("MasterKeyFromHex failed: %v", err)
	}

	got := mk.Bytes()
	for i := range got {
		if got[i] != HardcodedKey[i] {
			t.Errorf("Bytes()[%d] = %02x, want %02x", i, got[i], HardcodedKey[i])
		}
	}
}

func TestMasterKeyFromHexInvalid(t *testing.T) {
	tests := []struct {
		name string
		hex  string
	}{
		{"too_short", "abcd"},
		{"too_long", hex.EncodeToString(make([]byte, 65))},
		{"invalid_chars", "zzzz" + hex.EncodeToString(make([]byte, 62))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := MasterKeyFromHex(tt.hex)
			if err == nil {
				t.Errorf("MasterKeyFromHex(%q) expected error, got nil", tt.hex)
			}
		})
	}
}

func TestMasterKeyHex(t *testing.T) {
	mk, err := NewMasterKey(HardcodedKey)
	if err != nil {
		t.Fatalf("NewMasterKey failed: %v", err)
	}

	gotHex := mk.Hex()
	expectedHex := hex.EncodeToString(HardcodedKey)
	if gotHex != expectedHex {
		t.Errorf("Hex() = %q, want %q", gotHex, expectedHex)
	}
}

func TestMasterKeyZeroize(t *testing.T) {
	mk, err := NewMasterKey(HardcodedKey)
	if err != nil {
		t.Fatalf("NewMasterKey failed: %v", err)
	}

	// Before zeroize
	if mk.IsZeroized() {
		t.Error("IsZeroized() should be false before Zeroize()")
	}

	mk.Zeroize()

	// After zeroize
	if !mk.IsZeroized() {
		t.Error("IsZeroized() should be true after Zeroize()")
	}

	if mk.Bytes() != nil {
		t.Error("Bytes() should return nil after Zeroize()")
	}

	if mk.Hex() != "" {
		t.Error("Hex() should return empty string after Zeroize()")
	}
}

func TestMasterKeyZeroizeIdempotent(t *testing.T) {
	mk, err := NewMasterKey(HardcodedKey)
	if err != nil {
		t.Fatalf("NewMasterKey failed: %v", err)
	}

	// Calling Zeroize multiple times should not panic
	mk.Zeroize()
	mk.Zeroize()
	mk.Zeroize()

	if !mk.IsZeroized() {
		t.Error("IsZeroized() should be true")
	}
}

func TestMasterKeyFinalizerRegistered(t *testing.T) {
	// Create a MasterKey and let it go out of scope
	// The finalizer should be set (we can't easily test it fires, but we can
	// test that GC doesn't panic)
	mk, err := NewMasterKey(HardcodedKey)
	if err != nil {
		t.Fatalf("NewMasterKey failed: %v", err)
	}

	// Use mk to prevent early collection
	_ = mk.Bytes()
	mk = nil

	// Force GC to run the finalizer
	runtime.GC()
	runtime.GC()
}

func TestMasterKeyBytesCopy(t *testing.T) {
	mk, err := NewMasterKey(HardcodedKey)
	if err != nil {
		t.Fatalf("NewMasterKey failed: %v", err)
	}

	// Modify the returned bytes - should not affect the internal key
	got := mk.Bytes()
	got[0] = 0xFF

	got2 := mk.Bytes()
	if got2[0] == 0xFF {
		t.Error("Bytes() should return a copy, not a reference to internal state")
	}
}

func TestHardcodedMasterKey(t *testing.T) {
	mk := HardcodedMasterKey()
	if mk == nil {
		t.Fatal("HardcodedMasterKey() returned nil")
	}

	got := mk.Bytes()
	for i := range got {
		if got[i] != HardcodedKey[i] {
			t.Errorf("HardcodedMasterKey().Bytes()[%d] = %02x, want %02x", i, got[i], HardcodedKey[i])
		}
	}
}

func TestMasterKeySecureSchemes(t *testing.T) {
	key := HardcodedMasterKey().Hex()

	tests := []struct {
		format string
		scheme Scheme
	}{
		{"dgcmsiv.b32", SchemeDgcmsiv},
		{"dsiv.b32", SchemeDsiv},
		{"pgcmsiv.b32", SchemePgcmsiv},
		{"psiv.b32", SchemePsiv},
	}

	for _, tt := range tests {
		t.Run(string(tt.scheme), func(t *testing.T) {
			ob, err := New(tt.format, key)
			if err != nil {
				t.Fatalf("New(%q) failed: %v", tt.format, err)
			}
			if ob.Scheme() != tt.scheme {
				t.Errorf("Scheme() = %q, want %q", ob.Scheme(), tt.scheme)
			}

			encoded, err := ob.Enc("test")
			if err != nil {
				t.Fatalf("Enc failed: %v", err)
			}
			decoded, err := ob.Dec(encoded)
			if err != nil {
				t.Fatalf("Dec failed: %v", err)
			}
			if decoded != "test" {
				t.Errorf("Roundtrip failed: got %q, want %q", decoded, "test")
			}
		})
	}
}

// TestMasterKeyConstructionParity verifies the hex-string and raw-bytes
// constructors (spec §4.2) produce identical output.
func TestMasterKeyConstructionParity(t *testing.T) {
	fromStr, err := New("dgcmsiv.b32", HardcodedMasterKey().Hex())
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	fromBytes, err := NewObFromBytes("dgcmsiv.b32", HardcodedKey)
	if err != nil {
		t.Fatalf("NewObFromBytes failed: %v", err)
	}

	input := "hello world"
	strEncoded, _ := fromStr.Enc(input)
	bytesEncoded, _ := fromBytes.Enc(input)
	if strEncoded != bytesEncoded {
		t.Errorf("hex-key encode %q != raw-bytes encode %q", strEncoded, bytesEncoded)
	}
}

func TestMasterKeySizeConstant(t *testing.T) {
	if MasterKeySize != 64 {
		t.Errorf("MasterKeySize = %d, want 64", MasterKeySize)
	}
}
