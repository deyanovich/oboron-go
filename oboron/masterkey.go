package oboron

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"oboron.org/go/obcrypt"
)

// MasterKeyBase64Len is the number of base64url-nopad characters for a 512-bit key (86 chars).
const MasterKeyBase64Len = obcrypt.KeyBase64Len

// MasterKeySize is the size of a MasterKey in bytes (512 bits).
const MasterKeySize = obcrypt.KeySize

// MasterKey holds a 512-bit (64-byte) key for the secure a-tier/u-tier schemes
// (aags, aasv, apgs, apsv, upbc). It is the crypto-core key type, defined in
// the obcrypt package; this alias keeps the oboron-level name. MasterKey
// supports in-memory zeroization (see Zeroize) and exposes hex (canonical),
// base64 (deprecated), and raw-byte forms.
type MasterKey = obcrypt.Key

// NewMasterKey creates a MasterKey from a 64-byte slice.
// Returns ErrInvalidMasterKeyLength if the slice is not exactly 64 bytes.
func NewMasterKey(key []byte) (*MasterKey, error) {
	if len(key) != MasterKeySize {
		return nil, ErrInvalidMasterKeyLength
	}
	return obcrypt.NewKey(key)
}

// MasterKeyFromHex creates a MasterKey from a 128-character hex string.
func MasterKeyFromHex(keyHex string) (*MasterKey, error) {
	if len(keyHex) != MasterKeySize*2 {
		return nil, fmt.Errorf("master key hex must be %d characters, got %d", MasterKeySize*2, len(keyHex))
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid master key hex: %w", err)
	}
	return NewMasterKey(key)
}

// MasterKeyFromBase64 creates a MasterKey from an 86-character base64url-nopad string.
//
// Deprecated: base64 keys are a legacy format; use MasterKeyFromHex for the
// canonical representation (spec §3.2).
func MasterKeyFromBase64(keyB64 string) (*MasterKey, error) {
	if len(keyB64) != MasterKeyBase64Len {
		return nil, fmt.Errorf("master key base64url must be %d characters, got %d", MasterKeyBase64Len, len(keyB64))
	}
	key, err := base64.RawURLEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("invalid master key base64url: %w", err)
	}
	return NewMasterKey(key)
}

// MasterKeyFromString creates a MasterKey from a textual key, auto-detecting
// the encoding by length (spec §3.4): 128 characters → hex (the canonical
// format, see spec §3.2); 86 characters → base64url-nopad (deprecated,
// accepted for backward compatibility only).
func MasterKeyFromString(key string) (*MasterKey, error) {
	switch len(key) {
	case MasterKeySize * 2: // 128 hex chars (canonical)
		return MasterKeyFromHex(key)
	case MasterKeyBase64Len: // 86 base64url chars (deprecated)
		return MasterKeyFromBase64(key)
	default:
		return nil, fmt.Errorf("master key must be %d hex chars or %d base64url chars, got %d",
			MasterKeySize*2, MasterKeyBase64Len, len(key))
	}
}
