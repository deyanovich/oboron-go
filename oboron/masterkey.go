package oboron

import (
	"encoding/hex"
	"fmt"

	"oboron.org/go/obcrypt"
)

// MasterKeySize is the size of a MasterKey in bytes (512 bits).
const MasterKeySize = obcrypt.KeySize

// MasterKey holds a 512-bit (64-byte) key for the authenticated schemes
// (dgcmsiv, dsiv, pgcmsiv, psiv). It is the crypto-core key type, defined in
// the obcrypt package; this alias keeps the oboron-level name. MasterKey
// supports in-memory zeroization (see Zeroize). Its canonical text form is hex
// (128 characters); there is no base64 form.
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
	// Canonical key hex is lowercase (spec §3.3); reject uppercase.
	if hex.EncodeToString(key) != keyHex {
		return nil, fmt.Errorf("master key hex must be lowercase")
	}
	return NewMasterKey(key)
}

// MasterKeyFromString creates a MasterKey from a textual key. Hex is the only
// accepted form: 128 hex characters (spec §3.2). Anything else is an error.
func MasterKeyFromString(key string) (*MasterKey, error) {
	if len(key) != MasterKeySize*2 {
		return nil, fmt.Errorf("master key must be %d hex chars, got %d", MasterKeySize*2, len(key))
	}
	return MasterKeyFromHex(key)
}
