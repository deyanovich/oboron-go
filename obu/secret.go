// Package obu is the unauthenticated / obfuscation layer of oboron, mirroring
// the Rust reference's `obu` crate. The obu schemes (upcbc, zdcbc) are NOT
// authenticated encryption:
//
//   - upcbc provides confidentiality only (AES-256-CBC, no integrity); pair it
//     with an outer authenticator if you need tamper-detection;
//   - zdcbc provides reversible obfuscation only.
//
// Both are keyed by a 256-bit Secret rather than the authenticated layer's
// 512-bit master key. This package is kept separate from the main oboron
// package: oboron never imports obu, and the obu crypto lives here, not there.
//
// Use the authenticated API in package oboron for anything requiring
// confidentiality and integrity.
package obu

import (
	"encoding/hex"
	"fmt"

	"oboron.org/go/oboron"
)

// SecretSize is the size of a Secret in bytes (256 bits).
const SecretSize = 32

// Secret holds a 256-bit (32-byte) key for the obu schemes (upcbc, zdcbc).
// Unlike the authenticated MasterKey, Secret does not perform automatic
// zeroization, matching obu's design as a non-authenticated layer. Its
// canonical text form is hex (64 characters); there is no base64 form.
type Secret struct {
	secret [SecretSize]byte
}

// NewSecret creates a Secret from a 32-byte slice.
// Returns oboron.ErrInvalidSecretLength if the slice is not exactly 32 bytes.
func NewSecret(secret []byte) (*Secret, error) {
	if len(secret) != SecretSize {
		return nil, oboron.ErrInvalidSecretLength
	}
	s := &Secret{}
	copy(s.secret[:], secret)
	return s, nil
}

// SecretFromHex creates a Secret from a 64-character hex string.
func SecretFromHex(secretHex string) (*Secret, error) {
	if len(secretHex) != SecretSize*2 {
		return nil, fmt.Errorf("secret hex must be %d characters, got %d", SecretSize*2, len(secretHex))
	}
	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		return nil, fmt.Errorf("invalid secret hex: %w", err)
	}
	// Canonical secret hex is lowercase (spec §3, §6.1); reject uppercase.
	if hex.EncodeToString(secret) != secretHex {
		return nil, fmt.Errorf("secret hex must be lowercase")
	}
	return NewSecret(secret)
}

// SecretFromString creates a Secret from a textual secret. Hex is the only
// accepted form: 64 hex characters. Anything else is an error.
func SecretFromString(secret string) (*Secret, error) {
	if len(secret) != SecretSize*2 {
		return nil, fmt.Errorf("secret must be %d hex chars, got %d", SecretSize*2, len(secret))
	}
	return SecretFromHex(secret)
}

// SecretFromMasterKey derives a Secret from an authenticated MasterKey by taking
// its first 32 bytes. A convenience for tooling that holds a master key and
// wants a matching obu secret.
func SecretFromMasterKey(mk *oboron.MasterKey) (*Secret, error) {
	if mk.IsZeroized() {
		return nil, oboron.ErrMasterKeyZeroized
	}
	return NewSecret(mk.Bytes()[:SecretSize])
}

// HardcodedSecret returns a Secret derived from the first 32 bytes of the
// shared hardcoded key (testing only — NOT SECURE).
func HardcodedSecret() *Secret {
	s, _ := NewSecret(oboron.HardcodedKey[:SecretSize])
	return s
}

// Bytes returns a copy of the secret material.
func (s *Secret) Bytes() []byte {
	out := make([]byte, SecretSize)
	copy(out, s.secret[:])
	return out
}

// Hex returns the secret as a 64-character hex string. Hex is the canonical
// secret encoding.
func (s *Secret) Hex() string {
	return hex.EncodeToString(s.secret[:])
}
