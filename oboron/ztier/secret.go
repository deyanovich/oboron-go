// Package ztier is the isolated z-tier (obfuscation) layer of oboron, mirroring
// the Rust reference's `oboron::ztier` module. The z-tier schemes (zrbcx,
// legacy) are NOT encryption — they provide reversible obfuscation only, keyed
// by a 256-bit Secret rather than the a/u-tier 512-bit master key. This package
// is kept entirely separate from the main oboron package: oboron never imports
// ztier, and the z-tier crypto lives here, not there.
//
// Use the secure a/u-tier API in package oboron for anything requiring
// confidentiality.
package ztier

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"oboron.org/go/oboron"
)

// SecretSize is the size of a Secret in bytes (256 bits).
const SecretSize = 32

// SecretBase64Len is the number of base64url-nopad characters for a 256-bit secret (43 chars).
const SecretBase64Len = 43

// Secret holds a 256-bit (32-byte) key for the z-tier obfuscation schemes
// (legacy, zrbcx). Unlike the a/u-tier MasterKey, Secret does not perform
// automatic zeroization, matching the z-tier's design as a non-secure
// obfuscation layer.
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
	return NewSecret(secret)
}

// SecretFromBase64 creates a Secret from a 43-character base64url-nopad string.
//
// Deprecated: base64 secrets are a legacy format; use SecretFromHex for the
// canonical representation.
func SecretFromBase64(secretB64 string) (*Secret, error) {
	if len(secretB64) != SecretBase64Len {
		return nil, fmt.Errorf("secret base64url must be %d characters, got %d", SecretBase64Len, len(secretB64))
	}
	secret, err := base64.RawURLEncoding.DecodeString(secretB64)
	if err != nil {
		return nil, fmt.Errorf("invalid secret base64url: %w", err)
	}
	return NewSecret(secret)
}

// SecretFromString creates a Secret from a textual secret, auto-detecting the
// encoding by length: 64 characters → hex (the canonical format); 43
// characters → base64url-nopad (deprecated, accepted for backward
// compatibility only).
func SecretFromString(secret string) (*Secret, error) {
	switch len(secret) {
	case SecretSize * 2: // 64 hex chars (canonical)
		return SecretFromHex(secret)
	case SecretBase64Len: // 43 base64url chars (deprecated)
		return SecretFromBase64(secret)
	default:
		return nil, fmt.Errorf("secret must be %d hex chars or %d base64url chars, got %d",
			SecretSize*2, SecretBase64Len, len(secret))
	}
}

// SecretFromMasterKey derives a Secret from an a/u-tier MasterKey by taking its
// first 32 bytes. A convenience for tooling that holds a master key and wants a
// matching z-tier secret.
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

// Base64 returns the secret as a 43-character base64url-nopad string.
//
// Deprecated: base64 secrets are a legacy format; use Hex for the canonical
// representation.
func (s *Secret) Base64() string {
	return base64.RawURLEncoding.EncodeToString(s.secret[:])
}
