package oboron

import (
	"crypto/rand"
	"encoding/hex"

	"oboron.org/go/obcrypt"
)

// GenerateKey returns a fresh 512-bit master key as a 128-character lowercase
// hex string — the canonical key format (spec §3.2, §4.3). Use it with the
// a/u-tier codecs (New, NewOmnib, the fixed types).
//
// It panics only if the system CSPRNG fails, which on a healthy system does
// not happen (mirroring Rust's infallible generate_key).
func GenerateKey() string {
	k, err := obcrypt.GenerateKey()
	if err != nil {
		panic("oboron: crypto/rand failed: " + err.Error())
	}
	return k.Hex()
}

// GenerateSecret returns a fresh 256-bit z-tier secret as a 64-character
// lowercase hex string — the canonical secret format. Use it with the z-tier
// codecs in oboron/ztier (NewObz, NewOmnibz, NewZrbcxC32, NewLegacy).
//
// It panics only if the system CSPRNG fails (see GenerateKey).
func GenerateSecret() string {
	const secretSizeBytes = 32 // 256-bit z-tier secret
	b := make([]byte, secretSizeBytes)
	if _, err := rand.Read(b); err != nil {
		panic("oboron: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
