package oboron

import (
	"crypto/rand"
	"encoding/hex"

	"oboron.org/go/obcrypt"
)

// GenerateKey returns a fresh 512-bit master key as a 128-character lowercase
// hex string — the canonical key format (spec §3.2, §4.3). Use it with the
// authenticated codecs (New, NewOmnib, the fixed types).
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

// GenerateKeyBytes returns a fresh 512-bit master key as raw 64 bytes, for
// programmatic use (the byte counterpart of GenerateKey; mirrors Rust's
// generate_key_bytes). It panics only if the system CSPRNG fails.
func GenerateKeyBytes() []byte {
	k, err := obcrypt.GenerateKey()
	if err != nil {
		panic("oboron: crypto/rand failed: " + err.Error())
	}
	return k.Bytes()
}

// GenerateSecret returns a fresh 256-bit obu secret as a 64-character
// lowercase hex string — the canonical secret format. Use it with the obu
// codecs in the obu package (NewObu, NewOmnibu, NewUpcbcC32, NewZdcbcC32).
//
// It panics only if the system CSPRNG fails (see GenerateKey).
func GenerateSecret() string {
	const secretSizeBytes = 32 // 256-bit obu secret
	b := make([]byte, secretSizeBytes)
	if _, err := rand.Read(b); err != nil {
		panic("oboron: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
