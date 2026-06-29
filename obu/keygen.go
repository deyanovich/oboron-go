package obu

import (
	"crypto/rand"
	"encoding/hex"
)

// GenerateSecret returns a fresh 256-bit obu secret as a 64-character lowercase
// hex string — the canonical secret format. It mirrors the Rust obu crate's
// generate_secret, so callers importing only obu can mint a secret without
// reaching into package oboron.
//
// It panics only if the system CSPRNG fails, which on a healthy system does not
// happen (mirroring Rust's infallible generate_secret).
func GenerateSecret() string {
	return hex.EncodeToString(GenerateSecretBytes())
}

// GenerateSecretBytes returns a fresh 256-bit obu secret as raw 32 bytes, for
// programmatic use (the byte counterpart of GenerateSecret; mirrors Rust's
// generate_secret_bytes). It panics only if the system CSPRNG fails.
func GenerateSecretBytes() []byte {
	b := make([]byte, SecretSize)
	if _, err := rand.Read(b); err != nil {
		panic("obu: crypto/rand failed: " + err.Error())
	}
	return b
}
