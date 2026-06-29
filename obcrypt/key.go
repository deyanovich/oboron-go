package obcrypt

import (
	crand "crypto/rand"

	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"runtime"
	"sync"

	"github.com/agl/gcmsiv"
	"github.com/miscreant/miscreant.go"
	"golang.org/x/crypto/hkdf"
)

// KeySize is the size of an obcrypt key in bytes (512 bits).
const KeySize = 64

// Key is a 512-bit (64-byte) master key for the authenticated core schemes.
// Its canonical text form is hex (128 lowercase characters); see Hex. Key
// caches the per-scheme ciphers it derives, so reuse a single Key across many
// Encrypt/Decrypt calls rather than reconstructing one each time.
//
// Key supports in-memory zeroization: call Zeroize when done, or rely on the
// GC finalizer registered by the constructors for automatic cleanup.
type Key struct {
	key      [KeySize]byte
	zeroized bool

	// Cached AES-GCM-SIV cipher for dgcmsiv/pgcmsiv, keyed by a 32-byte key
	// derived via HKDF-Expand(master, info="gcmsiv").
	gcmsiv     cipher.AEAD
	gcmsivOnce sync.Once
	gcmsivErr  error

	// Cached AES-CMAC-SIV cipher for dsiv/psiv (all 64 bytes). Held as the
	// concrete type so callers control the associated-data items passed to S2V.
	sivCipher     *miscreant.Cipher
	sivCipherOnce sync.Once
	sivCipherErr  error
}

// GenerateKey returns a fresh Key from KeySize bytes of cryptographically
// secure randomness.
func GenerateKey() (*Key, error) {
	b := make([]byte, KeySize)
	if _, err := crand.Read(b); err != nil {
		return nil, err
	}
	return NewKey(b)
}

// NewKey creates a Key from a 64-byte slice. Returns ErrInvalidKeyLength if the
// slice is not exactly KeySize bytes.
func NewKey(b []byte) (*Key, error) {
	if len(b) != KeySize {
		return nil, ErrInvalidKeyLength
	}
	k := &Key{}
	copy(k.key[:], b)
	runtime.SetFinalizer(k, func(x *Key) { x.Zeroize() })
	return k, nil
}

// KeyFromHex creates a Key from a 128-character hex string. Hex is the only
// accepted key form — there is no base64 key form.
func KeyFromHex(s string) (*Key, error) {
	if len(s) != KeySize*2 {
		return nil, fmt.Errorf("obcrypt: key hex must be %d characters, got %d", KeySize*2, len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("obcrypt: invalid key hex: %w", err)
	}
	// Canonical key hex is lowercase (spec §3.3). hex.DecodeString accepts
	// uppercase, so reject any input that is not its own canonical re-encoding.
	if hex.EncodeToString(b) != s {
		return nil, fmt.Errorf("obcrypt: key hex must be lowercase")
	}
	return NewKey(b)
}

// Hex returns the key as a 128-character hex string, the canonical key
// encoding. Returns the empty string if zeroized.
func (k *Key) Hex() string {
	if k.zeroized {
		return ""
	}
	return hex.EncodeToString(k.key[:])
}

// Bytes returns a copy of the key material, or nil if zeroized.
func (k *Key) Bytes() []byte {
	if k.zeroized {
		return nil
	}
	out := make([]byte, KeySize)
	copy(out, k.key[:])
	return out
}

// Zeroize erases the key material from memory. After Zeroize, Bytes returns nil
// and the key can no longer encrypt or decrypt.
func (k *Key) Zeroize() {
	for i := range k.key {
		k.key[i] = 0
	}
	k.zeroized = true
}

// IsZeroized reports whether the key material has been erased.
func (k *Key) IsZeroized() bool {
	return k.zeroized
}

// --- cached cipher accessors ---

func (k *Key) getSIVCipher() (*miscreant.Cipher, error) {
	k.sivCipherOnce.Do(func() {
		key64 := make([]byte, KeySize)
		copy(key64, k.key[:])
		k.sivCipher, k.sivCipherErr = miscreant.NewAESCMACSIV(key64)
	})
	return k.sivCipher, k.sivCipherErr
}

func (k *Key) getGCMSIV() (cipher.AEAD, error) {
	k.gcmsivOnce.Do(func() {
		// dgcmsiv/pgcmsiv share one 32-byte AES-256-GCM-SIV key derived from
		// the 64-byte master via HKDF-Expand(info="gcmsiv"). HKDF-Extract is
		// skipped — the master is already a uniform pseudorandom key.
		r := hkdf.Expand(sha256.New, k.key[:], []byte("gcmsiv"))
		key32 := make([]byte, 32)
		if _, err := io.ReadFull(r, key32); err != nil {
			k.gcmsivErr = err
			return
		}
		k.gcmsiv, k.gcmsivErr = gcmsiv.NewGCMSIV(key32)
	})
	return k.gcmsiv, k.gcmsivErr
}

// generateNonce returns a cryptographically random 12-byte nonce (pgcmsiv).
// Per spec §5, probabilistic nonces MUST come from a CSPRNG; on failure enc
// fails rather than synthesizing a nonce.
func (k *Key) generateNonce() ([]byte, error) {
	nonce := make([]byte, 12)
	if _, err := crand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// generateNonce16 returns a cryptographically random 16-byte nonce (psiv).
func (k *Key) generateNonce16() ([]byte, error) {
	nonce := make([]byte, 16)
	if _, err := crand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}
