package obcrypt

import (
	crand "crypto/rand"

	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"runtime"
	"sync"
	"time"

	"github.com/agl/gcmsiv"
	"github.com/miscreant/miscreant.go"
)

// KeySize is the size of an obcrypt key in bytes (512 bits).
const KeySize = 64

// KeyBase64Len is the number of base64url-nopad characters for a 512-bit key.
const KeyBase64Len = 86

// Key is a 512-bit (64-byte) master key for the a-tier and u-tier schemes.
// Its canonical text form is hex (128 lowercase characters); see Hex. Key
// caches the per-scheme ciphers it derives, so reuse a single Key across many
// Encrypt/Decrypt calls rather than reconstructing one each time.
//
// Key supports in-memory zeroization: call Zeroize when done, or rely on the
// GC finalizer registered by the constructors for automatic cleanup.
type Key struct {
	key      [KeySize]byte
	zeroized bool

	// Cached AES-GCM-SIV cipher for aags/apgs (key[32:64]).
	gcmsiv     cipher.AEAD
	gcmsivOnce sync.Once
	gcmsivErr  error

	// Cached AES-CMAC-SIV cipher for aasv/apsv (all 64 bytes). Held as the
	// concrete type so callers control the associated-data items passed to S2V.
	sivCipher     *miscreant.Cipher
	sivCipherOnce sync.Once
	sivCipherErr  error

	// Cached AES-256 block cipher for upbc (key[8:40]).
	block256     cipher.Block
	block256Once sync.Once
	block256Err  error

	// Fast (non-cryptographic) random source for probabilistic nonces/IVs.
	rng     *rand.Rand
	rngOnce sync.Once
	rngMu   sync.Mutex
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

// KeyFromHex creates a Key from a 128-character hex string.
func KeyFromHex(s string) (*Key, error) {
	if len(s) != KeySize*2 {
		return nil, fmt.Errorf("obcrypt: key hex must be %d characters, got %d", KeySize*2, len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("obcrypt: invalid key hex: %w", err)
	}
	return NewKey(b)
}

// KeyFromBase64 creates a Key from an 86-character base64url-nopad string.
//
// Deprecated: base64 keys are a legacy format; use KeyFromHex for the canonical
// representation.
func KeyFromBase64(s string) (*Key, error) {
	if len(s) != KeyBase64Len {
		return nil, fmt.Errorf("obcrypt: key base64url must be %d characters, got %d", KeyBase64Len, len(s))
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("obcrypt: invalid key base64url: %w", err)
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

// Base64 returns the key as an 86-character base64url-nopad string.
//
// Deprecated: base64 keys are a legacy format; use Hex for the canonical
// representation. Returns the empty string if zeroized.
func (k *Key) Base64() string {
	if k.zeroized {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(k.key[:])
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

// --- cached cipher accessors (a/u-tier primitives) ---

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
		key32 := make([]byte, 32)
		copy(key32, k.key[32:64])
		k.gcmsiv, k.gcmsivErr = gcmsiv.NewGCMSIV(key32)
	})
	return k.gcmsiv, k.gcmsivErr
}

func (k *Key) getBlock256() (cipher.Block, error) {
	k.block256Once.Do(func() {
		k.block256, k.block256Err = aes.NewCipher(k.key[8:40])
	})
	return k.block256, k.block256Err
}

// generateNonce returns a random 12-byte nonce.
func (k *Key) generateNonce() []byte {
	k.rngOnce.Do(func() {
		k.rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	})
	nonce := make([]byte, 12)
	k.rngMu.Lock()
	binary.LittleEndian.PutUint64(nonce[0:8], k.rng.Uint64())
	binary.LittleEndian.PutUint32(nonce[8:12], k.rng.Uint32())
	k.rngMu.Unlock()
	return nonce
}

// generateNonce16 returns a random 16-byte nonce/IV.
func (k *Key) generateNonce16() []byte {
	k.rngOnce.Do(func() {
		k.rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	})
	nonce := make([]byte, 16)
	k.rngMu.Lock()
	binary.LittleEndian.PutUint64(nonce[0:8], k.rng.Uint64())
	binary.LittleEndian.PutUint64(nonce[8:16], k.rng.Uint64())
	k.rngMu.Unlock()
	return nonce
}
