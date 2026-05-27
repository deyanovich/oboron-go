package oboron

import (
	"crypto/aes"
	"crypto/cipher"

	"oboron.org/go/obcrypt"
)

// codec carries the key material the oboron layer needs. The a-tier / u-tier
// crypto is delegated to obKey (an obcrypt.Key, which caches its own ciphers);
// the z-tier schemes (zrbcx, legacy) use an AES-128 block cipher over the first
// 16 key bytes with the next 16 as the CBC IV.
type codec struct {
	obKey *obcrypt.Key // a/u-tier crypto core
	block cipher.Block // AES-128 over key[:16], for z-tier CBC
	iv    []byte       // key[16:32], the z-tier CBC IV
}

// newCodec builds a codec from a 64-byte key.
func newCodec(key []byte) (*codec, error) {
	if len(key) != 64 {
		return nil, ErrInvalidKeyLength
	}
	obKey, err := obcrypt.NewKey(key)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}
	iv := make([]byte, 16)
	copy(iv, key[16:32])
	return &codec{obKey: obKey, block: block, iv: iv}, nil
}
