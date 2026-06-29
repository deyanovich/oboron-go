package oboron

import "oboron.org/go/obcrypt"

// codec carries the key material the authenticated oboron layer needs. The
// crypto is delegated to obKey (an obcrypt.Key, which caches its own ciphers).
// The obu schemes (upcbc, zdcbc) are not part of this package — they live in
// the separate obu package with their own codec.
type codec struct {
	obKey *obcrypt.Key // authenticated crypto core
}

// newCodec builds a codec from a 64-byte master key.
func newCodec(key []byte) (*codec, error) {
	if len(key) != 64 {
		return nil, ErrInvalidKeyLength
	}
	obKey, err := obcrypt.NewKey(key)
	if err != nil {
		return nil, err
	}
	return &codec{obKey: obKey}, nil
}
