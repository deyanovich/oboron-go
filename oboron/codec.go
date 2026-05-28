package oboron

import "oboron.org/go/obcrypt"

// codec carries the key material the a/u-tier oboron layer needs. The a-tier /
// u-tier crypto is delegated to obKey (an obcrypt.Key, which caches its own
// ciphers). The z-tier schemes (zrbcx, legacy) are not part of this package —
// they live in the isolated oboron/ztier subpackage with their own codec.
type codec struct {
	obKey *obcrypt.Key // a/u-tier crypto core
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
