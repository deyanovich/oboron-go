package obcrypt

// Encrypt encrypts plaintext under scheme with key, returning the scheme's raw
// ciphertext output. obcrypt does not encode the output and appends no scheme
// marker — the obtext is the scheme's ciphertext and nothing more; the scheme
// is supplied by the caller. Empty plaintext is rejected (it cannot
// round-trip).
func Encrypt(plaintext []byte, scheme Scheme, key *Key) ([]byte, error) {
	if key.zeroized {
		return nil, ErrKeyZeroized
	}
	if len(plaintext) == 0 {
		return nil, ErrEmptyPlaintext
	}
	switch scheme {
	case Dsiv:
		return key.encryptDsiv(plaintext)
	case Psiv:
		return key.encryptPsiv(plaintext)
	case Dgcmsiv:
		return key.encryptDgcmsiv(plaintext)
	case Pgcmsiv:
		return key.encryptPgcmsiv(plaintext)
	default:
		return nil, ErrUnknownScheme
	}
}

// Decrypt decrypts the scheme's ciphertext output with key. The scheme is
// supplied by the caller — there is no marker and no auto-detection (the obtext
// carries no scheme identifier). A wrong scheme or tampered input fails the
// AEAD tag check and yields ErrDecryptionFailed. Decrypt does not mutate
// payload.
func Decrypt(payload []byte, scheme Scheme, key *Key) ([]byte, error) {
	if key.zeroized {
		return nil, ErrKeyZeroized
	}
	return key.decryptScheme(scheme, payload)
}

// decryptScheme dispatches the ciphertext to the scheme's primitive.
func (k *Key) decryptScheme(scheme Scheme, data []byte) ([]byte, error) {
	switch scheme {
	case Dsiv:
		return k.decryptDsiv(data)
	case Psiv:
		return k.decryptPsiv(data)
	case Dgcmsiv:
		return k.decryptDgcmsiv(data)
	case Pgcmsiv:
		return k.decryptPgcmsiv(data)
	default:
		return nil, ErrUnknownScheme
	}
}
