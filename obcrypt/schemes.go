package obcrypt

// This file holds the per-scheme byte primitives. Each encrypt* returns the
// scheme's raw ciphertext output — no scheme marker is appended (the scheme is
// supplied by the caller). Each decrypt* takes that output and returns the
// plaintext.

// --- dsiv: deterministic, AES-SIV ---

func (k *Key) encryptDsiv(plaintext []byte) ([]byte, error) {
	siv, err := k.getSIVCipher()
	if err != nil {
		return nil, err
	}
	// Zero associated-data items, matching the Rust reference.
	return siv.Seal(nil, plaintext)
}

func (k *Key) decryptDsiv(data []byte) ([]byte, error) {
	// Minimum: 1 byte plaintext + 16 byte tag.
	if len(data) < 17 {
		return nil, ErrDecryptionFailed
	}
	siv, err := k.getSIVCipher()
	if err != nil {
		return nil, err
	}
	pt, err := siv.Open(nil, data)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return pt, nil
}

// --- psiv: probabilistic, AES-SIV ---

func (k *Key) encryptPsiv(plaintext []byte) ([]byte, error) {
	siv, err := k.getSIVCipher()
	if err != nil {
		return nil, err
	}
	nonce, err := k.generateNonce16()
	if err != nil {
		return nil, err
	}
	// Nonce passed as the single associated-data item, matching Rust.
	ct, err := siv.Seal(nil, plaintext, nonce)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, len(nonce)+len(ct))
	buf = append(buf, nonce...)
	buf = append(buf, ct...)
	return buf, nil
}

func (k *Key) decryptPsiv(data []byte) ([]byte, error) {
	// Minimum: 16 byte nonce + 1 byte plaintext + 16 byte tag.
	if len(data) < 16+17 {
		return nil, ErrDecryptionFailed
	}
	nonce := data[:16]
	ciphertext := data[16:]
	siv, err := k.getSIVCipher()
	if err != nil {
		return nil, err
	}
	pt, err := siv.Open(nil, ciphertext, nonce)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return pt, nil
}

// --- dgcmsiv: deterministic, AES-GCM-SIV ---

func (k *Key) encryptDgcmsiv(plaintext []byte) ([]byte, error) {
	gcmsiv, err := k.getGCMSIV()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcmsiv.NonceSize()) // all-zero deterministic nonce
	return gcmsiv.Seal(nil, nonce, plaintext, nil), nil
}

func (k *Key) decryptDgcmsiv(data []byte) ([]byte, error) {
	// Minimum: 1 byte plaintext + 16 byte tag.
	if len(data) < 17 {
		return nil, ErrDecryptionFailed
	}
	gcmsiv, err := k.getGCMSIV()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcmsiv.NonceSize())
	pt, err := gcmsiv.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return pt, nil
}

// --- pgcmsiv: probabilistic, AES-GCM-SIV ---

func (k *Key) encryptPgcmsiv(plaintext []byte) ([]byte, error) {
	gcmsiv, err := k.getGCMSIV()
	if err != nil {
		return nil, err
	}
	nonce, err := k.generateNonce()
	if err != nil {
		return nil, err
	}
	ct := gcmsiv.Seal(nil, nonce, plaintext, nil)
	buf := make([]byte, 0, len(nonce)+len(ct))
	buf = append(buf, nonce...)
	buf = append(buf, ct...)
	return buf, nil
}

func (k *Key) decryptPgcmsiv(data []byte) ([]byte, error) {
	// Minimum: 12 byte nonce + 1 byte plaintext + 16 byte tag.
	if len(data) < 12+17 {
		return nil, ErrDecryptionFailed
	}
	nonce := data[:12]
	ciphertext := data[12:]
	gcmsiv, err := k.getGCMSIV()
	if err != nil {
		return nil, err
	}
	pt, err := gcmsiv.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return pt, nil
}
