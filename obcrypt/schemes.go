package obcrypt

import "crypto/cipher"

// This file holds the per-scheme byte primitives. Each encrypt* returns the
// framed payload (scheme ciphertext followed by the 2-byte XOR-mixed marker);
// each decrypt* takes a marker-stripped payload and returns the plaintext. The
// marker recovery, dispatch, and verification live in crypt.go.

const blockSize = 16

// --- aasv: a-tier, deterministic, AES-SIV ---

func (k *Key) encryptAasv(plaintext []byte) ([]byte, error) {
	siv, err := k.getSIVCipher()
	if err != nil {
		return nil, err
	}
	// Zero associated-data items, matching the Rust reference.
	ct, err := siv.Seal(nil, plaintext)
	if err != nil {
		return nil, err
	}
	return frame(ct, aasvMarker), nil
}

func (k *Key) decryptAasv(data []byte) ([]byte, error) {
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

// --- apsv: a-tier, probabilistic, AES-SIV ---

func (k *Key) encryptApsv(plaintext []byte) ([]byte, error) {
	siv, err := k.getSIVCipher()
	if err != nil {
		return nil, err
	}
	nonce := k.generateNonce16()
	// Nonce passed as the single associated-data item, matching Rust.
	ct, err := siv.Seal(nil, plaintext, nonce)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, len(nonce)+len(ct))
	buf = append(buf, nonce...)
	buf = append(buf, ct...)
	return frame(buf, apsvMarker), nil
}

func (k *Key) decryptApsv(data []byte) ([]byte, error) {
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

// --- aags: a-tier, deterministic, AES-GCM-SIV ---

func (k *Key) encryptAags(plaintext []byte) ([]byte, error) {
	gcmsiv, err := k.getGCMSIV()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcmsiv.NonceSize()) // all-zero deterministic nonce
	ct := gcmsiv.Seal(nil, nonce, plaintext, nil)
	return frame(ct, aagsMarker), nil
}

func (k *Key) decryptAags(data []byte) ([]byte, error) {
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

// --- apgs: a-tier, probabilistic, AES-GCM-SIV ---

func (k *Key) encryptApgs(plaintext []byte) ([]byte, error) {
	gcmsiv, err := k.getGCMSIV()
	if err != nil {
		return nil, err
	}
	nonce := k.generateNonce()
	ct := gcmsiv.Seal(nil, nonce, plaintext, nil)
	buf := make([]byte, 0, len(nonce)+len(ct))
	buf = append(buf, nonce...)
	buf = append(buf, ct...)
	return frame(buf, apgsMarker), nil
}

func (k *Key) decryptApgs(data []byte) ([]byte, error) {
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

// --- upbc: u-tier, probabilistic, AES-256-CBC ---

func (k *Key) encryptUpbc(plaintext []byte) ([]byte, error) {
	block256, err := k.getBlock256()
	if err != nil {
		return nil, err
	}
	iv := k.generateNonce16()

	// Pad with 0x01 to a block boundary.
	paddingSize := blockSize - (len(plaintext) % blockSize)
	if paddingSize == blockSize {
		paddingSize = 0
	}
	paddedLen := len(plaintext) + paddingSize
	padded := make([]byte, paddedLen)
	copy(padded, plaintext)
	for i := len(plaintext); i < paddedLen; i++ {
		padded[i] = 0x01
	}

	ciphertext := make([]byte, paddedLen)
	cipher.NewCBCEncrypter(block256, iv).CryptBlocks(ciphertext, padded)

	buf := make([]byte, 0, len(iv)+len(ciphertext))
	buf = append(buf, iv...)
	buf = append(buf, ciphertext...)
	return frame(buf, upbcMarker), nil
}

func (k *Key) decryptUpbc(data []byte) ([]byte, error) {
	// Minimum: 16 byte IV + one block.
	if len(data) < 16+blockSize {
		return nil, ErrDecryptionFailed
	}
	iv := data[:16]
	ciphertext := data[16:]
	if len(ciphertext)%blockSize != 0 {
		return nil, ErrDecryptionFailed
	}
	block256, err := k.getBlock256()
	if err != nil {
		return nil, err
	}
	// Decrypt into a fresh buffer rather than in place: Decrypt/DecryptAs must
	// not mutate the caller's payload.
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block256, iv).CryptBlocks(out, ciphertext)

	end := len(out)
	for end > 0 && out[end-1] == 0x01 {
		end--
	}
	return out[:end], nil
}

// frame appends the 2-byte marker to body (the scheme's pre-marker payload:
// ciphertext for the deterministic schemes, nonce/IV ‖ ciphertext for the
// probabilistic ones). Each marker byte is XORed with body[0] so the marker is
// not a constant trailer. body is always non-empty here (every scheme emits at
// least a tag or a full block).
func frame(body []byte, marker [2]byte) []byte {
	buf := make([]byte, len(body)+MarkerSize)
	copy(buf, body)
	buf[len(buf)-2] = marker[0] ^ body[0]
	buf[len(buf)-1] = marker[1] ^ body[0]
	return buf
}
