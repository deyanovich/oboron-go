package obu

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"unicode/utf8"

	"oboron.org/go/oboron"
)

// blockSize is the AES block size used by the obu CBC schemes.
const blockSize = 16

// codec carries the obu key material. zdcbc uses AES-128 over the first 16
// secret bytes with the next 16 as a fixed CBC IV; upcbc uses AES-256 over the
// full 32-byte secret with a fresh random IV per call. Both are markerless: the
// obtext is the bare encoded ciphertext.
type codec struct {
	secret   [SecretSize]byte
	zBlock   cipher.Block // AES-128 over secret[:16] (zdcbc)
	zIV      []byte       // secret[16:32], the zdcbc CBC IV
	upcbcAES cipher.Block // AES-256 over secret[:32] (upcbc)
}

// newCodec builds a codec from a 32-byte secret.
func newCodec(s *Secret) (*codec, error) {
	zBlock, err := aes.NewCipher(s.secret[:blockSize])
	if err != nil {
		return nil, err
	}
	upcbcAES, err := aes.NewCipher(s.secret[:SecretSize])
	if err != nil {
		return nil, err
	}
	iv := make([]byte, blockSize)
	copy(iv, s.secret[blockSize:SecretSize])
	c := &codec{zBlock: zBlock, zIV: iv, upcbcAES: upcbcAES}
	copy(c.secret[:], s.secret[:])
	return c, nil
}

// --- upcbc: AES-256-CBC, full 32-byte secret as the key, random 16-byte IV ---

// encryptUpcbc produces the raw upcbc ciphertext: IV ‖ padded ciphertext. The
// plaintext is padded with 0x01 bytes to a 16-byte boundary (no padding when
// already aligned), so a plaintext that itself ends in 0x01 is rejected to keep
// decoding unambiguous (spec §2.1).
func (c *codec) encryptUpcbc(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, oboron.ErrEmptyString
	}
	if !utf8.Valid(plaintext) {
		return nil, oboron.ErrInvalidUTF8
	}
	if plaintext[len(plaintext)-1] == 0x01 {
		return nil, oboron.ErrPlaintextEndsWithPadByte
	}
	iv := make([]byte, blockSize)
	if _, err := crand.Read(iv); err != nil {
		return nil, err
	}
	pad := blockSize - (len(plaintext) % blockSize)
	if pad == blockSize {
		pad = 0
	}
	padded := make([]byte, len(plaintext)+pad)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = 0x01
	}
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(c.upcbcAES, iv).CryptBlocks(ct, padded)
	out := make([]byte, 0, len(iv)+len(ct))
	out = append(out, iv...)
	out = append(out, ct...)
	return out, nil
}

// decryptUpcbc reverses encryptUpcbc: split the 16-byte IV, AES-256-CBC decrypt,
// strip trailing 0x01 padding.
func (c *codec) decryptUpcbc(data []byte) ([]byte, error) {
	if len(data) < blockSize+blockSize || (len(data)-blockSize)%blockSize != 0 {
		return nil, oboron.ErrDecryptionFailed
	}
	iv := data[:blockSize]
	ctext := make([]byte, len(data)-blockSize)
	copy(ctext, data[blockSize:])
	cipher.NewCBCDecrypter(c.upcbcAES, iv).CryptBlocks(ctext, ctext)
	end := len(ctext)
	for end > 0 && ctext[end-1] == 0x01 {
		end--
	}
	// The empty string is outside the obu plaintext domain (spec §2.2).
	if end == 0 {
		return nil, oboron.ErrDecryptionFailed
	}
	return ctext[:end], nil
}

func (c *codec) encodeUpcbc(s string, enc oboron.Encoding) (string, error) {
	ct, err := c.encryptUpcbc([]byte(s))
	if err != nil {
		return "", err
	}
	return encodeToText(ct, enc), nil
}

func (c *codec) decodeUpcbc(s string, enc oboron.Encoding) (string, error) {
	buf, err := decodeFromText(s, enc)
	if err != nil {
		return "", oboron.ErrInvalidEncoding
	}
	pt, err := c.decryptUpcbc(buf)
	if err != nil {
		return "", oboron.ErrDecryptionFailed
	}
	if !utf8.Valid(pt) {
		return "", oboron.ErrDecryptionFailed
	}
	return string(pt), nil
}

// --- zdcbc: AES-128-CBC, deterministic, prefix-restructured, markerless ---

// encodeZdcbc implements Zdcbc encoding with a configurable text encoding.
// Zdcbc: no header/terminal in plaintext, XOR first block with last block.
// Markerless — the obtext is the bare encoded ciphertext.
func (c *codec) encodeZdcbc(s string, enc oboron.Encoding) (string, error) {
	if len(s) == 0 {
		return "", oboron.ErrEmptyString
	}
	if !utf8.ValidString(s) {
		return "", oboron.ErrInvalidUTF8
	}
	// 0x01 is the pad byte; a plaintext ending in it would be silently
	// truncated on decode, so reject it (spec §2.1).
	if s[len(s)-1] == 0x01 {
		return "", oboron.ErrPlaintextEndsWithPadByte
	}
	iv := c.zIV

	paddingSize := blockSize - (len(s) % blockSize)
	if paddingSize == blockSize {
		paddingSize = 0
	}
	paddedLen := len(s) + paddingSize

	buf := make([]byte, paddedLen)
	copy(buf, s)
	for i := len(s); i < paddedLen; i++ {
		buf[i] = 0x01
	}

	cipher.NewCBCEncrypter(c.zBlock, iv).CryptBlocks(buf, buf)

	// XOR first block with last block for prefix entropy (if multiple blocks).
	if paddedLen > blockSize {
		for i := 0; i < blockSize; i++ {
			buf[i] ^= buf[paddedLen-blockSize+i]
		}
	}

	return encodeToText(buf, enc), nil
}

// decodeZdcbc implements Zdcbc decoding with a configurable text encoding.
func (c *codec) decodeZdcbc(s string, enc oboron.Encoding) (string, error) {
	iv := c.zIV

	buf, err := decodeFromText(s, enc)
	if err != nil {
		return "", oboron.ErrInvalidEncoding
	}
	n := len(buf)

	if n < blockSize || n%blockSize != 0 {
		return "", oboron.ErrDecryptionFailed
	}

	// Reverse the prefix restructuring (XOR first block with last) if multi-block.
	if n > blockSize {
		for i := 0; i < blockSize; i++ {
			buf[i] ^= buf[n-blockSize+i]
		}
	}

	cipher.NewCBCDecrypter(c.zBlock, iv).CryptBlocks(buf, buf)

	end := n
	for end > 0 && buf[end-1] == 0x01 {
		end--
	}
	// The empty string is outside the obu plaintext domain (spec §2.2).
	if end == 0 {
		return "", oboron.ErrDecryptionFailed
	}
	pt := buf[:end]
	if !utf8.Valid(pt) {
		return "", oboron.ErrDecryptionFailed
	}
	return string(pt), nil
}

// encodeScheme dispatches obu encoding by scheme.
func (c *codec) encodeScheme(s string, scheme oboron.Scheme, enc oboron.Encoding) (string, error) {
	switch scheme {
	case oboron.SchemeUpcbc:
		return c.encodeUpcbc(s, enc)
	case oboron.SchemeZdcbc:
		return c.encodeZdcbc(s, enc)
	default:
		return "", oboron.ErrInvalidFormat
	}
}

// decodeScheme dispatches obu decoding by scheme.
func (c *codec) decodeScheme(s string, scheme oboron.Scheme, enc oboron.Encoding) (string, error) {
	switch scheme {
	case oboron.SchemeUpcbc:
		return c.decodeUpcbc(s, enc)
	case oboron.SchemeZdcbc:
		return c.decodeZdcbc(s, enc)
	default:
		return "", oboron.ErrInvalidFormat
	}
}
