package oboron

import (
	"crypto/cipher"
	"encoding/base32"
)

// encodeZrbcx implements Zrbcx (formerly Ob1) encoding algorithm with default B32 encoding.
func (c *codec) encodeZrbcx(s string) (string, error) {
	return c.encodeZrbcxWith(s, EncodingB32)
}

// encodeZrbcxWith implements Zrbcx encoding with a configurable text encoding.
// Zrbcx: No header/terminal in plaintext, XOR first block with last block, add 2-byte XOR marker
func (c *codec) encodeZrbcxWith(s string, enc Encoding) (string, error) {
	if len(s) == 0 {
		return "", ErrEmptyString
	}

	// z-tier CBC IV (key bytes 16-31)
	iv := c.iv

	// Step 1: Calculate padding
	paddingSize := blockSize - (len(s) % blockSize)
	if paddingSize == blockSize {
		paddingSize = 0
	}
	paddedLen := len(s) + paddingSize
	ciphertextLen := paddedLen + MarkerSize

	// Step 2: Allocate buffer
	buf := make([]byte, ciphertextLen)
	copy(buf, s)
	for i := len(s); i < paddedLen; i++ {
		buf[i] = 0x01
	}

	// Step 3: Encrypt in-place
	mode := cipher.NewCBCEncrypter(c.block, iv)
	mode.CryptBlocks(buf[:paddedLen], buf[:paddedLen])

	// Step 4: XOR first block with last block for prefix entropy (if multiple blocks)
	if paddedLen > blockSize {
		for i := 0; i < blockSize; i++ {
			buf[i] ^= buf[paddedLen-blockSize+i]
		}
	}

	// Step 5: Append XOR-mixed marker
	buf[paddedLen] = zrbcxMarker[0] ^ buf[0]
	buf[paddedLen+1] = zrbcxMarker[1] ^ buf[0]

	// Step 6: Encode to text
	if enc == EncodingB32 {
		// Optimized B32 path — uppercase per RFC 4648
		b32Len := base32.StdEncoding.EncodedLen(ciphertextLen)
		b32Buf := make([]byte, b32Len)
		base32.StdEncoding.Encode(b32Buf, buf)

		end := b32Len
		for end > 0 && b32Buf[end-1] == '=' {
			end--
		}

		return string(b32Buf[:end]), nil
	}

	return encodeToText(buf, enc), nil
}

// decodeZrbcx implements Zrbcx (formerly Ob1) decoding algorithm with default B32 encoding.
func (c *codec) decodeZrbcx(s string) (string, error) {
	return c.decodeZrbcxWith(s, EncodingB32)
}

// decodeZrbcxWith implements Zrbcx decoding with a configurable text encoding.
func (c *codec) decodeZrbcxWith(s string, enc Encoding) (string, error) {
	// z-tier CBC IV (key bytes 16-31)
	iv := c.iv

	var buf []byte
	var n int

	if enc == EncodingB32 {
		// Optimized B32 path
		encLen := len(s)
		padding := (8 - (encLen % 8)) % 8
		b32Len := encLen + padding

		b32 := make([]byte, b32Len)
		for i := 0; i < encLen; i++ {
			b := s[i]
			if b >= 'a' && b <= 'z' {
				b -= 32
			}
			b32[i] = b
		}
		for i := encLen; i < b32Len; i++ {
			b32[i] = '='
		}

		maxDecodedLen := base32.StdEncoding.DecodedLen(b32Len)
		buf = make([]byte, maxDecodedLen)
		var err error
		n, err = base32.StdEncoding.Decode(buf, b32)
		if err != nil {
			return "", ErrInvalidBase32
		}
		buf = buf[:n]
	} else {
		var err error
		buf, err = decodeFromText(s, enc)
		if err != nil {
			return "", ErrInvalidEncoding
		}
		n = len(buf)
	}

	// Verify minimum length: blockSize + MarkerSize
	if n < blockSize+MarkerSize {
		return "", ErrDecryptionFailed
	}

	// Recover marker by XORing with first byte
	marker := [2]byte{
		buf[n-2] ^ buf[0],
		buf[n-1] ^ buf[0],
	}
	if marker != zrbcxMarker {
		return "", ErrDecryptionFailed
	}

	// Remove marker bytes
	ciphertext := buf[:n-MarkerSize]

	// Verify block alignment
	if len(ciphertext)%blockSize != 0 {
		return "", ErrDecryptionFailed
	}

	// XOR first block with last block to reverse prefix restructuring (if multiple blocks)
	if len(ciphertext) > blockSize {
		for i := 0; i < blockSize; i++ {
			ciphertext[i] ^= ciphertext[len(ciphertext)-blockSize+i]
		}
	}

	// Decrypt in-place
	mode := cipher.NewCBCDecrypter(c.block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// Remove 0x01 padding
	end := len(ciphertext)
	for end > 0 && ciphertext[end-1] == 0x01 {
		end--
	}

	return string(ciphertext[:end]), nil
}
