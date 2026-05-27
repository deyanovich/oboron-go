package oboron

import (
	"crypto/cipher"
	"encoding/base32"
)

// encodeLegacy implements Legacy (formerly Ob0) encoding algorithm with default B32 encoding.
func (c *codec) encodeLegacy(orig string) (string, error) {
	return c.encodeLegacyWith(orig, EncodingB32)
}

// encodeLegacyWith implements Legacy encoding with a configurable text encoding.
func (c *codec) encodeLegacyWith(orig string, enc Encoding) (string, error) {
	if len(orig) == 0 {
		return "", ErrEmptyString
	}

	// z-tier CBC IV (key bytes 16-31)
	iv := c.iv

	// Step 1: Calculate padding and build padded data
	paddingSize := blockSize - (len(orig) % blockSize)
	if paddingSize == blockSize {
		paddingSize = 0
	}
	paddedLen := len(orig) + paddingSize

	// Single allocation for padded + ciphertext
	buffer := make([]byte, paddedLen*2)
	padded := buffer[:paddedLen]
	ciphertext := buffer[paddedLen:]

	copy(padded, orig)
	for i := len(orig); i < paddedLen; i++ {
		padded[i] = '='
	}

	// Step 2: Encrypt with AES-128-CBC
	mode := cipher.NewCBCEncrypter(c.block, iv)
	mode.CryptBlocks(ciphertext, padded)

	// Step 3+4+5: Encode to text, then reverse (legacy-specific)
	if enc == EncodingB32 {
		// Optimized path for B32: combined base32 encode + trim + reverse + lowercase
		b32Len := base32.StdEncoding.EncodedLen(len(ciphertext))
		b32Buf := make([]byte, b32Len)
		base32.StdEncoding.Encode(b32Buf, ciphertext)

		end := b32Len
		for end > 0 && b32Buf[end-1] == '=' {
			end--
		}

		for i := 0; i < end/2; i++ {
			j := end - 1 - i
			left := b32Buf[i]
			if left >= 'A' && left <= 'Z' {
				left += 32
			}
			right := b32Buf[j]
			if right >= 'A' && right <= 'Z' {
				right += 32
			}
			b32Buf[i], b32Buf[j] = right, left
		}
		if end%2 == 1 {
			mid := end / 2
			if b32Buf[mid] >= 'A' && b32Buf[mid] <= 'Z' {
				b32Buf[mid] += 32
			}
		}

		return string(b32Buf[:end]), nil
	}

	// Generic path: encode to text, then reverse string (legacy-specific)
	text := encodeToText(ciphertext, enc)
	return reverseString(text), nil
}

// decodeLegacy implements Legacy (formerly Ob0) decoding algorithm with default B32 encoding.
func (c *codec) decodeLegacy(s string) (string, error) {
	return c.decodeLegacyWith(s, EncodingB32)
}

// decodeLegacyWith implements Legacy decoding with a configurable text encoding.
func (c *codec) decodeLegacyWith(s string, enc Encoding) (string, error) {
	// z-tier CBC IV (key bytes 16-31)
	iv := c.iv

	var ciphertext []byte
	var err error

	if enc == EncodingB32 {
		// Optimized path for B32: combined reverse + uppercase + pad + decode
		encLen := len(s)
		padding := (8 - (encLen % 8)) % 8
		b32Len := encLen + padding

		b32 := make([]byte, b32Len)
		for i := 0; i < encLen; i++ {
			c := s[encLen-1-i]
			if c >= 'a' && c <= 'z' {
				c -= 32
			}
			b32[i] = c
		}
		for i := encLen; i < b32Len; i++ {
			b32[i] = '='
		}

		maxDecodedLen := base32.StdEncoding.DecodedLen(b32Len)
		ciphertext = make([]byte, maxDecodedLen)
		var n int
		n, err = base32.StdEncoding.Decode(ciphertext, b32)
		if err != nil {
			return "", ErrInvalidBase32
		}
		ciphertext = ciphertext[:n]
	} else {
		// Generic path: reverse string, then decode from text
		reversed := reverseString(s)
		ciphertext, err = decodeFromText(reversed, enc)
		if err != nil {
			return "", ErrInvalidEncoding
		}
	}

	// Verify block alignment
	if len(ciphertext)%blockSize != 0 {
		return "", ErrDecryptionFailed
	}

	// Decrypt in-place
	mode := cipher.NewCBCDecrypter(c.block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// Remove '=' padding
	end := len(ciphertext)
	for end > 0 && ciphertext[end-1] == '=' {
		end--
	}

	return string(ciphertext[:end]), nil
}

// reverseString reverses a string (used by legacy scheme).
func reverseString(s string) string {
	n := len(s)
	buf := make([]byte, n)
	for i := 0; i < n; i++ {
		buf[i] = s[n-1-i]
	}
	return string(buf)
}
