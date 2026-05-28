package ztier

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base32"

	"oboron.org/go/oboron"
	"oboron.org/go/oboron/internal/textcodec"
)

// blockSize is the AES block size used by the z-tier CBC schemes.
const blockSize = 16

// zrbcxMarker is the z-tier zrbcx scheme marker (XORed with the first
// ciphertext byte before appending). Byte layout matches the a/u markers:
//
//	Byte 1: [ext:1][version:4][tier:3]
//	Byte 2: [properties:4][algorithm:4]
var zrbcxMarker = [2]byte{0x06, 0x21} // tier=6, properties=2/referenceable, algorithm=1/CBC

// zcodec carries the z-tier key material: an AES-128 block cipher over the
// first 16 secret bytes, with the next 16 as the CBC IV. The 256-bit secret
// maps directly onto these (no padding) — byte-identical to the pre-split
// codec, which zero-padded the secret to 64 bytes and used the same slices.
type zcodec struct {
	block cipher.Block // AES-128 over secret[:16]
	iv    []byte       // secret[16:32], the CBC IV
}

// newZcodec builds a zcodec from a 32-byte secret.
func newZcodec(s *Secret) (*zcodec, error) {
	block, err := aes.NewCipher(s.secret[:blockSize])
	if err != nil {
		return nil, err
	}
	iv := make([]byte, blockSize)
	copy(iv, s.secret[blockSize:SecretSize])
	return &zcodec{block: block, iv: iv}, nil
}

// encodeToText / decodeFromText delegate to the shared backends; thin wrappers
// keep the algorithm code below terse.
func encodeToText(data []byte, enc oboron.Encoding) string {
	return textcodec.EncodeToText(data, textcodec.Encoding(enc))
}

func decodeFromText(s string, enc oboron.Encoding) ([]byte, error) {
	return textcodec.DecodeFromText(s, textcodec.Encoding(enc))
}

// reverseString reverses a string (used by the legacy scheme).
func reverseString(s string) string {
	n := len(s)
	buf := make([]byte, n)
	for i := 0; i < n; i++ {
		buf[i] = s[n-1-i]
	}
	return string(buf)
}

// --- zrbcx ---

// encodeZrbcx implements Zrbcx encoding with a configurable text encoding.
// Zrbcx: no header/terminal in plaintext, XOR first block with last block, add
// a 2-byte XOR marker.
func (z *zcodec) encodeZrbcx(s string, enc oboron.Encoding) (string, error) {
	if len(s) == 0 {
		return "", oboron.ErrEmptyString
	}
	iv := z.iv

	paddingSize := blockSize - (len(s) % blockSize)
	if paddingSize == blockSize {
		paddingSize = 0
	}
	paddedLen := len(s) + paddingSize
	ciphertextLen := paddedLen + oboron.MarkerSize

	buf := make([]byte, ciphertextLen)
	copy(buf, s)
	for i := len(s); i < paddedLen; i++ {
		buf[i] = 0x01
	}

	cipher.NewCBCEncrypter(z.block, iv).CryptBlocks(buf[:paddedLen], buf[:paddedLen])

	// XOR first block with last block for prefix entropy (if multiple blocks).
	if paddedLen > blockSize {
		for i := 0; i < blockSize; i++ {
			buf[i] ^= buf[paddedLen-blockSize+i]
		}
	}

	buf[paddedLen] = zrbcxMarker[0] ^ buf[0]
	buf[paddedLen+1] = zrbcxMarker[1] ^ buf[0]

	if enc == oboron.EncodingB32 {
		// Optimized B32 path — uppercase per RFC 4648.
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

// decodeZrbcx implements Zrbcx decoding with a configurable text encoding.
func (z *zcodec) decodeZrbcx(s string, enc oboron.Encoding) (string, error) {
	iv := z.iv

	var buf []byte
	var n int

	if enc == oboron.EncodingB32 {
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
			return "", oboron.ErrInvalidBase32
		}
		buf = buf[:n]
	} else {
		var err error
		buf, err = decodeFromText(s, enc)
		if err != nil {
			return "", oboron.ErrInvalidEncoding
		}
		n = len(buf)
	}

	if n < blockSize+oboron.MarkerSize {
		return "", oboron.ErrDecryptionFailed
	}

	marker := [2]byte{buf[n-2] ^ buf[0], buf[n-1] ^ buf[0]}
	if marker != zrbcxMarker {
		return "", oboron.ErrDecryptionFailed
	}

	ciphertext := buf[:n-oboron.MarkerSize]
	if len(ciphertext)%blockSize != 0 {
		return "", oboron.ErrDecryptionFailed
	}

	// Reverse the prefix restructuring (XOR first block with last) if multi-block.
	if len(ciphertext) > blockSize {
		for i := 0; i < blockSize; i++ {
			ciphertext[i] ^= ciphertext[len(ciphertext)-blockSize+i]
		}
	}

	cipher.NewCBCDecrypter(z.block, iv).CryptBlocks(ciphertext, ciphertext)

	end := len(ciphertext)
	for end > 0 && ciphertext[end-1] == 0x01 {
		end--
	}
	return string(ciphertext[:end]), nil
}

// --- legacy ---

// encodeLegacy implements Legacy encoding with a configurable text encoding.
func (z *zcodec) encodeLegacy(orig string, enc oboron.Encoding) (string, error) {
	if len(orig) == 0 {
		return "", oboron.ErrEmptyString
	}
	iv := z.iv

	paddingSize := blockSize - (len(orig) % blockSize)
	if paddingSize == blockSize {
		paddingSize = 0
	}
	paddedLen := len(orig) + paddingSize

	buffer := make([]byte, paddedLen*2)
	padded := buffer[:paddedLen]
	ciphertext := buffer[paddedLen:]

	copy(padded, orig)
	for i := len(orig); i < paddedLen; i++ {
		padded[i] = '='
	}

	cipher.NewCBCEncrypter(z.block, iv).CryptBlocks(ciphertext, padded)

	if enc == oboron.EncodingB32 {
		// Optimized B32 path: base32 encode + trim + reverse + lowercase.
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

	// Generic path: encode to text, then reverse (legacy-specific).
	return reverseString(encodeToText(ciphertext, enc)), nil
}

// decodeLegacy implements Legacy decoding with a configurable text encoding.
func (z *zcodec) decodeLegacy(s string, enc oboron.Encoding) (string, error) {
	var ciphertext []byte
	var err error

	if enc == oboron.EncodingB32 {
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
			return "", oboron.ErrInvalidBase32
		}
		ciphertext = ciphertext[:n]
	} else {
		ciphertext, err = decodeFromText(reverseString(s), enc)
		if err != nil {
			return "", oboron.ErrInvalidEncoding
		}
	}

	return z.decryptLegacyBytes(ciphertext)
}

// decryptLegacyBytes finishes a legacy decode given the already-decoded
// ciphertext bytes: AES-128-CBC decrypt, then strip '=' padding.
func (z *zcodec) decryptLegacyBytes(buf []byte) (string, error) {
	if len(buf)%blockSize != 0 {
		return "", oboron.ErrDecryptionFailed
	}
	cipher.NewCBCDecrypter(z.block, z.iv).CryptBlocks(buf, buf)
	end := len(buf)
	for end > 0 && buf[end-1] == '=' {
		end--
	}
	return string(buf[:end]), nil
}

// tryDecodeZrbcx decodes marker-stripped zrbcx ciphertext bytes.
func (z *zcodec) tryDecodeZrbcx(data []byte) (string, error) {
	if len(data)%blockSize != 0 || len(data) < blockSize {
		return "", oboron.ErrDecryptionFailed
	}
	if len(data) > blockSize {
		for i := 0; i < blockSize; i++ {
			data[i] ^= data[len(data)-blockSize+i]
		}
	}
	cipher.NewCBCDecrypter(z.block, z.iv).CryptBlocks(data, data)
	end := len(data)
	for end > 0 && data[end-1] == 0x01 {
		end--
	}
	return string(data[:end]), nil
}

// --- z-tier autodetection (zrbcx marker, then marker-less legacy) ---

// decodeAutodetectWith decodes obtext under a known text encoding, trying the
// marker-bearing zrbcx scheme first and falling back to the marker-less legacy
// scheme. The a/u tier is never consulted (it lives in a separate package).
func (z *zcodec) decodeAutodetectWith(s string, textEnc oboron.Encoding) (string, error) {
	if textEnc == oboron.EncodingB32 {
		return z.decodeAutodetectB32(s)
	}

	buf, err := decodeFromText(s, textEnc)
	if err != nil {
		return "", oboron.ErrInvalidEncoding
	}
	if n := len(buf); n >= oboron.MarkerSize {
		marker := [2]byte{buf[n-2] ^ buf[0], buf[n-1] ^ buf[0]}
		if marker == zrbcxMarker {
			return z.tryDecodeZrbcx(buf[:n-oboron.MarkerSize])
		}
	}

	// Marker-less legacy fallback: reverse, decode, CBC.
	buf, err = decodeFromText(reverseString(s), textEnc)
	if err != nil {
		return "", oboron.ErrInvalidEncoding
	}
	return z.decryptLegacyBytes(buf)
}

// decodeAutodetectB32 is the optimized B32 autodetect path.
func (z *zcodec) decodeAutodetectB32(s string) (string, error) {
	encLen := len(s)
	padding := (8 - (encLen % 8)) % 8
	b32Len := encLen + padding
	b32 := make([]byte, b32Len)

	// Step 1: marker-bearing zrbcx (uppercase, no reversal).
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
	buf := make([]byte, maxDecodedLen)
	n, err := base32.StdEncoding.Decode(buf, b32)
	if err == nil && n >= oboron.MarkerSize {
		marker := [2]byte{buf[n-2] ^ buf[0], buf[n-1] ^ buf[0]}
		if marker == zrbcxMarker {
			return z.tryDecodeZrbcx(buf[:n-oboron.MarkerSize])
		}
	}

	// Step 2: marker-less legacy (reverse + uppercase, decode, CBC).
	for i := 0; i < encLen; i++ {
		b := s[encLen-1-i]
		if b >= 'a' && b <= 'z' {
			b -= 32
		}
		b32[i] = b
	}
	for i := encLen; i < b32Len; i++ {
		b32[i] = '='
	}
	buf = buf[:cap(buf)]
	n, err = base32.StdEncoding.Decode(buf, b32)
	if err != nil {
		return "", oboron.ErrInvalidBase32
	}
	return z.decryptLegacyBytes(buf[:n])
}

// decodeAutodetectAnyEncoding tries every known text encoding.
func (z *zcodec) decodeAutodetectAnyEncoding(s string) (string, error) {
	for _, textEnc := range []oboron.Encoding{oboron.EncodingB32, oboron.EncodingC32, oboron.EncodingB64, oboron.EncodingHex} {
		if result, err := z.decodeAutodetectWith(s, textEnc); err == nil {
			return result, nil
		}
	}
	return "", oboron.ErrDecryptionFailed
}

// encodeScheme dispatches z-tier encoding by scheme.
func (z *zcodec) encodeScheme(s string, scheme oboron.Scheme, enc oboron.Encoding) (string, error) {
	switch scheme {
	case oboron.SchemeZrbcx:
		return z.encodeZrbcx(s, enc)
	case oboron.SchemeLegacy:
		return z.encodeLegacy(s, enc)
	default:
		return "", oboron.ErrInvalidFormat
	}
}

// decodeScheme dispatches strict z-tier decoding by scheme.
func (z *zcodec) decodeScheme(s string, scheme oboron.Scheme, enc oboron.Encoding) (string, error) {
	switch scheme {
	case oboron.SchemeZrbcx:
		return z.decodeZrbcx(s, enc)
	case oboron.SchemeLegacy:
		return z.decodeLegacy(s, enc)
	default:
		return "", oboron.ErrInvalidFormat
	}
}
