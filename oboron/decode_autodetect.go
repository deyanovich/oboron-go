package oboron

import (
	"crypto/cipher"
	"encoding/base32"

	"oboron.org/go/obcrypt"
)

// decodeAutodetect decodes a string, auto-detecting the encryption scheme.
// Uses default B32 encoding for backward compatibility.
func (c *codec) decodeAutodetect(enc string) (string, error) {
	return c.decodeAutodetectWith(enc, EncodingB32)
}

// decodeAutodetectWith decodes a string using a specific text encoding,
// auto-detecting the scheme via the 2-byte XOR marker. a/u-tier schemes are
// resolved by obcrypt; the z-tier zrbcx marker and the marker-less legacy
// scheme are resolved here.
func (c *codec) decodeAutodetectWith(enc string, textEnc Encoding) (string, error) {
	if textEnc == EncodingB32 {
		return c.decodeAutodetectB32(enc)
	}

	// Generic path for non-B32 encodings.
	buf, err := decodeFromText(enc, textEnc)
	if err != nil {
		return "", ErrInvalidEncoding
	}

	if n := len(buf); n >= MarkerSize {
		if res, done, rerr := c.tryAUThenZrbcx(buf); done {
			return res, rerr
		}
	}

	// Fall through to the marker-less legacy scheme: reverse, decode, CBC.
	reversed := reverseString(enc)
	buf, err = decodeFromText(reversed, textEnc)
	if err != nil {
		return "", ErrInvalidEncoding
	}
	return c.decryptLegacyBytes(buf)
}

// decodeAutodetectB32 is the optimized B32 autodetect path.
func (c *codec) decodeAutodetectB32(enc string) (string, error) {
	encLen := len(enc)
	padding := (8 - (encLen % 8)) % 8
	b32Len := encLen + padding

	// Reusable b32 buffer (marker-based attempt, then legacy attempt).
	b32 := make([]byte, b32Len)

	// Step 1: marker-based schemes (uppercase, no reversal).
	for i := 0; i < encLen; i++ {
		b := enc[i]
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
	if err == nil && n >= MarkerSize {
		if res, done, rerr := c.tryAUThenZrbcx(buf[:n]); done {
			return res, rerr
		}
	}

	// Step 2: marker-less legacy scheme (reverse + uppercase, decode, CBC).
	for i := 0; i < encLen; i++ {
		b := enc[encLen-1-i]
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
		return "", ErrInvalidBase32
	}
	return c.decryptLegacyBytes(buf[:n])
}

// tryAUThenZrbcx attempts to decrypt a framed payload as an a/u-tier scheme
// (via obcrypt) and then as the z-tier zrbcx scheme. done is true when the
// payload's marker was recognized — meaning the result is terminal (the caller
// must not fall through to legacy), whether decryption succeeded or failed.
// done is false only when the marker is not an a/u or zrbcx marker.
func (c *codec) tryAUThenZrbcx(buf []byte) (res string, done bool, err error) {
	pt, derr := obcrypt.Decrypt(buf, c.obKey)
	if derr == nil {
		return string(pt), true, nil
	}
	if derr != obcrypt.ErrUnknownScheme {
		// An a/u marker matched but the payload did not authenticate/decode.
		return "", true, ErrDecryptionFailed
	}

	// Not an a/u marker: is it zrbcx?
	n := len(buf)
	marker := [2]byte{buf[n-2] ^ buf[0], buf[n-1] ^ buf[0]}
	if marker == zrbcxMarker {
		out, zerr := c.tryDecodeZrbcx(buf[:n-MarkerSize])
		return out, true, zerr
	}
	return "", false, nil
}

// decryptLegacyBytes finishes a legacy decode given the (already reversed and
// decoded) ciphertext bytes: AES-128-CBC decrypt, then strip '=' padding.
func (c *codec) decryptLegacyBytes(buf []byte) (string, error) {
	if len(buf)%blockSize != 0 {
		return "", ErrDecryptionFailed
	}
	cipher.NewCBCDecrypter(c.block, c.iv).CryptBlocks(buf, buf)

	end := len(buf)
	for end > 0 && buf[end-1] == '=' {
		end--
	}
	return string(buf[:end]), nil
}

// decodeAutodetectAnyEncoding tries all known encodings to decode a string.
// Used when the encoding is not known. Returns the first successful decode.
func (c *codec) decodeAutodetectAnyEncoding(enc string) (string, error) {
	encodings := []Encoding{EncodingB32, EncodingC32, EncodingB64, EncodingHex}
	for _, textEnc := range encodings {
		result, err := c.decodeAutodetectWith(enc, textEnc)
		if err == nil {
			return result, nil
		}
	}
	return "", ErrDecryptionFailed
}

// tryDecodeZrbcx decodes marker-stripped zrbcx ciphertext bytes (z-tier,
// AES-128-CBC with prefix restructuring).
func (c *codec) tryDecodeZrbcx(data []byte) (string, error) {
	if len(data)%blockSize != 0 || len(data) < blockSize {
		return "", ErrDecryptionFailed
	}

	// Reverse the prefix restructuring (XOR first block with last) if multi-block.
	if len(data) > blockSize {
		for i := 0; i < blockSize; i++ {
			data[i] ^= data[len(data)-blockSize+i]
		}
	}

	cipher.NewCBCDecrypter(c.block, c.iv).CryptBlocks(data, data)

	end := len(data)
	for end > 0 && data[end-1] == 0x01 {
		end--
	}
	return string(data[:end]), nil
}
