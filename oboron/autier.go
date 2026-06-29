package oboron

import (
	"unicode/utf8"

	"oboron.org/go/obcrypt"
)

// This file is the authenticated-scheme bridge: the secure schemes' crypto
// lives in the obcrypt package (bytes-in / bytes-out); here we only wrap it
// with obtext encoding. encodeAU produces ciphertext via obcrypt then encodes
// it; decodeAU decodes the text then hands the ciphertext back to obcrypt. The
// obu schemes (upcbc, zdcbc) are handled by the separate obu package.

// encodeAU encrypts s under an obcrypt scheme and encodes the ciphertext.
func (c *codec) encodeAU(s string, scheme obcrypt.Scheme, enc Encoding) (string, error) {
	if len(s) == 0 {
		return "", ErrEmptyString
	}
	// oboron operates on UTF-8 text; reject non-UTF-8 input (spec §4.1).
	if !utf8.ValidString(s) {
		return "", ErrInvalidUTF8
	}
	ct, err := obcrypt.Encrypt([]byte(s), scheme, c.obKey)
	if err != nil {
		return "", err
	}
	return encodeToText(ct, enc), nil
}

// decodeAU decodes obtext to ciphertext bytes and decrypts them as a specific
// obcrypt scheme.
func (c *codec) decodeAU(s string, scheme obcrypt.Scheme, enc Encoding) (string, error) {
	buf, err := decodeFromText(s, enc)
	if err != nil {
		return "", ErrInvalidEncoding
	}
	pt, err := obcrypt.Decrypt(buf, scheme, c.obKey)
	if err != nil {
		return "", ErrDecryptionFailed
	}
	// dec MUST validate the decrypted bytes are UTF-8 and never return an
	// unchecked string (spec §4.1); report via the uniform decrypt error.
	if !utf8.Valid(pt) {
		return "", ErrDecryptionFailed
	}
	return string(pt), nil
}

// obcryptScheme maps an oboron authenticated scheme to its obcrypt counterpart.
// The boolean is false for obu or unknown schemes, which obcrypt does not
// handle.
func obcryptScheme(scheme Scheme) (obcrypt.Scheme, bool) {
	switch scheme {
	case SchemeDsiv:
		return obcrypt.Dsiv, true
	case SchemePsiv:
		return obcrypt.Psiv, true
	case SchemeDgcmsiv:
		return obcrypt.Dgcmsiv, true
	case SchemePgcmsiv:
		return obcrypt.Pgcmsiv, true
	default:
		return 0, false
	}
}

// encodeScheme dispatches encoding to the requested authenticated scheme.
// Shared by Ob (fixed format) and Omnib (per-call format).
func (c *codec) encodeScheme(s string, scheme Scheme, enc Encoding) (string, error) {
	oc, ok := obcryptScheme(scheme)
	if !ok {
		return "", ErrInvalidFormat
	}
	return c.encodeAU(s, oc, enc)
}

// decodeScheme dispatches decoding to the requested authenticated scheme.
func (c *codec) decodeScheme(s string, scheme Scheme, enc Encoding) (string, error) {
	oc, ok := obcryptScheme(scheme)
	if !ok {
		return "", ErrInvalidFormat
	}
	return c.decodeAU(s, oc, enc)
}
