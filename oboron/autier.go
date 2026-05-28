package oboron

import "oboron.org/go/obcrypt"

// This file is the a-tier / u-tier bridge: the secure schemes' crypto lives in
// the obcrypt package (bytes-in / bytes-out); here we only wrap it with obtext
// encoding. encodeAU produces framed bytes via obcrypt then encodes them;
// decodeAU decodes the text then hands the framed bytes back to obcrypt. The
// z-tier schemes (zrbcx, legacy) are not crypto and live in the oboron/ztier
// subpackage.

// encodeAU encrypts s under an obcrypt scheme and encodes the framed payload.
func (c *codec) encodeAU(s string, scheme obcrypt.Scheme, enc Encoding) (string, error) {
	if len(s) == 0 {
		return "", ErrEmptyString
	}
	framed, err := obcrypt.Encrypt([]byte(s), scheme, c.obKey)
	if err != nil {
		return "", err
	}
	return encodeToText(framed, enc), nil
}

// decodeAU decodes obtext to framed bytes and decrypts them as a specific
// obcrypt scheme (strict: the recovered marker must match).
func (c *codec) decodeAU(s string, scheme obcrypt.Scheme, enc Encoding) (string, error) {
	buf, err := decodeFromText(s, enc)
	if err != nil {
		return "", ErrInvalidEncoding
	}
	pt, err := obcrypt.DecryptAs(buf, scheme, c.obKey)
	if err != nil {
		return "", ErrDecryptionFailed
	}
	return string(pt), nil
}

// obcryptScheme maps an oboron a/u-tier scheme to its obcrypt counterpart.
// The boolean is false for z-tier or unknown schemes, which obcrypt does not
// handle.
func obcryptScheme(scheme Scheme) (obcrypt.Scheme, bool) {
	switch scheme {
	case SchemeAasv:
		return obcrypt.Aasv, true
	case SchemeApsv:
		return obcrypt.Apsv, true
	case SchemeAags:
		return obcrypt.Aags, true
	case SchemeApgs:
		return obcrypt.Apgs, true
	case SchemeUpbc:
		return obcrypt.Upbc, true
	default:
		return 0, false
	}
}

// encodeScheme dispatches encoding to the requested a/u-tier scheme. Shared by
// Ob (fixed format) and Omnib (per-call format).
func (c *codec) encodeScheme(s string, scheme Scheme, enc Encoding) (string, error) {
	oc, ok := obcryptScheme(scheme)
	if !ok {
		return "", ErrInvalidFormat
	}
	return c.encodeAU(s, oc, enc)
}

// decodeScheme dispatches strict decoding to the requested a/u-tier scheme.
func (c *codec) decodeScheme(s string, scheme Scheme, enc Encoding) (string, error) {
	oc, ok := obcryptScheme(scheme)
	if !ok {
		return "", ErrInvalidFormat
	}
	return c.decodeAU(s, oc, enc)
}
