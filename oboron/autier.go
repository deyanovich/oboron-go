package oboron

import "oboron.org/go/obcrypt"

// This file is the a-tier / u-tier bridge: the secure schemes' crypto lives in
// the obcrypt package (bytes-in / bytes-out); here we only wrap it with obtext
// encoding. encodeAU produces framed bytes via obcrypt then encodes them;
// decodeAU decodes the text then hands the framed bytes back to obcrypt. The
// z-tier schemes (zrbcx, legacy) are not crypto and keep their implementations
// in zrbcx.go / legacy.go.

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

// --- per-scheme codec methods (referenced by Oboron/Omnib dispatch and the
// scheme conformance tests). Each is a thin wrapper over encodeAU/decodeAU. ---

func (c *codec) encodeAasvWith(s string, enc Encoding) (string, error) {
	return c.encodeAU(s, obcrypt.Aasv, enc)
}
func (c *codec) decodeAasvWith(s string, enc Encoding) (string, error) {
	return c.decodeAU(s, obcrypt.Aasv, enc)
}
func (c *codec) encodeAasv(s string) (string, error) { return c.encodeAasvWith(s, EncodingB32) }
func (c *codec) decodeAasv(s string) (string, error) { return c.decodeAasvWith(s, EncodingB32) }

func (c *codec) encodeApsvWith(s string, enc Encoding) (string, error) {
	return c.encodeAU(s, obcrypt.Apsv, enc)
}
func (c *codec) decodeApsvWith(s string, enc Encoding) (string, error) {
	return c.decodeAU(s, obcrypt.Apsv, enc)
}
func (c *codec) encodeApsv(s string) (string, error) { return c.encodeApsvWith(s, EncodingB32) }
func (c *codec) decodeApsv(s string) (string, error) { return c.decodeApsvWith(s, EncodingB32) }

func (c *codec) encodeAagsWith(s string, enc Encoding) (string, error) {
	return c.encodeAU(s, obcrypt.Aags, enc)
}
func (c *codec) decodeAagsWith(s string, enc Encoding) (string, error) {
	return c.decodeAU(s, obcrypt.Aags, enc)
}
func (c *codec) encodeAags(s string) (string, error) { return c.encodeAagsWith(s, EncodingB32) }
func (c *codec) decodeAags(s string) (string, error) { return c.decodeAagsWith(s, EncodingB32) }

func (c *codec) encodeApgsWith(s string, enc Encoding) (string, error) {
	return c.encodeAU(s, obcrypt.Apgs, enc)
}
func (c *codec) decodeApgsWith(s string, enc Encoding) (string, error) {
	return c.decodeAU(s, obcrypt.Apgs, enc)
}
func (c *codec) encodeApgs(s string) (string, error) { return c.encodeApgsWith(s, EncodingB32) }
func (c *codec) decodeApgs(s string) (string, error) { return c.decodeApgsWith(s, EncodingB32) }

func (c *codec) encodeUpbcWith(s string, enc Encoding) (string, error) {
	return c.encodeAU(s, obcrypt.Upbc, enc)
}
func (c *codec) decodeUpbcWith(s string, enc Encoding) (string, error) {
	return c.decodeAU(s, obcrypt.Upbc, enc)
}
func (c *codec) encodeUpbc(s string) (string, error) { return c.encodeUpbcWith(s, EncodingB32) }
func (c *codec) decodeUpbc(s string) (string, error) { return c.decodeUpbcWith(s, EncodingB32) }
