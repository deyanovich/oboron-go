package oboron

import "oboron.org/go/obcrypt"

// a/u-tier scheme autodetection. obcrypt.Decrypt reads the 2-byte XOR marker
// off the framed payload and dispatches to the right a/u scheme; it returns
// obcrypt.ErrUnknownScheme for markers it does not recognise. The z-tier
// (zrbcx, legacy) has its own, separate autodetection in oboron/ztier — the
// two tiers never cross, mirroring the Rust dec_auto / ztier::zdec_auto split.

// decodeAutodetectWith decodes obtext under a known text encoding and
// auto-detects the a/u scheme via the marker.
func (c *codec) decodeAutodetectWith(s string, textEnc Encoding) (string, error) {
	buf, err := decodeFromText(s, textEnc)
	if err != nil {
		return "", ErrInvalidEncoding
	}
	pt, err := obcrypt.Decrypt(buf, c.obKey)
	if err != nil {
		return "", ErrDecryptionFailed
	}
	return string(pt), nil
}

// decodeAutodetectAnyEncoding tries every known text encoding, returning the
// first that both decodes and authenticates under some a/u scheme.
func (c *codec) decodeAutodetectAnyEncoding(s string) (string, error) {
	for _, textEnc := range []Encoding{EncodingB32, EncodingC32, EncodingB64, EncodingHex} {
		if result, err := c.decodeAutodetectWith(s, textEnc); err == nil {
			return result, nil
		}
	}
	return "", ErrDecryptionFailed
}
