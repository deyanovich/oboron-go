package ztier

import "oboron.org/go/oboron"

// Obz is the z-tier runtime-format codec — the Go analog of Rust's `Obz`. One
// instance carries a single z-tier format (zrbcx.* or legacy), chosen at
// construction and changeable via the setters, keyed by a 256-bit Secret.
//
// For a fixed format prefer a fixed type (ZrbcxC32, Legacy, …); for a format
// chosen per call use Omnibz.
type Obz struct {
	codec  *zcodec
	format oboron.Format
	secret *Secret
}

// NewObz creates an Obz for a z-tier format ("zrbcx.c32", "zrbcx.b64",
// "legacy", …) from a secret string. The secret encoding is auto-detected by
// length: 64 hex chars (canonical) or 43 base64url chars (deprecated). a/u-tier
// formats are rejected with ErrInvalidFormat — use package oboron.
func NewObz(format string, secret string) (*Obz, error) {
	f, err := parseZFormat(format)
	if err != nil {
		return nil, err
	}
	s, err := SecretFromString(secret)
	if err != nil {
		return nil, err
	}
	return newObz(f, s)
}

// NewObzFromBytes creates an Obz from a raw 32-byte secret (spec §4.2).
func NewObzFromBytes(format string, secret []byte) (*Obz, error) {
	f, err := parseZFormat(format)
	if err != nil {
		return nil, err
	}
	s, err := NewSecret(secret)
	if err != nil {
		return nil, err
	}
	return newObz(f, s)
}

// NewObzKeyless creates an Obz with the hardcoded secret (testing/obfuscation
// only — NOT SECURE).
func NewObzKeyless(format string) (*Obz, error) {
	f, err := parseZFormat(format)
	if err != nil {
		return nil, err
	}
	return newObz(f, HardcodedSecret())
}

func newObz(f oboron.Format, s *Secret) (*Obz, error) {
	cd, err := newZcodec(s)
	if err != nil {
		return nil, err
	}
	return &Obz{codec: cd, format: f, secret: s}, nil
}

// parseZFormat parses format and requires it to be a z-tier format.
func parseZFormat(format string) (oboron.Format, error) {
	f, err := oboron.ParseFormat(format)
	if err != nil {
		return oboron.Format{}, err
	}
	if !f.Scheme().IsZTier() {
		return oboron.Format{}, oboron.ErrInvalidFormat
	}
	return f, nil
}

// Enc obfuscates and encodes plaintext under the configured format. Empty
// plaintext is rejected (spec §4.1).
func (ob *Obz) Enc(plaintext string) (string, error) {
	return ob.codec.encodeScheme(plaintext, ob.format.Scheme(), ob.format.Encoding())
}

// Dec decodes and de-obfuscates obtext using the configured format (strict — no
// scheme autodetection; use Autodec for that).
func (ob *Obz) Dec(obtext string) (string, error) {
	return ob.codec.decodeScheme(obtext, ob.format.Scheme(), ob.format.Encoding())
}

// Autodec decodes obtext, auto-detecting the z-tier scheme. It tries the
// configured encoding first (fast path), then every other encoding.
func (ob *Obz) Autodec(obtext string) (string, error) {
	if result, err := ob.codec.decodeAutodetectWith(obtext, ob.format.Encoding()); err == nil {
		return result, nil
	}
	return ob.codec.decodeAutodetectAnyEncoding(obtext)
}

// Format returns the configured format (scheme + encoding).
func (ob *Obz) Format() oboron.Format { return ob.format }

// Scheme returns the configured scheme.
func (ob *Obz) Scheme() oboron.Scheme { return ob.format.Scheme() }

// Encoding returns the configured encoding.
func (ob *Obz) Encoding() oboron.Encoding { return ob.format.Encoding() }

// SetFormat changes the format to another z-tier format string.
func (ob *Obz) SetFormat(format string) error {
	f, err := parseZFormat(format)
	if err != nil {
		return err
	}
	ob.format = f
	return nil
}

// SetScheme changes the scheme (keeping the current encoding). Only z-tier
// schemes are accepted.
func (ob *Obz) SetScheme(scheme oboron.Scheme) error {
	if !scheme.IsZTier() {
		return oboron.ErrInvalidFormat
	}
	ob.format = oboron.NewFormat(scheme, ob.format.Encoding())
	return nil
}

// SetEncoding changes the encoding (keeping the current scheme).
func (ob *Obz) SetEncoding(enc oboron.Encoding) error {
	ob.format = oboron.NewFormat(ob.format.Scheme(), enc)
	return nil
}

// Secret returns the 64-character hex secret.
func (ob *Obz) Secret() string { return ob.secret.Hex() }

// SecretBytes returns a copy of the raw 32-byte secret.
func (ob *Obz) SecretBytes() []byte { return ob.secret.Bytes() }
