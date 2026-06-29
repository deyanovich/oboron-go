package obu

import "oboron.org/go/oboron"

// Obu is the obu runtime-format codec — the Go analog of Rust's `Obu`. One
// instance carries a single obu format (upcbc.* or zdcbc.*), chosen at
// construction and changeable via the setters, keyed by a 256-bit Secret.
//
// For a fixed format prefer a fixed type (UpcbcC32, ZdcbcC32, …); for a format
// chosen per call use Omnibu.
type Obu struct {
	codec  *codec
	format oboron.Format
	secret *Secret
}

// NewObu creates an Obu for an obu format ("upcbc.c32", "zdcbc.b64", …) from a
// secret string (64 hex chars). Authenticated formats are rejected with
// ErrInvalidFormat — use package oboron.
func NewObu(format string, secret string) (*Obu, error) {
	f, err := parseObuFormat(format)
	if err != nil {
		return nil, err
	}
	s, err := SecretFromString(secret)
	if err != nil {
		return nil, err
	}
	return newObu(f, s)
}

// NewObuFromBytes creates an Obu from a raw 32-byte secret (spec §4.2).
func NewObuFromBytes(format string, secret []byte) (*Obu, error) {
	f, err := parseObuFormat(format)
	if err != nil {
		return nil, err
	}
	s, err := NewSecret(secret)
	if err != nil {
		return nil, err
	}
	return newObu(f, s)
}

// NewObuKeyless creates an Obu with the hardcoded secret (testing only — NOT
// SECURE).
func NewObuKeyless(format string) (*Obu, error) {
	f, err := parseObuFormat(format)
	if err != nil {
		return nil, err
	}
	return newObu(f, HardcodedSecret())
}

func newObu(f oboron.Format, s *Secret) (*Obu, error) {
	cd, err := newCodec(s)
	if err != nil {
		return nil, err
	}
	return &Obu{codec: cd, format: f, secret: s}, nil
}

// parseObuFormat parses format and requires it to be an obu format.
func parseObuFormat(format string) (oboron.Format, error) {
	f, err := oboron.ParseFormat(format)
	if err != nil {
		return oboron.Format{}, err
	}
	if !f.Scheme().IsObu() {
		return oboron.Format{}, oboron.ErrInvalidFormat
	}
	return f, nil
}

// Enc encrypts/obfuscates and encodes plaintext under the configured format.
// Empty plaintext is rejected (spec §4.1).
func (ob *Obu) Enc(plaintext string) (string, error) {
	return ob.codec.encodeScheme(plaintext, ob.format.Scheme(), ob.format.Encoding())
}

// Dec decodes and decrypts/de-obfuscates obtext using the configured format.
// obtext carries no scheme marker, so the format must match the encode.
func (ob *Obu) Dec(obtext string) (string, error) {
	return ob.codec.decodeScheme(obtext, ob.format.Scheme(), ob.format.Encoding())
}

// Format returns the configured format (scheme + encoding).
func (ob *Obu) Format() oboron.Format { return ob.format }

// Scheme returns the configured scheme.
func (ob *Obu) Scheme() oboron.Scheme { return ob.format.Scheme() }

// Encoding returns the configured encoding.
func (ob *Obu) Encoding() oboron.Encoding { return ob.format.Encoding() }

// SetFormat changes the format to another obu format string.
func (ob *Obu) SetFormat(format string) error {
	f, err := parseObuFormat(format)
	if err != nil {
		return err
	}
	ob.format = f
	return nil
}

// SetScheme changes the scheme (keeping the current encoding). Only obu schemes
// are accepted.
func (ob *Obu) SetScheme(scheme oboron.Scheme) error {
	if !scheme.IsObu() {
		return oboron.ErrInvalidFormat
	}
	ob.format = oboron.NewFormat(scheme, ob.format.Encoding())
	return nil
}

// SetEncoding changes the encoding (keeping the current scheme).
func (ob *Obu) SetEncoding(enc oboron.Encoding) error {
	ob.format = oboron.NewFormat(ob.format.Scheme(), enc)
	return nil
}

// Secret returns the 64-character hex secret.
func (ob *Obu) Secret() string { return ob.secret.Hex() }

// SecretBytes returns a copy of the raw 32-byte secret.
func (ob *Obu) SecretBytes() []byte { return ob.secret.Bytes() }
