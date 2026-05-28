package oboron

//go:generate go run ../scripts/gen-codecs

// Ob is the a/u-tier runtime-format codec: one instance carries a single
// format (scheme + encoding), chosen at construction and changeable via the
// setters. It is the Go analog of Rust's `Ob`. The z-tier (zrbcx, legacy)
// lives in the isolated oboron/ztier subpackage and is not reachable here.
//
// For a format that never changes, prefer a fixed type (AasvC32, …); for a
// format chosen per operation, use Omnib.
type Ob struct {
	codec  *codec
	format Format
}

// New creates an Ob for an a/u-tier format ("aasv.c32", "aags.b64", …) from a
// key string. The key encoding is auto-detected by length (spec §3.4): 128 hex
// chars (canonical) or 86 base64url chars (deprecated). z-tier formats (zrbcx,
// legacy) are rejected with ErrInvalidFormat — use oboron/ztier.
func New(format string, key string) (*Ob, error) {
	f, err := parseAUFormat(format)
	if err != nil {
		return nil, err
	}
	mk, err := MasterKeyFromString(key)
	if err != nil {
		return nil, err
	}
	return newOb(f, mk.Bytes())
}

// NewObFromBytes creates an Ob from a raw 64-byte master key (spec §4.2).
func NewObFromBytes(format string, key []byte) (*Ob, error) {
	f, err := parseAUFormat(format)
	if err != nil {
		return nil, err
	}
	return newOb(f, key)
}

// NewObKeyless creates an Ob with the hardcoded key (testing only — NOT SECURE).
func NewObKeyless(format string) (*Ob, error) {
	return NewObFromBytes(format, HardcodedKey)
}

func newOb(f Format, key []byte) (*Ob, error) {
	cd, err := newCodec(key)
	if err != nil {
		return nil, err
	}
	return &Ob{codec: cd, format: f}, nil
}

// parseAUFormat parses format and requires it to be an a/u-tier format.
func parseAUFormat(format string) (Format, error) {
	f, err := ParseFormat(format)
	if err != nil {
		return Format{}, err
	}
	if f.scheme.IsZTier() {
		return Format{}, ErrInvalidFormat
	}
	return f, nil
}

// Enc encrypts and encodes plaintext under the configured format. Empty
// plaintext is rejected (spec §4.1).
func (ob *Ob) Enc(plaintext string) (string, error) {
	return ob.codec.encodeScheme(plaintext, ob.format.scheme, ob.format.encoding)
}

// Dec decodes and decrypts obtext using the configured format (strict — no
// scheme autodetection; use Autodec for that).
func (ob *Ob) Dec(obtext string) (string, error) {
	return ob.codec.decodeScheme(obtext, ob.format.scheme, ob.format.encoding)
}

// Autodec decodes obtext, auto-detecting the a/u scheme. It tries the
// configured encoding first (fast path), then every other encoding.
func (ob *Ob) Autodec(obtext string) (string, error) {
	if result, err := ob.codec.decodeAutodetectWith(obtext, ob.format.encoding); err == nil {
		return result, nil
	}
	return ob.codec.decodeAutodetectAnyEncoding(obtext)
}

// Format returns the configured format (scheme + encoding).
func (ob *Ob) Format() Format { return ob.format }

// Scheme returns the configured scheme.
func (ob *Ob) Scheme() Scheme { return ob.format.scheme }

// Encoding returns the configured encoding.
func (ob *Ob) Encoding() Encoding { return ob.format.encoding }

// SetFormat changes the format to another a/u-tier format string.
func (ob *Ob) SetFormat(format string) error {
	f, err := parseAUFormat(format)
	if err != nil {
		return err
	}
	ob.format = f
	return nil
}

// SetScheme changes the scheme (keeping the current encoding). z-tier schemes
// are rejected.
func (ob *Ob) SetScheme(scheme Scheme) error {
	if scheme.IsZTier() {
		return ErrInvalidFormat
	}
	if _, ok := obcryptScheme(scheme); !ok {
		return ErrUnknownScheme
	}
	ob.format = Format{scheme: scheme, encoding: ob.format.encoding}
	return nil
}

// SetEncoding changes the encoding (keeping the current scheme).
func (ob *Ob) SetEncoding(enc Encoding) error {
	ob.format = Format{scheme: ob.format.scheme, encoding: enc}
	return nil
}

// Key returns the 128-character hex master key.
func (ob *Ob) Key() string { return ob.codec.obKey.Hex() }

// KeyBytes returns a copy of the raw 64-byte master key.
func (ob *Ob) KeyBytes() []byte { return ob.codec.obKey.Bytes() }
