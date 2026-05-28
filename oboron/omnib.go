package oboron

// Omnib is the a/u-tier multi-format codec: it takes a format on every call,
// so one instance can encode/decode across all a/u-tier formats under a single
// key. The Go analog of Rust's `Omnib`. For decoding when the format is
// unknown, use Autodec. The z-tier equivalent is ztier.Omnibz.
//
// Omnib deliberately does not satisfy the Codec interface — its Enc/Dec take a
// format argument.
type Omnib struct {
	codec *codec
}

// NewOmnib creates an Omnib from a key string. The key encoding is
// auto-detected by length (spec §3.4): 128 hex chars (canonical) or 86
// base64url chars (deprecated).
func NewOmnib(key string) (*Omnib, error) {
	mk, err := MasterKeyFromString(key)
	if err != nil {
		return nil, err
	}
	return NewOmnibFromBytes(mk.Bytes())
}

// NewOmnibFromBytes creates an Omnib from a raw 64-byte master key (spec §4.2).
func NewOmnibFromBytes(key []byte) (*Omnib, error) {
	cd, err := newCodec(key)
	if err != nil {
		return nil, err
	}
	return &Omnib{codec: cd}, nil
}

// NewOmnibKeyless creates an Omnib with the hardcoded key (testing only — NOT SECURE).
func NewOmnibKeyless() (*Omnib, error) {
	return NewOmnibFromBytes(HardcodedKey)
}

// Enc encrypts and encodes plaintext under the given a/u-tier format string
// (e.g. "aasv.c32"). Empty plaintext is rejected (spec §4.1).
func (g *Omnib) Enc(plaintext string, format string) (string, error) {
	f, err := parseAUFormat(format)
	if err != nil {
		return "", err
	}
	return g.codec.encodeScheme(plaintext, f.scheme, f.encoding)
}

// Dec decodes and decrypts obtext under the given a/u-tier format string
// (strict — no autodetection).
func (g *Omnib) Dec(obtext string, format string) (string, error) {
	f, err := parseAUFormat(format)
	if err != nil {
		return "", err
	}
	return g.codec.decodeScheme(obtext, f.scheme, f.encoding)
}

// Autodec decodes obtext by auto-detecting both the a/u scheme and the
// encoding. Use when the format is unknown.
func (g *Omnib) Autodec(obtext string) (string, error) {
	return g.codec.decodeAutodetectAnyEncoding(obtext)
}

// Key returns the 128-character hex master key.
func (g *Omnib) Key() string { return g.codec.obKey.Hex() }

// KeyBytes returns a copy of the raw 64-byte master key.
func (g *Omnib) KeyBytes() []byte { return g.codec.obKey.Bytes() }
