package ztier

// Omnibz is the z-tier multi-format codec — the Go analog of Rust's `Omnibz`.
// It takes a format on every call, so one instance can encode/decode across all
// z-tier formats under a single secret. For decoding when the format is
// unknown, use Autodec. The a/u-tier equivalent is oboron.Omnib.
//
// Like Omnib, Omnibz does not satisfy oboron.Codec — its Enc/Dec take a format
// argument.
type Omnibz struct {
	codec  *zcodec
	secret *Secret
}

// NewOmnibz creates an Omnibz from a secret string. The secret encoding is
// auto-detected by length: 64 hex chars (canonical) or 43 base64url chars
// (deprecated).
func NewOmnibz(secret string) (*Omnibz, error) {
	s, err := SecretFromString(secret)
	if err != nil {
		return nil, err
	}
	return newOmnibz(s)
}

// NewOmnibzFromBytes creates an Omnibz from a raw 32-byte secret (spec §4.2).
func NewOmnibzFromBytes(secret []byte) (*Omnibz, error) {
	s, err := NewSecret(secret)
	if err != nil {
		return nil, err
	}
	return newOmnibz(s)
}

// NewOmnibzKeyless creates an Omnibz with the hardcoded secret (testing only — NOT SECURE).
func NewOmnibzKeyless() (*Omnibz, error) {
	return newOmnibz(HardcodedSecret())
}

func newOmnibz(s *Secret) (*Omnibz, error) {
	cd, err := newZcodec(s)
	if err != nil {
		return nil, err
	}
	return &Omnibz{codec: cd, secret: s}, nil
}

// Enc obfuscates and encodes plaintext under the given z-tier format string
// (e.g. "zrbcx.c32", "legacy"). Empty plaintext is rejected (spec §4.1).
func (g *Omnibz) Enc(plaintext string, format string) (string, error) {
	f, err := parseZFormat(format)
	if err != nil {
		return "", err
	}
	return g.codec.encodeScheme(plaintext, f.Scheme(), f.Encoding())
}

// Dec decodes and de-obfuscates obtext under the given z-tier format string
// (strict — no autodetection).
func (g *Omnibz) Dec(obtext string, format string) (string, error) {
	f, err := parseZFormat(format)
	if err != nil {
		return "", err
	}
	return g.codec.decodeScheme(obtext, f.Scheme(), f.Encoding())
}

// Autodec decodes obtext by auto-detecting both the z-tier scheme and the
// encoding. Use when the format is unknown.
func (g *Omnibz) Autodec(obtext string) (string, error) {
	return g.codec.decodeAutodetectAnyEncoding(obtext)
}

// Secret returns the 64-character hex secret.
func (g *Omnibz) Secret() string { return g.secret.Hex() }

// SecretBytes returns a copy of the raw 32-byte secret.
func (g *Omnibz) SecretBytes() []byte { return g.secret.Bytes() }
