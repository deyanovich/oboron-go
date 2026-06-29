package obu

// Omnibu is the obu multi-format codec — the Go analog of Rust's `Omnibu`. It
// takes a format on every call, so one instance can encode/decode across all
// obu formats under a single secret. The authenticated equivalent is
// oboron.Omnib.
//
// Like Omnib, Omnibu does not satisfy oboron.Codec — its Enc/Dec take a format
// argument.
type Omnibu struct {
	codec  *codec
	secret *Secret
}

// NewOmnibu creates an Omnibu from a secret string (64 hex chars).
func NewOmnibu(secret string) (*Omnibu, error) {
	s, err := SecretFromString(secret)
	if err != nil {
		return nil, err
	}
	return newOmnibu(s)
}

// NewOmnibuFromBytes creates an Omnibu from a raw 32-byte secret (spec §4.2).
func NewOmnibuFromBytes(secret []byte) (*Omnibu, error) {
	s, err := NewSecret(secret)
	if err != nil {
		return nil, err
	}
	return newOmnibu(s)
}

// NewOmnibuKeyless creates an Omnibu with the hardcoded secret (testing only —
// NOT SECURE).
func NewOmnibuKeyless() (*Omnibu, error) {
	return newOmnibu(HardcodedSecret())
}

func newOmnibu(s *Secret) (*Omnibu, error) {
	cd, err := newCodec(s)
	if err != nil {
		return nil, err
	}
	return &Omnibu{codec: cd, secret: s}, nil
}

// Enc encrypts/obfuscates and encodes plaintext under the given obu format
// string (e.g. "upcbc.c32", "zdcbc.b64"). Empty plaintext is rejected (spec
// §4.1).
func (g *Omnibu) Enc(plaintext string, format string) (string, error) {
	f, err := parseObuFormat(format)
	if err != nil {
		return "", err
	}
	return g.codec.encodeScheme(plaintext, f.Scheme(), f.Encoding())
}

// Dec decodes and decrypts/de-obfuscates obtext under the given obu format
// string. obtext carries no scheme marker, so the format must match the encode.
func (g *Omnibu) Dec(obtext string, format string) (string, error) {
	f, err := parseObuFormat(format)
	if err != nil {
		return "", err
	}
	return g.codec.decodeScheme(obtext, f.Scheme(), f.Encoding())
}

// Secret returns the 64-character hex secret.
func (g *Omnibu) Secret() string { return g.secret.Hex() }

// SecretBytes returns a copy of the raw 32-byte secret.
func (g *Omnibu) SecretBytes() []byte { return g.secret.Bytes() }
