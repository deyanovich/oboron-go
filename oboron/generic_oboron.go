package oboron

// Omnib is a multi-scheme encoder/decoder that supports all oboron schemes.
// It requires a format specification per operation, enabling simultaneous work
// with different formats. Use Autodec for decoding when the format is unknown.
//
// For production use with a single fixed format, prefer scheme-specific Oboron
// constructors (NewLegacy, NewZrbcx, etc.) which carry the format in the instance.
type Omnib struct {
	codec *codec
}

// NewOmnib creates an Omnib instance with a 64-byte key.
func NewOmnib(key []byte) (*Omnib, error) {
	cd, err := newCodec(key)
	if err != nil {
		return nil, err
	}
	return &Omnib{codec: cd}, nil
}

// NewOmnibKeyless creates an Omnib instance with the hardcoded key (testing only).
func NewOmnibKeyless() (*Omnib, error) {
	return NewOmnib(HardcodedKey)
}

// NewOmnibFromMasterKey creates an Omnib from a MasterKey (64 bytes).
// Supports all schemes including z-tier (first 32 bytes used as secret).
func NewOmnibFromMasterKey(mk *MasterKey) (*Omnib, error) {
	if mk.IsZeroized() {
		return nil, ErrMasterKeyZeroized
	}
	return NewOmnib(mk.Bytes())
}

// NewOmnibFromSecret creates an Omnib from a Secret (32 bytes).
// Only supports z-tier schemes (legacy, zrbcx). Secure schemes will use
// the zero-padded key which may produce different results from MasterKey.
func NewOmnibFromSecret(s *Secret) (*Omnib, error) {
	key := make([]byte, 64)
	copy(key, s.internalSecret())
	return NewOmnib(key)
}

// Key returns the codec's key. Always 64 bytes when created via NewOmnib or any other constructor,
// which validates the key length at construction time.
func (g *Omnib) Key() []byte {
	return g.codec.obKey.Bytes()
}

// Enc encodes a string using the given format string (e.g., "aasv.c32").
// This is the primary encoding method, combining encryption and encoding.
func (g *Omnib) Enc(s string, format string) (string, error) {
	return g.EncodeWithFormat(s, format)
}

// Dec decodes an obtext string using the given format string.
// The scheme in the format selects the decryption algorithm; the encoding
// specifies the text representation. This is a strict decode (no autodetection).
func (g *Omnib) Dec(s string, format string) (string, error) {
	return g.DecodeWithFormat(s, format)
}

// Autodec decodes an obtext string by autodetecting both the scheme and encoding.
// Tries all known encodings and schemes until one succeeds. Use when the format
// is not known in advance. For better performance when encoding is known, use
// DecodeWithEncoding instead.
func (g *Omnib) Autodec(s string) (string, error) {
	return g.codec.decodeAutodetectAnyEncoding(s)
}

// Encode methods for all schemes
func (g *Omnib) EncodeLegacy(s string) (string, error) {
	return g.codec.encodeLegacy(s)
}

func (g *Omnib) EncodeZrbcx(s string) (string, error) {
	return g.codec.encodeZrbcx(s)
}

func (g *Omnib) EncodeAags(s string) (string, error) {
	return g.codec.encodeAags(s)
}

func (g *Omnib) EncodeAasv(s string) (string, error) {
	return g.codec.encodeAasv(s)
}

func (g *Omnib) EncodeApgs(s string) (string, error) {
	return g.codec.encodeApgs(s)
}

func (g *Omnib) EncodeApsv(s string) (string, error) {
	return g.codec.encodeApsv(s)
}

func (g *Omnib) EncodeUpbc(s string) (string, error) {
	return g.codec.encodeUpbc(s)
}

// Encode*Keyless functions encode using the hardcoded key (testing only).
func EncodeLegacyKeyless(s string) (string, error) {
	g, err := NewOmnibKeyless()
	if err != nil {
		return "", err
	}
	return g.codec.encodeLegacy(s)
}

func EncodeZrbcxKeyless(s string) (string, error) {
	g, err := NewOmnibKeyless()
	if err != nil {
		return "", err
	}
	return g.codec.encodeZrbcx(s)
}

func EncodeAagsKeyless(s string) (string, error) {
	g, err := NewOmnibKeyless()
	if err != nil {
		return "", err
	}
	return g.codec.encodeAags(s)
}

func EncodeAasvKeyless(s string) (string, error) {
	g, err := NewOmnibKeyless()
	if err != nil {
		return "", err
	}
	return g.codec.encodeAasv(s)
}

func EncodeApgsKeyless(s string) (string, error) {
	g, err := NewOmnibKeyless()
	if err != nil {
		return "", err
	}
	return g.codec.encodeApgs(s)
}

func EncodeApsvKeyless(s string) (string, error) {
	g, err := NewOmnibKeyless()
	if err != nil {
		return "", err
	}
	return g.codec.encodeApsv(s)
}

func EncodeUpbcKeyless(s string) (string, error) {
	g, err := NewOmnibKeyless()
	if err != nil {
		return "", err
	}
	return g.codec.encodeUpbc(s)
}

// Decode autodetects the scheme and decodes using default B32 encoding.
func (g *Omnib) Decode(s string) (string, error) {
	return g.codec.decodeAutodetect(s)
}

func (g *Omnib) DecodeLegacy(s string) (string, error) {
	return g.codec.decodeLegacy(s)
}

func (g *Omnib) DecodeZrbcx(s string) (string, error) {
	return g.codec.decodeZrbcx(s)
}

func (g *Omnib) DecodeAags(s string) (string, error) {
	return g.codec.decodeAags(s)
}

func (g *Omnib) DecodeAasv(s string) (string, error) {
	return g.codec.decodeAasv(s)
}

func (g *Omnib) DecodeApgs(s string) (string, error) {
	return g.codec.decodeApgs(s)
}

func (g *Omnib) DecodeApsv(s string) (string, error) {
	return g.codec.decodeApsv(s)
}

func (g *Omnib) DecodeUpbc(s string) (string, error) {
	return g.codec.decodeUpbc(s)
}

// DecodeKeyless decodes using the hardcoded key with scheme autodetection.
func DecodeKeyless(s string) (string, error) {
	g, err := NewOmnibKeyless()
	if err != nil {
		return "", err
	}
	return g.codec.decodeAutodetect(s)
}

// --- Format-aware methods ---

// EncodeWithFormat encodes a string using a format string (e.g., "aasv.c32").
func (g *Omnib) EncodeWithFormat(s string, format string) (string, error) {
	f, err := ParseFormat(format)
	if err != nil {
		return "", err
	}
	return g.encodeSchemeWith(s, f.Scheme(), f.Encoding())
}

// DecodeWithFormat decodes a string using a specific format string.
// The scheme in the format is used for decryption; the encoding for text decoding.
func (g *Omnib) DecodeWithFormat(s string, format string) (string, error) {
	f, err := ParseFormat(format)
	if err != nil {
		return "", err
	}
	return g.decodeSchemeWith(s, f.Scheme(), f.Encoding())
}

// DecodeWithEncoding decodes a string with scheme autodetection using a specific text encoding.
func (g *Omnib) DecodeWithEncoding(s string, enc Encoding) (string, error) {
	return g.codec.decodeAutodetectWith(s, enc)
}

// DecodeAny tries all encodings to decode a string, autodetecting both scheme and encoding.
func (g *Omnib) DecodeAny(s string) (string, error) {
	return g.codec.decodeAutodetectAnyEncoding(s)
}

// encodeSchemeWith dispatches encoding to the appropriate scheme with a specific text encoding.
func (g *Omnib) encodeSchemeWith(s string, scheme Scheme, enc Encoding) (string, error) {
	switch scheme {
	case SchemeLegacy:
		return g.codec.encodeLegacyWith(s, enc)
	case SchemeZrbcx:
		return g.codec.encodeZrbcxWith(s, enc)
	case SchemeAags:
		return g.codec.encodeAagsWith(s, enc)
	case SchemeAasv:
		return g.codec.encodeAasvWith(s, enc)
	case SchemeApgs:
		return g.codec.encodeApgsWith(s, enc)
	case SchemeApsv:
		return g.codec.encodeApsvWith(s, enc)
	case SchemeUpbc:
		return g.codec.encodeUpbcWith(s, enc)
	default:
		return "", ErrUnknownScheme
	}
}

// decodeSchemeWith dispatches decoding to the appropriate scheme with a specific text encoding.
func (g *Omnib) decodeSchemeWith(s string, scheme Scheme, enc Encoding) (string, error) {
	switch scheme {
	case SchemeLegacy:
		return g.codec.decodeLegacyWith(s, enc)
	case SchemeZrbcx:
		return g.codec.decodeZrbcxWith(s, enc)
	case SchemeAags:
		return g.codec.decodeAagsWith(s, enc)
	case SchemeAasv:
		return g.codec.decodeAasvWith(s, enc)
	case SchemeApgs:
		return g.codec.decodeApgsWith(s, enc)
	case SchemeApsv:
		return g.codec.decodeApsvWith(s, enc)
	case SchemeUpbc:
		return g.codec.decodeUpbcWith(s, enc)
	default:
		return "", ErrUnknownScheme
	}
}
