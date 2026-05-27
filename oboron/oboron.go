package oboron

// Oboron codec encoding a pre-determined scheme
type Oboron struct {
	codec    *codec
	scheme   Scheme
	encoding Encoding
}

func (ob *Oboron) Key() []byte {
	return ob.codec.obKey.Bytes()
}

func (ob *Oboron) Scheme() Scheme {
	return ob.scheme
}

// Encoding returns the text encoding used by this Oboron instance.
func (ob *Oboron) Encoding() Encoding {
	return ob.encoding
}

// Format returns the Format (scheme + encoding) of this Oboron instance.
func (ob *Oboron) Format() Format {
	return NewFormat(ob.scheme, ob.encoding)
}

func newOboron(key []byte, scheme Scheme) (*Oboron, error) {
	return newOboronWithEncoding(key, scheme, DefaultEncoding)
}

func newOboronWithEncoding(key []byte, scheme Scheme, enc Encoding) (*Oboron, error) {
	cd, err := newCodec(key)
	if err != nil {
		return nil, err
	}
	return &Oboron{codec: cd, scheme: scheme, encoding: enc}, nil
}

// NewLegacy creates a legacy codec with a long key
func NewLegacy(key []byte) (*Oboron, error) {
	return newOboron(key, SchemeLegacy)
}

// NewLegacyKeyless creates a legacy codec with the hardcoded key (testing only)
func NewLegacyKeyless() (*Oboron, error) {
	return newOboron(HardcodedKey, SchemeLegacy)
}

// NewZrbcx creates a zrbcx codec with a long key
func NewZrbcx(key []byte) (*Oboron, error) {
	return newOboron(key, SchemeZrbcx)
}

// NewZrbcxKeyless creates a zrbcx codec with the hardcoded key (testing only)
func NewZrbcxKeyless() (*Oboron, error) {
	return newOboron(HardcodedKey, SchemeZrbcx)
}

// NewAags creates an aags codec with a long key (deterministic AES-GCM-SIV)
func NewAags(key []byte) (*Oboron, error) {
	return newOboron(key, SchemeAags)
}

// NewAagsKeyless creates an aags codec with the hardcoded key (testing only)
func NewAagsKeyless() (*Oboron, error) {
	return newOboron(HardcodedKey, SchemeAags)
}

// NewAasv creates an aasv codec with a long key (deterministic AES-SIV)
func NewAasv(key []byte) (*Oboron, error) {
	return newOboron(key, SchemeAasv)
}

// NewAasvKeyless creates an aasv codec with the hardcoded key (testing only)
func NewAasvKeyless() (*Oboron, error) {
	return newOboron(HardcodedKey, SchemeAasv)
}

// NewApgs creates an apgs codec with a long key (probabilistic AES-GCM-SIV)
func NewApgs(key []byte) (*Oboron, error) {
	return newOboron(key, SchemeApgs)
}

// NewApgsKeyless creates an apgs codec with the hardcoded key (testing only)
func NewApgsKeyless() (*Oboron, error) {
	return newOboron(HardcodedKey, SchemeApgs)
}

// NewApsv creates an apsv codec with a long key (probabilistic AES-SIV)
func NewApsv(key []byte) (*Oboron, error) {
	return newOboron(key, SchemeApsv)
}

// NewApsvKeyless creates an apsv codec with the hardcoded key (testing only)
func NewApsvKeyless() (*Oboron, error) {
	return newOboron(HardcodedKey, SchemeApsv)
}

// NewUpbc creates an upbc codec with a long key (probabilistic AES-256-CBC)
func NewUpbc(key []byte) (*Oboron, error) {
	return newOboron(key, SchemeUpbc)
}

// NewUpbcKeyless creates an upbc codec with the hardcoded key (testing only)
func NewUpbcKeyless() (*Oboron, error) {
	return newOboron(HardcodedKey, SchemeUpbc)
}

// --- MasterKey-based constructors (a-tier / u-tier secure schemes) ---

// newOboronFromMasterKey creates an Oboron from a MasterKey (64 bytes).
// Used for secure schemes: aags, aasv, apgs, apsv, upbc.
func newOboronFromMasterKey(mk *MasterKey, scheme Scheme) (*Oboron, error) {
	if mk.IsZeroized() {
		return nil, ErrMasterKeyZeroized
	}
	return newOboron(mk.Bytes(), scheme)
}

// NewAagsFromMasterKey creates an aags codec from a MasterKey (deterministic AES-GCM-SIV)
func NewAagsFromMasterKey(mk *MasterKey) (*Oboron, error) {
	return newOboronFromMasterKey(mk, SchemeAags)
}

// NewAasvFromMasterKey creates an aasv codec from a MasterKey (deterministic AES-SIV)
func NewAasvFromMasterKey(mk *MasterKey) (*Oboron, error) {
	return newOboronFromMasterKey(mk, SchemeAasv)
}

// NewApgsFromMasterKey creates an apgs codec from a MasterKey (probabilistic AES-GCM-SIV)
func NewApgsFromMasterKey(mk *MasterKey) (*Oboron, error) {
	return newOboronFromMasterKey(mk, SchemeApgs)
}

// NewApsvFromMasterKey creates an apsv codec from a MasterKey (probabilistic AES-SIV)
func NewApsvFromMasterKey(mk *MasterKey) (*Oboron, error) {
	return newOboronFromMasterKey(mk, SchemeApsv)
}

// NewUpbcFromMasterKey creates a upbc codec from a MasterKey (probabilistic AES-256-CBC)
func NewUpbcFromMasterKey(mk *MasterKey) (*Oboron, error) {
	return newOboronFromMasterKey(mk, SchemeUpbc)
}

// --- Format-based constructors ---

// New creates an Oboron instance from a format string (e.g., "aasv.c32", "legacy", "aags.hex")
// and a raw 64-byte key.
func New(format string, key []byte) (*Oboron, error) {
	f, err := ParseFormat(format)
	if err != nil {
		return nil, err
	}
	return newOboronWithEncoding(key, f.Scheme(), f.Encoding())
}

// NewKeylessFromFormat creates an Oboron instance from a format string with the hardcoded key (testing only).
func NewKeylessFromFormat(format string) (*Oboron, error) {
	f, err := ParseFormat(format)
	if err != nil {
		return nil, err
	}
	return newOboronWithEncoding(HardcodedKey, f.Scheme(), f.Encoding())
}

// NewFromFormat creates an Oboron instance from a Format struct and a raw 64-byte key.
func NewFromFormat(f Format, key []byte) (*Oboron, error) {
	return newOboronWithEncoding(key, f.Scheme(), f.Encoding())
}

// NewFromFormatMasterKey creates an Oboron instance from a Format and a MasterKey.
func NewFromFormatMasterKey(f Format, mk *MasterKey) (*Oboron, error) {
	if mk.IsZeroized() {
		return nil, ErrMasterKeyZeroized
	}
	return newOboronWithEncoding(mk.Bytes(), f.Scheme(), f.Encoding())
}

// --- Secret-based constructors (z-tier obfuscation schemes) ---

// newOboronFromSecret creates an Oboron from a Secret (32 bytes).
// The 32-byte secret is zero-padded to 64 bytes internally for codec compatibility.
// Used for z-tier schemes: legacy, zrbcx.
func newOboronFromSecret(s *Secret, scheme Scheme) (*Oboron, error) {
	// Build a 64-byte key by zero-padding the secret
	key := make([]byte, 64)
	copy(key, s.internalSecret())
	return newOboron(key, scheme)
}

// NewLegacyFromSecret creates a legacy codec from a Secret
func NewLegacyFromSecret(s *Secret) (*Oboron, error) {
	return newOboronFromSecret(s, SchemeLegacy)
}

// NewZrbcxFromSecret creates a zrbcx codec from a Secret
func NewZrbcxFromSecret(s *Secret) (*Oboron, error) {
	return newOboronFromSecret(s, SchemeZrbcx)
}

// Enc encodes a string using the scheme and encoding specified at construction.
// This is the primary encoding method, combining encryption and encoding.
func (ob *Oboron) Enc(s string) (string, error) {
	return ob.Encode(s)
}

// Encode encodes a string using the scheme and encoding specified at construction
func (ob *Oboron) Encode(s string) (string, error) {
	return ob.EncodeWithEncoding(s, ob.encoding)
}

// EncodeWithEncoding encodes a string using the stored scheme and a specified encoding.
func (ob *Oboron) EncodeWithEncoding(s string, enc Encoding) (string, error) {
	switch ob.scheme {
	case SchemeLegacy:
		return ob.codec.encodeLegacyWith(s, enc)
	case SchemeZrbcx:
		return ob.codec.encodeZrbcxWith(s, enc)
	case SchemeApgs:
		return ob.codec.encodeApgsWith(s, enc)
	case SchemeAags:
		return ob.codec.encodeAagsWith(s, enc)
	case SchemeApsv:
		return ob.codec.encodeApsvWith(s, enc)
	case SchemeAasv:
		return ob.codec.encodeAasvWith(s, enc)
	case SchemeUpbc:
		return ob.codec.encodeUpbcWith(s, enc)
	default:
		return "", ErrUnknownScheme
	}
}

// Decode decodes a string, auto-detecting the encryption scheme using the stored encoding.
func (ob *Oboron) Decode(s string) (string, error) {
	return ob.codec.decodeAutodetectWith(s, ob.encoding)
}

// Dec performs a strict decode using only the scheme and encoding specified at construction.
// Unlike Decode/Autodec, this does not attempt autodetection and will fail if the
// scheme or encoding does not match the one used for encoding.
func (ob *Oboron) Dec(s string) (string, error) {
	switch ob.scheme {
	case SchemeLegacy:
		return ob.codec.decodeLegacyWith(s, ob.encoding)
	case SchemeZrbcx:
		return ob.codec.decodeZrbcxWith(s, ob.encoding)
	case SchemeApgs:
		return ob.codec.decodeApgsWith(s, ob.encoding)
	case SchemeAags:
		return ob.codec.decodeAagsWith(s, ob.encoding)
	case SchemeApsv:
		return ob.codec.decodeApsvWith(s, ob.encoding)
	case SchemeAasv:
		return ob.codec.decodeAasvWith(s, ob.encoding)
	case SchemeUpbc:
		return ob.codec.decodeUpbcWith(s, ob.encoding)
	default:
		return "", ErrUnknownScheme
	}
}

// Autodec decodes a string using scheme autodetection with the stored encoding.
// It will try to detect the encryption scheme automatically. For decoding across
// all encodings, use DecodeAny on an Omnib instance instead.
func (ob *Oboron) Autodec(s string) (string, error) {
	return ob.codec.decodeAutodetectWith(s, ob.encoding)
}

// DecodeWithEncoding decodes a string using a specific text encoding.
func (ob *Oboron) DecodeWithEncoding(s string, enc Encoding) (string, error) {
	return ob.codec.decodeAutodetectWith(s, enc)
}

// Explicit decode methods
func (ob *Oboron) DecodeLegacy(s string) (string, error) {
	return ob.codec.decodeLegacy(s)
}

func (ob *Oboron) DecodeZrbcx(s string) (string, error) {
	return ob.codec.decodeZrbcx(s)
}

func (ob *Oboron) DecodeAags(s string) (string, error) {
	return ob.codec.decodeAags(s)
}

func (ob *Oboron) DecodeAasv(s string) (string, error) {
	return ob.codec.decodeAasv(s)
}

func (ob *Oboron) DecodeApgs(s string) (string, error) {
	return ob.codec.decodeApgs(s)
}

func (ob *Oboron) DecodeApsv(s string) (string, error) {
	return ob.codec.decodeApsv(s)
}

func (ob *Oboron) DecodeUpbc(s string) (string, error) {
	return ob.codec.decodeUpbc(s)
}
