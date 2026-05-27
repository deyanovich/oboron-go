package oboron

import "strings"

// Format represents a combination of Scheme and Encoding, e.g. "aasv.c32".
type Format struct {
	scheme   Scheme
	encoding Encoding
}

// NewFormat creates a Format from a Scheme and Encoding.
func NewFormat(scheme Scheme, encoding Encoding) Format {
	return Format{scheme: scheme, encoding: encoding}
}

// Scheme returns the scheme component of the format.
func (f Format) Scheme() Scheme {
	return f.scheme
}

// Encoding returns the encoding component of the format.
func (f Format) Encoding() Encoding {
	return f.encoding
}

// String returns the format string representation, e.g. "aasv.c32".
// The encoding suffix is always included so the result round-trips through ParseFormat
// to an identical Format and matches the canonical "scheme.encoding" form used in
// test vectors.
func (f Format) String() string {
	enc := f.encoding
	if enc == "" {
		enc = DefaultEncoding
	}
	return string(f.scheme) + "." + string(enc)
}

// ParseFormat parses a format string like "aasv.c32" or "legacy".
// If no encoding suffix is present the scheme's default encoding is used: b32 for
// the pre-spec legacy scheme (its historical encoding, with no 2-byte marker), and
// the global DefaultEncoding (c32) for every other scheme.
func ParseFormat(s string) (Format, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return Format{}, ErrInvalidFormat
	}

	parts := strings.SplitN(s, ".", 2)

	scheme, err := ParseScheme(parts[0])
	if err != nil {
		return Format{}, ErrInvalidFormat
	}

	var enc Encoding
	if len(parts) == 2 {
		enc, err = ParseEncoding(parts[1])
		if err != nil {
			return Format{}, ErrInvalidFormat
		}
	} else {
		enc = schemeDefaultEncoding(scheme)
	}

	return Format{scheme: scheme, encoding: enc}, nil
}

// schemeDefaultEncoding returns the encoding to use when no explicit encoding
// suffix is given. The legacy scheme is locked to b32 (its only ever encoding);
// all spec-conformant schemes fall back to DefaultEncoding (c32).
func schemeDefaultEncoding(scheme Scheme) Encoding {
	if scheme == SchemeLegacy {
		return EncodingB32
	}
	return DefaultEncoding
}

// ParseScheme parses a scheme string (case-insensitive).
func ParseScheme(s string) (Scheme, error) {
	switch strings.ToLower(s) {
	case "legacy":
		return SchemeLegacy, nil
	case "zrbcx":
		return SchemeZrbcx, nil
	case "aags":
		return SchemeAags, nil
	case "aasv":
		return SchemeAasv, nil
	case "apgs":
		return SchemeApgs, nil
	case "apsv":
		return SchemeApsv, nil
	case "upbc":
		return SchemeUpbc, nil
	default:
		return "", ErrUnknownScheme
	}
}
