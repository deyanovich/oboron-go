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

// String returns the format string representation, e.g. "aasv.c32". The legacy
// scheme is the sole exception: it has a single fixed form with no encoding
// suffix and renders as just "legacy". Every other format always carries its
// encoding suffix so the result round-trips through ParseFormat.
func (f Format) String() string {
	if f.scheme == SchemeLegacy {
		return string(SchemeLegacy)
	}
	return string(f.scheme) + "." + string(f.encoding)
}

// ParseFormat parses a format string like "aasv.c32". Parsing is strict: there
// is no library-level default encoding (the c32 default is a CLI concept, spec
// CLI.md §3, not a protocol one — spec SPEC.md defines none). Every scheme must
// carry an explicit encoding suffix, so "aasv", "zrbcx" and "zrbcx." all error.
// The lone exception is the pre-spec legacy scheme, whose single fixed form is
// the bare "legacy" (its historical b32 encoding, no marker, no suffix).
func ParseFormat(s string) (Format, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return Format{}, ErrInvalidFormat
	}

	if !strings.Contains(s, ".") {
		// Only the legacy scheme has a suffix-free form.
		if s == string(SchemeLegacy) {
			return Format{scheme: SchemeLegacy, encoding: EncodingB32}, nil
		}
		return Format{}, ErrInvalidFormat
	}

	parts := strings.SplitN(s, ".", 2)
	scheme, err := ParseScheme(parts[0])
	if err != nil {
		return Format{}, ErrInvalidFormat
	}
	// legacy never takes an encoding suffix; "legacy.b32" is not a valid form.
	if scheme == SchemeLegacy {
		return Format{}, ErrInvalidFormat
	}
	enc, err := ParseEncoding(parts[1])
	if err != nil {
		return Format{}, ErrInvalidFormat
	}
	return Format{scheme: scheme, encoding: enc}, nil
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
