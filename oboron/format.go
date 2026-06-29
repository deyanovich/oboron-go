package oboron

import "strings"

// Format represents a combination of Scheme and Encoding, e.g. "dsiv.c32".
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

// String returns the format string representation, e.g. "dsiv.c32". Every
// format carries its encoding suffix so the result round-trips through
// ParseFormat.
func (f Format) String() string {
	return string(f.scheme) + "." + string(f.encoding)
}

// ParseFormat parses a format string like "dsiv.c32". Parsing is strict and
// case-sensitive (spec §1.1): format identifiers are lowercase ASCII, so any
// uppercase letter, surrounding whitespace, "ob:" prefix, empty component, or
// extra separator is rejected. There is also no library-level default encoding
// (the c32 default is a CLI concept, CLI.md §3, not a protocol one), so every
// scheme must carry an explicit encoding suffix: "dsiv", "zdcbc" and "zdcbc."
// all error.
func ParseFormat(s string) (Format, error) {
	if s == "" {
		return Format{}, ErrInvalidFormat
	}

	if !strings.Contains(s, ".") {
		return Format{}, ErrInvalidFormat
	}

	parts := strings.SplitN(s, ".", 2)
	scheme, err := ParseScheme(parts[0])
	if err != nil {
		return Format{}, ErrInvalidFormat
	}
	enc, err := ParseEncoding(parts[1])
	if err != nil {
		return Format{}, ErrInvalidFormat
	}
	return Format{scheme: scheme, encoding: enc}, nil
}

// ParseScheme parses a scheme string. Scheme codes are lowercase ASCII and
// case-sensitive (spec §1.1).
func ParseScheme(s string) (Scheme, error) {
	switch s {
	case "zdcbc":
		return SchemeZdcbc, nil
	case "dgcmsiv":
		return SchemeDgcmsiv, nil
	case "dsiv":
		return SchemeDsiv, nil
	case "pgcmsiv":
		return SchemePgcmsiv, nil
	case "psiv":
		return SchemePsiv, nil
	case "upcbc":
		return SchemeUpcbc, nil
	default:
		return "", ErrUnknownScheme
	}
}
