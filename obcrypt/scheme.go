package obcrypt

// Scheme identifies an authenticated oboron core encryption scheme. obcrypt is
// the authenticated core: confidentiality and integrity over raw bytes. The
// unauthenticated and obfuscation schemes (upcbc, zdcbc) are not part of
// obcrypt — they live in the separate obu layer.
type Scheme uint8

const (
	// Dsiv is deterministic AES-SIV. The most general default.
	Dsiv Scheme = iota
	// Psiv is probabilistic AES-SIV.
	Psiv
	// Dgcmsiv is deterministic AES-GCM-SIV.
	Dgcmsiv
	// Pgcmsiv is probabilistic AES-GCM-SIV.
	Pgcmsiv
)

// String returns the scheme identifier (e.g. "dsiv").
func (s Scheme) String() string {
	switch s {
	case Dsiv:
		return "dsiv"
	case Psiv:
		return "psiv"
	case Dgcmsiv:
		return "dgcmsiv"
	case Pgcmsiv:
		return "pgcmsiv"
	default:
		return "unknown"
	}
}
