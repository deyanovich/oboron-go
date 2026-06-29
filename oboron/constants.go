package oboron

import "oboron.org/go/obcrypt"

// HardcodedKey for oboron (testing only - NOT SECURE).
// 64-byte HARDCODED_KEY_BYTES shared with oboron-rs for cross-language
// compatibility; the canonical bytes live in the obcrypt package.
var HardcodedKey = obcrypt.HardcodedKeyBytes()

// HardcodedMasterKey returns a MasterKey from HardcodedKey (testing only - NOT SECURE).
// Used for the authenticated schemes (dgcmsiv, dsiv, pgcmsiv, psiv). The obu
// schemes (upcbc, zdcbc) have their own hardcoded secret in the obu package.
func HardcodedMasterKey() *MasterKey {
	return obcrypt.HardcodedKey()
}

// Scheme represents an oboron encoding scheme. The enum is whole — it includes
// the obu upcbc/zdcbc variants — so that Format/ParseFormat (shared by both
// layers) can name them, even though the obu codecs live in the obu package.
type Scheme string

func (s Scheme) String() string {
	return string(s)
}

const (
	SchemeZdcbc   Scheme = "zdcbc"   // AES-CBC, deterministic, prefix-restructured (obu)
	SchemeDgcmsiv Scheme = "dgcmsiv" // AES-GCM-SIV, deterministic
	SchemeDsiv    Scheme = "dsiv"    // AES-SIV, deterministic
	SchemePgcmsiv Scheme = "pgcmsiv" // AES-GCM-SIV, probabilistic
	SchemePsiv    Scheme = "psiv"    // AES-SIV, probabilistic
	SchemeUpcbc   Scheme = "upcbc"   // AES-256-CBC, probabilistic (obu)
)

// IsObu reports whether a scheme belongs to the obu layer (upcbc, zdcbc) — the
// unauthenticated / obfuscation schemes handled by the separate obu package.
// The authenticated codecs (Ob, Omnib, the fixed types) reject obu schemes; the
// obu codecs reject the authenticated schemes.
func (s Scheme) IsObu() bool {
	return s == SchemeUpcbc || s == SchemeZdcbc
}
