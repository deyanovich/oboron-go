package oboron

import "oboron.org/go/obcrypt"

// HardcodedKey for oboron (testing only - NOT SECURE).
// 64-byte HARDCODED_KEY_BYTES shared with oboron-rs for cross-language
// compatibility; the canonical bytes live in the obcrypt package.
var HardcodedKey = obcrypt.HardcodedKeyBytes()

// HardcodedMasterKey returns a MasterKey from HardcodedKey (testing only - NOT SECURE).
// Used for a-tier/u-tier secure schemes (aags, aasv, apgs, apsv, upbc). The
// z-tier hardcoded secret lives in the oboron/ztier subpackage.
func HardcodedMasterKey() *MasterKey {
	return obcrypt.HardcodedKey()
}

// Security tier constants
const (
	// TierA represents authenticated encryption schemes (aags, aasv, apgs, apsv)
	TierA = 1
	// TierU represents unauthenticated encryption schemes (upbc)
	TierU = 2
	// TierZ represents zero-security obfuscation schemes (legacy, zrbcx)
	TierZ = 6
)

// Scheme represents an oboron encoding scheme. The enum is whole — it includes
// the z-tier zrbcx/legacy variants — so that Format/ParseFormat (shared by both
// tiers) can name them, even though the z-tier codecs live in oboron/ztier.
type Scheme string

func (s Scheme) String() string {
	return string(s)
}

const (
	SchemeLegacy Scheme = "legacy" // AES-CBC legacy (no marker)
	SchemeZrbcx  Scheme = "zrbcx"  // AES-CBC, deterministic, prefix-restructured
	SchemeAags   Scheme = "aags"   // AES-GCM-SIV, deterministic
	SchemeAasv   Scheme = "aasv"   // AES-SIV, deterministic
	SchemeApgs   Scheme = "apgs"   // AES-GCM-SIV, probabilistic
	SchemeApsv   Scheme = "apsv"   // AES-SIV, probabilistic
	SchemeUpbc   Scheme = "upbc"   // AES-CBC, probabilistic
)

// IsZTier reports whether a scheme belongs to the z-tier (zrbcx, legacy) — the
// obfuscation-only schemes handled by the oboron/ztier subpackage. The a/u-tier
// codecs (Ob, Omnib, the fixed types) reject z-tier schemes; ztier's codecs
// reject a/u schemes.
func (s Scheme) IsZTier() bool {
	return s == SchemeZrbcx || s == SchemeLegacy
}

// MarkerSize is the size of the 2-byte scheme marker appended to ciphertext.
const MarkerSize = obcrypt.MarkerSize
