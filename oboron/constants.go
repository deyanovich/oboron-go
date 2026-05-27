package oboron

import "oboron.org/go/obcrypt"

// HardcodedKey for oboron (testing only - NOT SECURE).
// 64-byte HARDCODED_KEY_BYTES shared with oboron-rs for cross-language
// compatibility; the canonical bytes live in the obcrypt package.
var HardcodedKey = obcrypt.HardcodedKeyBytes()

// HardcodedMasterKey returns a MasterKey from HardcodedKey (testing only - NOT SECURE).
// Used for a-tier/u-tier secure schemes (aags, aasv, apgs, apsv, upbc).
func HardcodedMasterKey() *MasterKey {
	return obcrypt.HardcodedKey()
}

// HardcodedSecret returns a Secret derived from the first 32 bytes of HardcodedKey
// (testing only - NOT SECURE). Used for z-tier obfuscation schemes (legacy, zrbcx).
func HardcodedSecret() *Secret {
	s, _ := NewSecret(HardcodedKey[:SecretSize])
	return s
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

// Scheme represents an oboron encoding scheme
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

// MarkerSize is the size of the 2-byte scheme marker appended to ciphertext.
// The a/u-tier markers live in the obcrypt package; the z-tier zrbcx marker is
// defined here.
const MarkerSize = obcrypt.MarkerSize

// zrbcxMarker is the z-tier zrbcx scheme marker (XORed with the first
// ciphertext byte before appending). Byte layout matches the a/u markers:
//
//	Byte 1: [ext:1][version:4][tier:3]
//	Byte 2: [properties:4][algorithm:4]
var zrbcxMarker = [2]byte{0x06, 0x21} // tier=6, properties=2/referenceable, algorithm=1/CBC

const blockSize = 16
