package obcrypt

// Scheme identifies an a-tier or u-tier oboron encryption scheme. These are the
// schemes obcrypt implements: confidentiality (and, for a-tier, integrity) over
// raw bytes. The z-tier obfuscation schemes (zrbcx, legacy) are not crypto and
// live in the oboron encoding layer, not here.
type Scheme uint8

const (
	// Aasv is a-tier, deterministic, AES-SIV. The most general default.
	Aasv Scheme = iota
	// Apsv is a-tier, probabilistic, AES-SIV.
	Apsv
	// Aags is a-tier, deterministic, AES-GCM-SIV.
	Aags
	// Apgs is a-tier, probabilistic, AES-GCM-SIV.
	Apgs
	// Upbc is u-tier (unauthenticated), probabilistic, AES-256-CBC.
	Upbc
)

// MarkerSize is the number of trailing bytes carrying the XOR-mixed scheme
// marker in a framed payload.
const MarkerSize = 2

// 2-byte scheme markers, XORed with the first ciphertext byte before being
// appended to the framed payload. Marker byte layout:
//
//	Byte 1: [ext:1][version:4][tier:3]
//	Byte 2: [properties:4][algorithm:4]
var (
	aasvMarker = [2]byte{0x01, 0x13} // tier=1, properties=1/avalanche,      algorithm=3/SIV
	apsvMarker = [2]byte{0x01, 0x03} // tier=1, properties=0/probabilistic,  algorithm=3/SIV
	aagsMarker = [2]byte{0x01, 0x12} // tier=1, properties=1/avalanche,      algorithm=2/GCM-SIV
	apgsMarker = [2]byte{0x01, 0x02} // tier=1, properties=0/probabilistic,  algorithm=2/GCM-SIV
	upbcMarker = [2]byte{0x02, 0x01} // tier=2, properties=0/probabilistic,  algorithm=1/CBC
)

// String returns the 4-letter scheme identifier (e.g. "aasv").
func (s Scheme) String() string {
	switch s {
	case Aasv:
		return "aasv"
	case Apsv:
		return "apsv"
	case Aags:
		return "aags"
	case Apgs:
		return "apgs"
	case Upbc:
		return "upbc"
	default:
		return "unknown"
	}
}

// Marker returns the scheme's 2-byte marker (before XOR mixing).
func (s Scheme) Marker() [2]byte {
	switch s {
	case Aasv:
		return aasvMarker
	case Apsv:
		return apsvMarker
	case Aags:
		return aagsMarker
	case Apgs:
		return apgsMarker
	case Upbc:
		return upbcMarker
	default:
		return [2]byte{}
	}
}

// schemeForMarker maps a recovered marker back to its scheme. The boolean is
// false when the marker is not an obcrypt (a/u-tier) marker.
func schemeForMarker(m [2]byte) (Scheme, bool) {
	switch m {
	case aasvMarker:
		return Aasv, true
	case apsvMarker:
		return Apsv, true
	case aagsMarker:
		return Aags, true
	case apgsMarker:
		return Apgs, true
	case upbcMarker:
		return Upbc, true
	default:
		return 0, false
	}
}
