package obcrypt

// Encrypt encrypts plaintext under scheme with key, returning the framed
// payload: the scheme's ciphertext followed by the 2-byte XOR-mixed marker.
// The payload is raw bytes — obcrypt does not encode it. Empty plaintext is
// rejected (it cannot round-trip).
func Encrypt(plaintext []byte, scheme Scheme, key *Key) ([]byte, error) {
	if key.zeroized {
		return nil, ErrKeyZeroized
	}
	if len(plaintext) == 0 {
		return nil, ErrEmptyPlaintext
	}
	switch scheme {
	case Aasv:
		return key.encryptAasv(plaintext)
	case Apsv:
		return key.encryptApsv(plaintext)
	case Aags:
		return key.encryptAags(plaintext)
	case Apgs:
		return key.encryptApgs(plaintext)
	case Upbc:
		return key.encryptUpbc(plaintext)
	default:
		return nil, ErrUnknownScheme
	}
}

// Decrypt decrypts a framed payload with key, recovering the scheme from the
// payload's marker. It returns ErrUnknownScheme if the marker is not an
// a/u-tier marker (the caller can then try other schemes); ErrDecryptionFailed
// if the marker is recognized but the payload does not authenticate or decode.
// Decrypt does not mutate payload.
func Decrypt(payload []byte, key *Key) ([]byte, error) {
	scheme, data, ok := splitMarker(payload)
	if !ok {
		return nil, ErrUnknownScheme
	}
	if key.zeroized {
		return nil, ErrKeyZeroized
	}
	return key.decryptScheme(scheme, data)
}

// DecryptAs decrypts a framed payload, requiring its marker to match the given
// scheme. A mismatched or absent marker yields ErrDecryptionFailed. DecryptAs
// does not mutate payload.
func DecryptAs(payload []byte, scheme Scheme, key *Key) ([]byte, error) {
	if key.zeroized {
		return nil, ErrKeyZeroized
	}
	n := len(payload)
	if n < MarkerSize {
		return nil, ErrDecryptionFailed
	}
	marker := [2]byte{
		payload[n-2] ^ payload[0],
		payload[n-1] ^ payload[0],
	}
	if marker != scheme.Marker() {
		return nil, ErrDecryptionFailed
	}
	return key.decryptScheme(scheme, payload[:n-MarkerSize])
}

// splitMarker recovers the scheme from a framed payload and returns the
// marker-stripped data. ok is false when the payload is too short to carry a
// marker or its marker is not an a/u-tier marker.
func splitMarker(payload []byte) (scheme Scheme, data []byte, ok bool) {
	n := len(payload)
	if n < MarkerSize {
		return 0, nil, false
	}
	marker := [2]byte{
		payload[n-2] ^ payload[0],
		payload[n-1] ^ payload[0],
	}
	s, found := schemeForMarker(marker)
	if !found {
		return 0, nil, false
	}
	return s, payload[:n-MarkerSize], true
}

// decryptScheme dispatches marker-stripped data to the scheme's primitive.
func (k *Key) decryptScheme(scheme Scheme, data []byte) ([]byte, error) {
	switch scheme {
	case Aasv:
		return k.decryptAasv(data)
	case Apsv:
		return k.decryptApsv(data)
	case Aags:
		return k.decryptAags(data)
	case Apgs:
		return k.decryptApgs(data)
	case Upbc:
		return k.decryptUpbc(data)
	default:
		return nil, ErrUnknownScheme
	}
}
