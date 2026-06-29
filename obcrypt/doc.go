// Package obcrypt is the bytes-in / bytes-out cryptographic core of the oboron
// protocol (https://oboron.org/).
//
// obcrypt implements oboron's authenticated encryption schemes operating on raw
// byte slices. It does not encode the payload (no base32, no base64) and does
// not validate UTF-8 — plaintext bytes pass through unchanged. Keys do have a
// canonical text form: hex (see Key).
//
// For the full string-in / string-out protocol — obtext encoding, format
// strings — use the oboron package (oboron.org/go/oboron), which is layered on
// top of this one. The unauthenticated / obfuscation schemes (upcbc, zdcbc)
// are not part of obcrypt; they live in the separate obu layer.
//
// # Schemes
//
// Each Scheme is identified by name:
//
//	Dsiv     deterministic   AES-SIV       auth + same-input→same-output; the default
//	Dgcmsiv  deterministic   AES-GCM-SIV   like dsiv, faster on hardware AES
//	Psiv     probabilistic   AES-SIV       auth + fresh ciphertext per call
//	Pgcmsiv  probabilistic   AES-GCM-SIV   like psiv, faster on hardware AES
//
// # Payload
//
// Encrypt returns the scheme's raw ciphertext output and nothing more — there
// is no scheme marker. The scheme is supplied by the caller on both Encrypt and
// Decrypt; there is no auto-detection. For the deterministic schemes the output
// is the ciphertext; for the probabilistic ones it is nonce ‖ ciphertext.
package obcrypt
