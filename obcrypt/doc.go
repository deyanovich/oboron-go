// Package obcrypt is the bytes-in / bytes-out cryptographic core of the oboron
// protocol (https://oboron.org/).
//
// obcrypt implements oboron's a-tier (authenticated) and u-tier (unauthenticated)
// encryption schemes operating on raw byte slices. It does not encode the
// payload (no base32, no base64) and does not validate UTF-8 — plaintext bytes
// pass through unchanged. Keys do have a canonical text form: hex (see Key).
//
// For the full string-in / string-out protocol — obtext encoding, format
// strings, and the z-tier obfuscation schemes — use the oboron package
// (oboron.org/go/oboron), which is layered on top of this one.
//
// # Schemes
//
// Each Scheme is a 4-letter identifier of the form <tier><props><alg>:
//
//	Aasv  a  deterministic   AES-SIV       auth + same-input→same-output; the default
//	Aags  a  deterministic   AES-GCM-SIV   like aasv, faster on hardware AES
//	Apsv  a  probabilistic   AES-SIV       auth + fresh ciphertext per call
//	Apgs  a  probabilistic   AES-GCM-SIV   like apsv, faster on hardware AES
//	Upbc  u  probabilistic   AES-256-CBC   confidentiality only; pair with outer auth
//
// # Framed payload
//
// For every scheme, the payload returned by Encrypt is:
//
//	[ scheme ciphertext bytes ][ marker[0] ^ body[0] ][ marker[1] ^ body[0] ]
//
// where body is the scheme's pre-marker bytes (the ciphertext for the
// deterministic schemes; nonce/IV ‖ ciphertext for the probabilistic ones).
// Decrypt reverses this, dispatching on the recovered marker; DecryptAs
// additionally checks the marker matches a caller-supplied scheme.
package obcrypt
