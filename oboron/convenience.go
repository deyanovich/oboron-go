package oboron

// Package-level convenience functions mirroring the Rust reference's crate-level
// enc/dec helpers. Each constructs a one-shot Omnib; for repeated operations
// build an Omnib (or a fixed type) once and reuse it.
//
// The parameter order follows the cross-language convention data < format < key:
// the data operated on comes first, the format second, the key last.

// Enc encrypts and encodes plaintext under format ("dsiv.c32", …) with a
// 128-character hex key.
func Enc(plaintext, format, key string) (string, error) {
	o, err := NewOmnib(key)
	if err != nil {
		return "", err
	}
	return o.Enc(plaintext, format)
}

// Dec decodes and decrypts obtext under format with a 128-character hex key.
func Dec(obtext, format, key string) (string, error) {
	o, err := NewOmnib(key)
	if err != nil {
		return "", err
	}
	return o.Dec(obtext, format)
}

// EncKeyless encrypts and encodes plaintext under format with the fixed public
// test key (INSECURE — testing only).
func EncKeyless(plaintext, format string) (string, error) {
	o, err := NewOmnibKeyless()
	if err != nil {
		return "", err
	}
	return o.Enc(plaintext, format)
}

// DecKeyless decodes and decrypts obtext under format with the fixed public
// test key (INSECURE — testing only).
func DecKeyless(obtext, format string) (string, error) {
	o, err := NewOmnibKeyless()
	if err != nil {
		return "", err
	}
	return o.Dec(obtext, format)
}
