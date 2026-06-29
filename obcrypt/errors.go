package obcrypt

import "errors"

var (
	// ErrInvalidKeyLength is returned when a key is not exactly KeySize bytes.
	ErrInvalidKeyLength = errors.New("obcrypt: key must be 64 bytes (512 bits)")
	// ErrKeyZeroized is returned when a zeroized key is used for crypto.
	ErrKeyZeroized = errors.New("obcrypt: key has been zeroized")
	// ErrEmptyPlaintext is returned by Encrypt for empty input. Empty plaintext
	// cannot round-trip: the minimum framed payload would be shorter than the
	// length a decrypt requires.
	ErrEmptyPlaintext = errors.New("obcrypt: cannot encrypt empty plaintext")
	// ErrDecryptionFailed is returned when a payload cannot be decrypted under
	// the given key and scheme (wrong key, tampered ciphertext, or truncation).
	ErrDecryptionFailed = errors.New("obcrypt: decryption failed")
	// ErrUnknownScheme is returned when an unrecognized Scheme value is passed
	// to Encrypt or Decrypt.
	ErrUnknownScheme = errors.New("obcrypt: unknown scheme")
)
