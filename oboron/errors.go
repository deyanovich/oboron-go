package oboron

import "errors"

var (
	ErrEmptyString      = errors.New("cannot encode empty string")
	ErrInvalidKeyLength = errors.New("key must be 64 bytes")
	ErrInvalidIVLength  = errors.New("IV must be 16 bytes")
	ErrInvalidBase32    = errors.New("invalid base32 encoding")
	ErrInvalidEncoding  = errors.New("invalid text encoding")
	ErrDecryptionFailed = errors.New("decryption failed")
	ErrUnknownScheme    = errors.New("unknown scheme")
	ErrUnknownEncoding  = errors.New("unknown encoding")
	ErrInvalidFormat    = errors.New("invalid format string")
	ErrDataTooShort     = errors.New("data too short")

	// MasterKey/Secret errors
	ErrInvalidMasterKeyLength = errors.New("master key must be 64 bytes (512 bits)")
	ErrInvalidSecretLength    = errors.New("secret must be 32 bytes (256 bits)")
	ErrMasterKeyZeroized      = errors.New("master key has been zeroized")
	ErrSchemeKeyMismatch      = errors.New("scheme requires a different key type")
)
