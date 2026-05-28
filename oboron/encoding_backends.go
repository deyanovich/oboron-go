package oboron

import "oboron.org/go/oboron/internal/textcodec"

// The byte<->text encoding backends live in the shared internal/textcodec
// package so the z-tier (oboron/ztier) can reuse them without importing
// oboron. These thin wrappers keep the a/u-tier call sites (autier.go, the
// autodetect path) terse.

// encodeToText converts raw bytes to an encoded text string.
func encodeToText(data []byte, enc Encoding) string {
	return textcodec.EncodeToText(data, textcodec.Encoding(enc))
}

// decodeFromText converts an encoded text string back to raw bytes.
func decodeFromText(s string, enc Encoding) ([]byte, error) {
	return textcodec.DecodeFromText(s, textcodec.Encoding(enc))
}
