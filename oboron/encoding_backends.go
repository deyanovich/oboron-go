package oboron

import "oboron.org/go/oboron/internal/textcodec"

// The byte<->text encoding backends live in the shared internal/textcodec
// package. These thin wrappers keep the authenticated call sites (autier.go)
// terse. The obu package has its own copy of the same logic (it is a sibling
// package and cannot import oboron/internal).

// encodeToText converts raw bytes to an encoded text string.
func encodeToText(data []byte, enc Encoding) string {
	return textcodec.EncodeToText(data, textcodec.Encoding(enc))
}

// decodeFromText converts an encoded text string back to raw bytes.
func decodeFromText(s string, enc Encoding) ([]byte, error) {
	return textcodec.DecodeFromText(s, textcodec.Encoding(enc))
}
