package textcodec

import (
	"bytes"
	"strconv"
	"testing"
)

func TestRoundtrip(t *testing.T) {
	testData := [][]byte{
		{0x00},
		{0xff},
		{0x01, 0x02, 0x03},
		[]byte("hello world"),
		{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
		bytes.Repeat([]byte{0xAB}, 100),
	}
	for _, enc := range []Encoding{B32, C32, B64, Hex} {
		for i, data := range testData {
			t.Run(string(enc)+"/data_"+strconv.Itoa(i), func(t *testing.T) {
				encoded := EncodeToText(data, enc)
				decoded, err := DecodeFromText(encoded, enc)
				if err != nil {
					t.Fatalf("DecodeFromText failed: %v", err)
				}
				if !bytes.Equal(decoded, data) {
					t.Errorf("Roundtrip mismatch: got %x, want %x", decoded, data)
				}
			})
		}
	}
}

func TestCrockfordNormalize(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"abc123", "ABC123"},
		{"Io1l", "1011"},     // I→1, o→0, l→1
		{"OoIiLl", "001111"}, // O→0, o→0, I→1, i→1, L→1, l→1
		{"HELLO", "HE110"},   // L→1, O→0 (Crockford mapping)
		{"hello", "HE110"},   // same in lowercase
		{"0123456789", "0123456789"},
	}
	for _, tt := range tests {
		if got := crockfordNormalize(tt.input); got != tt.want {
			t.Errorf("crockfordNormalize(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
