package oboron

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// rsVector represents a single a/u-tier test vector from oboron-rs.
// Fields: format (e.g. "aags.c32"), plaintext, obtext.
type rsVector struct {
	Format    string `json:"format"`
	Plaintext string `json:"plaintext"`
	Obtext    string `json:"obtext"`
}

// rsMeta represents the metadata line in a vector file.
type rsMeta struct {
	Type   string `json:"type"`
	Secret string `json:"secret"`
}

// rsHardcodedKey is the shared HARDCODED_KEY_BYTES (identical across Go and
// oboron-rs for cross-language CLI compatibility), as a 128-char hex string.
var rsHardcodedKey = HardcodedMasterKey().Hex()

// loadRsVectors reads a JSONL file and returns parsed test vectors,
// skipping metadata lines (type: "meta").
func loadRsVectors(t *testing.T, path string) []rsVector {
	t.Helper()

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Failed to open %s: %v", path, err)
	}
	defer file.Close()

	var vectors []rsVector
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var meta rsMeta
		if err := json.Unmarshal([]byte(line), &meta); err == nil && meta.Type == "meta" {
			continue
		}

		var v rsVector
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Fatalf("Failed to parse vector in %s: %v\nLine: %s", path, err, line)
		}
		vectors = append(vectors, v)
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("Error reading %s: %v", path, err)
	}

	return vectors
}

// ─── A-tier decode with Rust key ────────────────────────────────────────────

// TestGoldenRsVectorsDecode verifies that Go can decode Rust-generated a/u-tier
// vectors using the shared hardcoded key — full cross-language interop.
func TestGoldenRsVectorsDecode(t *testing.T) {
	vectors := loadRsVectors(t, "testdata/rs-test-vectors.jsonl")
	if len(vectors) == 0 {
		t.Fatal("No test vectors loaded from rs-test-vectors.jsonl")
	}
	t.Logf("Loaded %d a-tier test vectors", len(vectors))

	om, err := NewOmnib(rsHardcodedKey)
	if err != nil {
		t.Fatalf("NewOmnib(rsHardcodedKey) failed: %v", err)
	}

	for _, v := range vectors {
		name := fmt.Sprintf("%s/%s", v.Format, truncate(v.Plaintext, 20))
		t.Run(name+"/decode", func(t *testing.T) {
			pt, err := om.Dec(v.Obtext, v.Format)
			if err != nil {
				t.Fatalf("Dec(%q, %q) failed: %v", v.Obtext, v.Format, err)
			}
			if pt != v.Plaintext {
				t.Errorf("Dec mismatch:\n  got:      %q\n  expected: %q", pt, v.Plaintext)
			}
		})
	}
}

// ─── Go self-consistency across a/u scheme/encoding combinations ────────────

// TestGoldenFormatRoundtrip verifies Go's own encode/decode round-trip for
// every a/u scheme × encoding combination.
func TestGoldenFormatRoundtrip(t *testing.T) {
	om, err := NewOmnibKeyless()
	if err != nil {
		t.Fatalf("NewOmnibKeyless() failed: %v", err)
	}

	schemes := []Scheme{SchemeAags, SchemeAasv, SchemeApgs, SchemeApsv, SchemeUpbc}
	encodings := []Encoding{EncodingB32, EncodingC32, EncodingB64, EncodingHex}
	inputs := []string{"a", "hello", "test123", "abcdefghijklmnop", "abcdefghijklmnopqrstuvwxyz"}

	for _, scheme := range schemes {
		for _, enc := range encodings {
			format := string(scheme) + "." + string(enc)

			for _, input := range inputs {
				name := fmt.Sprintf("%s/%s", format, truncate(input, 12))

				t.Run(name+"/roundtrip", func(t *testing.T) {
					encoded, err := om.Enc(input, format)
					if err != nil {
						t.Fatalf("Enc(%q, %q) failed: %v", input, format, err)
					}
					decoded, err := om.Dec(encoded, format)
					if err != nil {
						t.Fatalf("Dec(%q, %q) failed: %v", encoded, format, err)
					}
					if decoded != input {
						t.Errorf("Roundtrip mismatch:\n  input:   %q\n  encoded: %q\n  decoded: %q", input, encoded, decoded)
					}
				})

				// Deterministic schemes: encode is stable.
				if !isProbabilistic(scheme) {
					t.Run(name+"/deterministic", func(t *testing.T) {
						enc1, _ := om.Enc(input, format)
						enc2, _ := om.Enc(input, format)
						if enc1 != enc2 {
							t.Errorf("Deterministic scheme %s produced different outputs:\n  first:  %q\n  second: %q", format, enc1, enc2)
						}
					})
				}

				t.Run(name+"/autodec", func(t *testing.T) {
					encoded, err := om.Enc(input, format)
					if err != nil {
						t.Fatalf("Enc(%q, %q) failed: %v", input, format, err)
					}
					decoded, err := om.Autodec(encoded)
					if err != nil {
						t.Fatalf("Autodec(%q) failed for format %s: %v", encoded, format, err)
					}
					if decoded != input {
						t.Errorf("Autodec mismatch:\n  input:   %q\n  encoded: %q\n  decoded: %q", input, encoded, decoded)
					}
				})
			}
		}
	}
}

// isProbabilistic returns true for schemes where encode output varies per run.
func isProbabilistic(scheme Scheme) bool {
	switch scheme {
	case SchemeApgs, SchemeApsv, SchemeUpbc:
		return true
	default:
		return false
	}
}

// truncate shortens a string for test names.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
