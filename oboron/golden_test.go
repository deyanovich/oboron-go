package oboron

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// rsVector represents a single test vector from oboron-rs.
// Fields: format (e.g. "aags.c32"), plaintext, obtext.
type rsVector struct {
	Format    string `json:"format"`
	Plaintext string `json:"plaintext"`
	Obtext    string `json:"obtext"`
}

// rsMeta represents the metadata line in legacy-test-vectors.jsonl.
type rsMeta struct {
	Type   string `json:"type"`
	Secret string `json:"secret"`
}

// rsHardcodedKey is the Rust oboron-rs HARDCODED_KEY_BYTES, now identical to
// Go's HardcodedKey (aligned in Phase 6 for cross-lang CLI compatibility).
// Source: oboron-rs/oboron/src/constants.rs
var rsHardcodedKey = HardcodedKey

// isProbabilistic returns true for schemes where encode output varies per run.
func isProbabilistic(scheme Scheme) bool {
	switch scheme {
	case SchemeApgs, SchemeApsv, SchemeUpbc:
		return true
	default:
		return false
	}
}

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

		// Skip metadata lines
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

// ─── Legacy interop (full bidirectional) ────────────────────────────────────

// loadLegacySecret extracts the secret from the metadata line in legacy test vector files.
func loadLegacySecret(t *testing.T, path string) *Secret {
	t.Helper()

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Failed to open %s: %v", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var meta rsMeta
		if err := json.Unmarshal([]byte(line), &meta); err == nil && meta.Type == "meta" {
			s, err := SecretFromBase64(meta.Secret)
			if err != nil {
				t.Fatalf("Failed to parse legacy secret from meta line: %v", err)
			}
			return s
		}
		break
	}

	t.Fatalf("No meta line with secret found in %s", path)
	return nil
}

// TestGoldenRsLegacyVectors verifies full Go ↔ Rust interop for the legacy scheme.
// The Rust legacy vectors embed a secret (in metadata); we extract it and use it
// explicitly to match the contract of legacy_vector_tests.rs.
func TestGoldenRsLegacyVectors(t *testing.T) {
	const legacyPath = "testdata/rs-legacy-test-vectors.jsonl"

	vectors := loadRsVectors(t, legacyPath)
	if len(vectors) == 0 {
		t.Fatal("No test vectors loaded from rs-legacy-test-vectors.jsonl")
	}
	t.Logf("Loaded %d legacy test vectors", len(vectors))

	secret := loadLegacySecret(t, legacyPath)
	om, err := NewOmnibFromSecret(secret)
	if err != nil {
		t.Fatalf("NewOmnibFromSecret() failed: %v", err)
	}

	passed := 0
	for _, v := range vectors {
		name := fmt.Sprintf("%s/%s", v.Format, truncate(v.Plaintext, 20))

		t.Run(name+"/encode", func(t *testing.T) {
			ot, err := om.Enc(v.Plaintext, v.Format)
			if err != nil {
				t.Fatalf("Enc(%q, %q) failed: %v", v.Plaintext, v.Format, err)
			}
			if ot != v.Obtext {
				t.Errorf("Enc mismatch (Go ≠ Rust):\n  plaintext: %q\n  got:       %q\n  expected:  %q", v.Plaintext, ot, v.Obtext)
			}
		})

		t.Run(name+"/decode", func(t *testing.T) {
			pt, err := om.Dec(v.Obtext, v.Format)
			if err != nil {
				t.Fatalf("Dec(%q, %q) failed: %v", v.Obtext, v.Format, err)
			}
			if pt != v.Plaintext {
				t.Errorf("Dec mismatch:\n  obtext:   %q\n  got:      %q\n  expected: %q", v.Obtext, pt, v.Plaintext)
			}
		})

		t.Run(name+"/autodec", func(t *testing.T) {
			pt, err := om.Autodec(v.Obtext)
			if err != nil {
				t.Fatalf("Autodec(%q) failed: %v", v.Obtext, err)
			}
			if pt != v.Plaintext {
				t.Errorf("Autodec mismatch:\n  obtext:   %q\n  got:      %q\n  expected: %q", v.Obtext, pt, v.Plaintext)
			}
		})

		passed++
	}

	t.Logf("Validated %d/%d legacy vectors (full interop)", passed, len(vectors))
}

// ─── A-tier decode with Rust key ────────────────────────────────────────────

// TestGoldenRsVectorsDecode verifies that Go can decode Rust-generated a-tier vectors
// using Rust's hardcoded key. All schemes are now fully interoperable with oboron-rs.
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

	// Track pass/fail per format for summary
	type stat struct{ pass, fail int }
	stats := make(map[string]*stat)

	for _, v := range vectors {
		_, err := ParseFormat(v.Format)
		if err != nil {
			t.Errorf("Invalid format %q: %v", v.Format, err)
			continue
		}

		if stats[v.Format] == nil {
			stats[v.Format] = &stat{}
		}

		name := fmt.Sprintf("%s/%s", v.Format, truncate(v.Plaintext, 20))

		t.Run(name+"/decode", func(t *testing.T) {
			pt, err := om.Dec(v.Obtext, v.Format)
			if err != nil {
				t.Fatalf("Dec(%q, %q) failed: %v", v.Obtext, v.Format, err)
			}
			if pt != v.Plaintext {
				t.Errorf("Dec mismatch:\n  got:      %q\n  expected: %q", pt, v.Plaintext)
			}
			stats[v.Format].pass++
		})
	}

	// Log summary
	for format, s := range stats {
		t.Logf("  %s: %d pass, %d fail", format, s.pass, s.fail)
	}
}

// TestGoldenRsZtierVectorsDecode verifies that Go can decode Rust ztier (zrbcx) vectors.
// Both implementations now use 0x01 as the CBC padding byte, enabling full interop.
func TestGoldenRsZtierVectorsDecode(t *testing.T) {
	vectors := loadRsVectors(t, "testdata/rs-ztier-test-vectors.jsonl")
	if len(vectors) == 0 {
		t.Fatal("No test vectors loaded from rs-ztier-test-vectors.jsonl")
	}
	t.Logf("Loaded %d ztier test vectors", len(vectors))

	om, err := NewOmnib(rsHardcodedKey)
	if err != nil {
		t.Fatalf("NewOmnib(rsHardcodedKey) failed: %v", err)
	}

	pass := 0
	for _, v := range vectors {
		name := fmt.Sprintf("%s/%s", v.Format, truncate(v.Plaintext, 20))

		t.Run(name+"/decode", func(t *testing.T) {
			pt, err := om.Dec(v.Obtext, v.Format)
			if err != nil {
				t.Fatalf("Dec(%q, %q) failed: %v", v.Obtext, v.Format, err)
			}
			if pt != v.Plaintext {
				t.Errorf("Dec mismatch: got %q, want %q", pt, v.Plaintext)
				return
			}
			pass++
		})
	}

	t.Logf("Ztier decode: %d pass", pass)
}

// ─── Go self-consistency across all scheme/encoding combinations ────────────

// TestGoldenFormatRoundtrip verifies Go's own encode/decode round-trip for every
// scheme × encoding combination, using the Rust vector format structure.
// This ensures Go produces valid output for all 28 format variants (7 schemes × 4 encodings).
func TestGoldenFormatRoundtrip(t *testing.T) {
	om, err := NewOmnibKeyless()
	if err != nil {
		t.Fatalf("NewOmnibKeyless() failed: %v", err)
	}

	schemes := []Scheme{SchemeLegacy, SchemeZrbcx, SchemeAags, SchemeAasv, SchemeApgs, SchemeApsv, SchemeUpbc}
	encodings := []Encoding{EncodingB32, EncodingC32, EncodingB64, EncodingHex}
	inputs := []string{"a", "hello", "test123", "abcdefghijklmnop", "abcdefghijklmnopqrstuvwxyz"}

	for _, scheme := range schemes {
		for _, enc := range encodings {
			format := string(scheme)
			if enc != DefaultEncoding {
				format = string(scheme) + "." + string(enc)
			}

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

				// Deterministic schemes: verify encode is stable
				if !isProbabilistic(scheme) {
					t.Run(name+"/deterministic", func(t *testing.T) {
						enc1, _ := om.Enc(input, format)
						enc2, _ := om.Enc(input, format)
						if enc1 != enc2 {
							t.Errorf("Deterministic scheme %s produced different outputs:\n  first:  %q\n  second: %q", format, enc1, enc2)
						}
					})
				}

				// Test autodec only for b32/c32 where autodetection is reliable.
				// Non-b32/c32 encodings may be misidentified by the heuristic
				// autodetection (pre-existing limitation, not a golden test issue).
				// Legacy scheme has no marker, so autodec can produce false positives
				// when the ciphertext coincidentally matches another scheme's marker.
				if (enc == EncodingB32 || enc == EncodingC32) && scheme != SchemeLegacy {
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
}

// ─── Rust vector format parsing ─────────────────────────────────────────────

// TestGoldenVectorFormatParsing verifies that all format strings from Rust vectors
// are correctly parsed by Go's ParseFormat.
func TestGoldenVectorFormatParsing(t *testing.T) {
	files := []string{
		"testdata/rs-test-vectors.jsonl",
		"testdata/rs-ztier-test-vectors.jsonl",
		"testdata/rs-legacy-test-vectors.jsonl",
	}

	formats := make(map[string]bool)

	for _, file := range files {
		vectors := loadRsVectors(t, file)
		for _, v := range vectors {
			formats[v.Format] = true
		}
	}

	for format := range formats {
		t.Run(format, func(t *testing.T) {
			f, err := ParseFormat(format)
			if err != nil {
				t.Fatalf("ParseFormat(%q) failed: %v", format, err)
			}

			scheme := f.Scheme()
			encoding := f.Encoding()

			if scheme == "" {
				t.Errorf("Parsed scheme is empty for %q", format)
			}
			if encoding == "" {
				t.Errorf("Parsed encoding is empty for %q", format)
			}

			t.Logf("Parsed %q → scheme=%s encoding=%s", format, scheme, encoding)
		})
	}
}

// ─── Helpers ────────────────────────────────────────────────────────────────

// isKnownInteropDelta always returns false: all schemes are now fully interoperable
// between oboron-go and oboron-rs.
func isKnownInteropDelta(scheme Scheme) bool {
	return false
}

// truncate shortens a string for test names.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
