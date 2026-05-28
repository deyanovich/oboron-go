package ztier

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// rsVector represents a single z-tier test vector from oboron-rs.
type rsVector struct {
	Format    string `json:"format"`
	Plaintext string `json:"plaintext"`
	Obtext    string `json:"obtext"`
}

// rsMeta represents the metadata line in a vector file (carries the secret for
// the legacy vectors).
type rsMeta struct {
	Type   string `json:"type"`
	Secret string `json:"secret"`
}

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

// loadLegacySecret extracts the secret from the metadata line in a legacy
// vector file.
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

// TestGoldenRsZtierVectorsDecode verifies Go can decode Rust zrbcx vectors with
// the shared hardcoded secret — full cross-language interop.
func TestGoldenRsZtierVectorsDecode(t *testing.T) {
	vectors := loadRsVectors(t, "testdata/rs-ztier-test-vectors.jsonl")
	if len(vectors) == 0 {
		t.Fatal("No test vectors loaded from rs-ztier-test-vectors.jsonl")
	}
	t.Logf("Loaded %d ztier test vectors", len(vectors))

	om, err := NewOmnibzKeyless()
	if err != nil {
		t.Fatalf("NewOmnibzKeyless() failed: %v", err)
	}

	for _, v := range vectors {
		name := fmt.Sprintf("%s/%s", v.Format, truncate(v.Plaintext, 20))
		t.Run(name+"/decode", func(t *testing.T) {
			pt, err := om.Dec(v.Obtext, v.Format)
			if err != nil {
				t.Fatalf("Dec(%q, %q) failed: %v", v.Obtext, v.Format, err)
			}
			if pt != v.Plaintext {
				t.Errorf("Dec mismatch: got %q, want %q", pt, v.Plaintext)
			}
		})
	}
}

// TestGoldenRsLegacyVectors verifies full Go ↔ Rust interop for the legacy
// scheme. The Rust legacy vectors embed their secret in the metadata line.
func TestGoldenRsLegacyVectors(t *testing.T) {
	const legacyPath = "testdata/rs-legacy-test-vectors.jsonl"

	vectors := loadRsVectors(t, legacyPath)
	if len(vectors) == 0 {
		t.Fatal("No test vectors loaded from rs-legacy-test-vectors.jsonl")
	}
	t.Logf("Loaded %d legacy test vectors", len(vectors))

	secret := loadLegacySecret(t, legacyPath)
	om, err := NewOmnibz(secret.Hex())
	if err != nil {
		t.Fatalf("NewOmnibz() failed: %v", err)
	}

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
	}
}

// TestGoldenZtierRoundtrip verifies Go's own encode/decode round-trip for the
// z-tier scheme × encoding combinations.
func TestGoldenZtierRoundtrip(t *testing.T) {
	om, err := NewOmnibzKeyless()
	if err != nil {
		t.Fatalf("NewOmnibzKeyless() failed: %v", err)
	}

	formats := []string{
		"zrbcx.b32", "zrbcx.c32", "zrbcx.b64", "zrbcx.hex", "legacy",
	}
	inputs := []string{"a", "hello", "test123", "abcdefghijklmnop", "abcdefghijklmnopqrstuvwxyz"}

	for _, format := range formats {
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
		}
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
