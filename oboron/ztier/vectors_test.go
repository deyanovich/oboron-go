package ztier

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"oboron.org/go/oboron"
)

// localVector is a gentest-produced keyless encode vector (scheme/in/out, b32).
type localVector struct {
	Scheme oboron.Scheme `json:"scheme"`
	Key    string        `json:"key"`
	In     string        `json:"in"`
	Out    string        `json:"out"`
}

// TestVectorsFromFile checks keyless b32 encode output for the z-tier schemes
// (legacy, zrbcx) against the committed vectors shared with the oboron package.
func TestVectorsFromFile(t *testing.T) {
	const path = "../test-vectors.jsonl"
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Failed to open %s: %v", path, err)
	}
	defer file.Close()

	om, err := NewOmnibzKeyless()
	if err != nil {
		t.Fatalf("NewOmnibzKeyless() failed: %v", err)
	}

	scanner := bufio.NewScanner(file)
	lineNum, passCount := 0, 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		var v localVector
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Fatalf("Line %d: Failed to parse JSON: %v", lineNum, err)
		}
		if !v.Scheme.IsZTier() {
			continue // covered by the oboron package
		}

		// The keyless vectors use the bare scheme name as the format; legacy is
		// suffix-free, zrbcx defaults its committed output to b32.
		format := string(v.Scheme)
		if v.Scheme == oboron.SchemeZrbcx {
			format += ".b32"
		}

		t.Run(fmt.Sprintf("line_%d_%s_%s", lineNum, v.Scheme, v.In), func(t *testing.T) {
			encoded, err := om.Enc(v.In, format)
			if err != nil {
				t.Fatalf("Enc(%q, %q) failed: %v", v.In, format, err)
			}
			if encoded != v.Out {
				t.Errorf("Encoding mismatch:\n  input:    %q\n  got:      %q\n  expected: %q", v.In, encoded, v.Out)
			}
			passCount++
		})
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("Error reading test vectors: %v", err)
	}
	t.Logf("Passed %d z-tier test vectors", passCount)
}
