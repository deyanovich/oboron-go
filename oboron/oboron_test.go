package oboron

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// localVector is a gentest-produced keyless encode vector (scheme/in/out, b32).
type localVector struct {
	Scheme Scheme `json:"scheme"`
	Key    string `json:"key"`
	In     string `json:"in"`
	Out    string `json:"out"`
}

// TestVectorsFromFile checks keyless b32 encode output for the a/u-tier schemes
// against the committed vectors. The z-tier (legacy, zrbcx) lines are covered
// by the ztier package's tests.
func TestVectorsFromFile(t *testing.T) {
	file, err := os.Open("test-vectors.jsonl")
	if err != nil {
		t.Fatalf("Failed to open test-vectors.jsonl: %v", err)
	}
	defer file.Close()

	om, err := NewOmnibKeyless()
	if err != nil {
		t.Fatalf("NewOmnibKeyless() failed: %v", err)
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
		if v.Key != "" {
			t.Fatalf("Line %d: keyed vectors are not supported by this test", lineNum)
		}
		if v.Scheme.IsZTier() {
			continue // covered by the ztier package
		}

		t.Run(fmt.Sprintf("line_%d_%s_%s", lineNum, v.Scheme, v.In), func(t *testing.T) {
			encoded, err := om.Enc(v.In, string(v.Scheme)+".b32")
			if err != nil {
				t.Fatalf("Enc(%q, %q.b32) failed: %v", v.In, v.Scheme, err)
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
	t.Logf("Passed %d a/u test vectors", passCount)
}
