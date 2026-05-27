package oboron

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestVectorsFromFile(t *testing.T) {
	// Open the test vectors file
	file, err := os.Open("test-vectors.jsonl")
	if err != nil {
		t.Fatalf("Failed to open test-vectors.jsonl: %v", err)
	}
	defer file.Close()

	// Parse and test each vector
	scanner := bufio.NewScanner(file)
	lineNum := 0
	passCount := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip empty lines
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Parse JSON test vector
		var vector struct {
			Scheme Scheme `json:"scheme"`
			Key    string `json:"key"`
			In     string `json:"in"`
			Out    string `json:"out"`
		}

		if err := json.Unmarshal([]byte(line), &vector); err != nil {
			t.Fatalf("Line %d: Failed to parse JSON: %v", lineNum, err)
		}

		// Test encoding
		t.Run(fmt.Sprintf("line_%d_v%s_%s", lineNum, vector.Scheme, vector.In), func(t *testing.T) {
			var ob *Omnib
			var err error

			// Check if key field is present
			if vector.Key == "" {
				// No key provided, use the hardcoded key
				ob, err = NewOmnibKeyless()
				if err != nil {
					t.Fatalf("Failed to create encoder with hardcoded key: %v", err)
				}
			} else {
				// Decode key from hex
				key, err := hex.DecodeString(vector.Key)
				if err != nil {
					t.Fatalf("Invalid key hex: %v", err)
				}

				// Expect 64-byte key
				if len(key) != 64 {
					t.Fatalf("Expected 64-byte key, got %d bytes", len(key))
				}

				ob, err = NewOmnib(key)
				if err != nil {
					t.Fatalf("Failed to create encoder with long key: %v", err)
				}
			}

			// Encode based on scheme
			var encoded string
			switch vector.Scheme {
			case SchemeLegacy:
				encoded, err = ob.EncodeLegacy(vector.In)
			case SchemeZrbcx:
				encoded, err = ob.EncodeZrbcx(vector.In)
			case SchemeAags:
				encoded, err = ob.EncodeAags(vector.In)
			case SchemeAasv:
				encoded, err = ob.EncodeAasv(vector.In)
			case SchemeApgs:
				encoded, err = ob.EncodeApgs(vector.In)
			case SchemeApsv:
				encoded, err = ob.EncodeApsv(vector.In)
			case SchemeUpbc:
				encoded, err = ob.EncodeUpbc(vector.In)
			default:
				t.Fatalf("Unknown scheme: %s", vector.Scheme)
			}

			if err != nil {
				t.Fatalf("Encode failed: %v", err)
			}

			// Verify encoded output matches expected
			if encoded != vector.Out {
				t.Errorf("Encoding mismatch:\n  input:    %q\n  key:      %s\n  got:      %q\n  expected: %q",
					vector.In, vector.Key, encoded, vector.Out)
				return
			}

			passCount++
		})
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("Error reading test vectors: %v", err)
	}

	t.Logf("Passed %d test vectors", passCount)
}
