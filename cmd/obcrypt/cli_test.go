package main

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// hardcodedKeyHex is the 128-char hex of the shared HARDCODED_KEY_BYTES (the
// same key the .hex test vectors were generated under). obcrypt has no keyless
// flag, so we pass it explicitly via --key.
const hardcodedKeyHex = "381284633d02ea5f35df8596b5cc4218310060468e8b465455a415174ea6e966" +
	"a9f48eec4ba446ddfc8b78587895356f45a75a1ab7419454dd9f7aa8a95dbdd5"

type testVector struct {
	Format    string `json:"format"`
	Plaintext string `json:"plaintext"`
	Obtext    string `json:"obtext"`
}

type metaEntry struct {
	Type string `json:"type"`
}

func obcryptBinary(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "obcrypt")
	cmd := exec.Command("go", "build", "-o", binary, ".")
	cmd.Dir = "."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build obcrypt binary: %v\n%s", err, out)
	}
	return binary
}

// runObcrypt runs the binary and returns trimmed stdout and exit success.
func runObcrypt(t *testing.T, binary string, args ...string) (string, bool) {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
	out, err := cmd.Output()
	return strings.TrimRight(string(out), "\n\r"), err == nil
}

func schemeOf(format string) string { return strings.Split(format, ".")[0] }

func isDeterministic(format string) bool {
	s := schemeOf(format)
	return s == "aasv" || s == "aags"
}

func loadHexVectors(t *testing.T, path string) []testVector {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer file.Close()

	var vectors []testVector
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var meta metaEntry
		if json.Unmarshal([]byte(line), &meta) == nil && meta.Type == "meta" {
			continue
		}
		var v testVector
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Fatalf("parse vector: %v\nline: %s", err, line)
		}
		if !strings.HasSuffix(v.Format, ".hex") {
			continue // obcrypt works in hex (-x/-X); skip other encodings
		}
		vectors = append(vectors, v)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return vectors
}

// TestObcryptVectors mirrors the Rust oboron-cli-conformance obcrypt runner:
// for each .hex vector, deterministic schemes must reproduce the obtext exactly
// and decrypt it; probabilistic schemes must decrypt the canned obtext and
// survive a fresh encrypt→decrypt round-trip.
func TestObcryptVectors(t *testing.T) {
	binary := obcryptBinary(t)
	vectors := loadHexVectors(t, "../../oboron/testdata/rs-test-vectors.jsonl")
	if len(vectors) == 0 {
		t.Fatal("no .hex test vectors loaded")
	}
	t.Logf("loaded %d .hex vectors", len(vectors))

	for _, v := range vectors {
		scheme := schemeOf(v.Format)

		if isDeterministic(v.Format) {
			t.Run(v.Format+"/enc/"+truncate(v.Plaintext), func(t *testing.T) {
				got, ok := runObcrypt(t, binary, "encrypt", "-s", scheme, "-x", "-k", hardcodedKeyHex, "--", v.Plaintext)
				if !ok {
					t.Fatalf("encrypt failed for %q", v.Plaintext)
				}
				if got != v.Obtext {
					t.Errorf("encrypt mismatch:\n  expected: %s\n  got:      %s", v.Obtext, got)
				}
			})
			t.Run(v.Format+"/dec/"+truncate(v.Plaintext), func(t *testing.T) {
				got, ok := runObcrypt(t, binary, "decrypt", "-s", scheme, "-X", "-k", hardcodedKeyHex, "--", v.Obtext)
				if !ok {
					t.Fatalf("decrypt failed for %q", v.Obtext)
				}
				if got != v.Plaintext {
					t.Errorf("decrypt mismatch:\n  expected: %s\n  got:      %s", v.Plaintext, got)
				}
			})
		} else {
			t.Run(v.Format+"/dec/"+truncate(v.Plaintext), func(t *testing.T) {
				got, ok := runObcrypt(t, binary, "decrypt", "-s", scheme, "-X", "-k", hardcodedKeyHex, "--", v.Obtext)
				if !ok {
					t.Fatalf("decrypt failed for %q", v.Obtext)
				}
				if got != v.Plaintext {
					t.Errorf("decrypt mismatch (canned):\n  expected: %s\n  got:      %s", v.Plaintext, got)
				}
			})
			t.Run(v.Format+"/roundtrip/"+truncate(v.Plaintext), func(t *testing.T) {
				fresh, ok := runObcrypt(t, binary, "encrypt", "-s", scheme, "-x", "-k", hardcodedKeyHex, "--", v.Plaintext)
				if !ok {
					t.Fatalf("encrypt failed for %q", v.Plaintext)
				}
				rt, ok := runObcrypt(t, binary, "decrypt", "-s", scheme, "-X", "-k", hardcodedKeyHex, "--", fresh)
				if !ok {
					t.Fatalf("decrypt roundtrip failed for %q", fresh)
				}
				if rt != v.Plaintext {
					t.Errorf("roundtrip mismatch:\n  expected: %s\n  got:      %s", v.Plaintext, rt)
				}
			})
		}
	}
}

// TestObcryptAutodetect verifies decrypt without -s recovers the scheme from
// the marker (mirrors obcrypt.Decrypt).
func TestObcryptAutodetect(t *testing.T) {
	binary := obcryptBinary(t)
	for _, scheme := range []string{"aasv", "apsv", "aags", "apgs", "upbc"} {
		t.Run(scheme, func(t *testing.T) {
			ct, ok := runObcrypt(t, binary, "encrypt", "-s", scheme, "-x", "-k", hardcodedKeyHex, "--", "hello world")
			if !ok {
				t.Fatalf("encrypt failed")
			}
			pt, ok := runObcrypt(t, binary, "decrypt", "-X", "-k", hardcodedKeyHex, "--", ct)
			if !ok || pt != "hello world" {
				t.Errorf("autodetect decrypt = %q (ok=%v), want %q", pt, ok, "hello world")
			}
		})
	}
}

func TestObcryptKeygen(t *testing.T) {
	binary := obcryptBinary(t)
	out, ok := runObcrypt(t, binary, "keygen")
	if !ok {
		t.Fatal("keygen failed")
	}
	if len(out) != 128 {
		t.Errorf("keygen length = %d, want 128", len(out))
	}
}

func truncate(s string) string {
	if len(s) <= 15 {
		return s
	}
	return s[:15] + "..."
}
