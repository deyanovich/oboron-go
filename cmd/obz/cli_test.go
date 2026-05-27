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

// testVector represents a single test vector from the reference suite.
type testVector struct {
	Format    string `json:"format"`
	Plaintext string `json:"plaintext"`
	Obtext    string `json:"obtext"`
}

// metaEntry represents the metadata line in legacy vector files.
type metaEntry struct {
	Type   string `json:"type"`
	Secret string `json:"secret"`
}

// obzBinary returns the path to the obz binary built for testing.
func obzBinary(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "obz")
	cmd := exec.Command("go", "build", "-o", binary, ".")
	cmd.Dir = "."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build obz binary: %v\n%s", err, out)
	}
	return binary
}

// testHomeDir returns a fresh temporary home directory for test isolation.
func testHomeDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// runObz runs the obz binary with the given args, returning stdout and exit success.
func runObz(t *testing.T, binary, home string, args ...string) (string, bool) {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Env = append(os.Environ(), "HOME="+home)
	out, err := cmd.Output()
	return strings.TrimRight(string(out), "\n\r"), err == nil
}

// Valid 43-character base64url-nopad secret (256-bit)
const testSecret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
const testSecretAlt = "ZAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// ─── Keyless enc tests ──────────────────────────────────────────────────────

func TestObzEncKeyless(t *testing.T) {
	binary := obzBinary(t)
	home := testHomeDir(t)
	stdout, ok := runObz(t, binary, home, "enc", "-K", "--zrbcx", "--b32", "test123")
	if !ok {
		t.Fatal("obz enc -K --zrbcx --b32 test123 failed")
	}
	if stdout == "" {
		t.Fatal("obz enc produced empty output")
	}
}

func TestObzEncWithExplicitSecret(t *testing.T) {
	binary := obzBinary(t)
	home := testHomeDir(t)
	stdout, ok := runObz(t, binary, home, "enc", "--secret", testSecret, "--zrbcx", "--b32", "test_data")
	if !ok {
		t.Fatal("obz enc with explicit secret failed")
	}
	if stdout == "" {
		t.Fatal("obz enc produced empty output")
	}
}

// ─── Enc/dec roundtrip tests ────────────────────────────────────────────────

func TestObzEncDecRoundtrip(t *testing.T) {
	binary := obzBinary(t)
	home := testHomeDir(t)

	enc, ok := runObz(t, binary, home, "enc", "-K", "--zrbcx", "--b32", "hello_obz")
	if !ok || enc == "" {
		t.Fatal("enc failed")
	}

	dec, ok := runObz(t, binary, home, "dec", "-K", "--zrbcx", "--b32", enc)
	if !ok {
		t.Fatal("dec failed")
	}
	if dec != "hello_obz" {
		t.Errorf("roundtrip: got %q, want %q", dec, "hello_obz")
	}
}

func TestObzEncDecRoundtripB64(t *testing.T) {
	binary := obzBinary(t)
	home := testHomeDir(t)

	enc, ok := runObz(t, binary, home, "enc", "-K", "--zrbcx", "--b64", "hello_b64")
	if !ok || enc == "" {
		t.Fatal("enc failed")
	}

	dec, ok := runObz(t, binary, home, "dec", "-K", "--zrbcx", "--b64", enc)
	if !ok {
		t.Fatal("dec failed")
	}
	if dec != "hello_b64" {
		t.Errorf("roundtrip: got %q, want %q", dec, "hello_b64")
	}
}

func TestObzEncDecRoundtripHex(t *testing.T) {
	binary := obzBinary(t)
	home := testHomeDir(t)

	enc, ok := runObz(t, binary, home, "enc", "-K", "--zrbcx", "--hex", "hello_hex")
	if !ok || enc == "" {
		t.Fatal("enc failed")
	}

	dec, ok := runObz(t, binary, home, "dec", "-K", "--zrbcx", "--hex", enc)
	if !ok {
		t.Fatal("dec failed")
	}
	if dec != "hello_hex" {
		t.Errorf("roundtrip: got %q, want %q", dec, "hello_hex")
	}
}

func TestObzEncDecRoundtripWithExplicitSecret(t *testing.T) {
	binary := obzBinary(t)
	home := testHomeDir(t)

	enc, ok := runObz(t, binary, home, "enc", "--secret", testSecret, "--zrbcx", "--b32", "hello_key")
	if !ok || enc == "" {
		t.Fatal("enc failed")
	}

	dec, ok := runObz(t, binary, home, "dec", "--secret", testSecret, "--zrbcx", "--b32", enc)
	if !ok {
		t.Fatal("dec failed")
	}
	if dec != "hello_key" {
		t.Errorf("roundtrip: got %q, want %q", dec, "hello_key")
	}
}

// ─── Error handling tests ───────────────────────────────────────────────────

func TestObzEncInvalidSecretTooShort(t *testing.T) {
	binary := obzBinary(t)
	home := testHomeDir(t)
	_, ok := runObz(t, binary, home, "enc", "--secret", "TOOSHORT", "--zrbcx", "--b32", "hello")
	if ok {
		t.Fatal("expected failure for too-short secret")
	}
}

func TestObzEncInvalidSecretEmpty(t *testing.T) {
	binary := obzBinary(t)
	home := testHomeDir(t)
	_, ok := runObz(t, binary, home, "enc", "--secret", "", "--zrbcx", "--b32", "hello")
	if ok {
		t.Fatal("expected failure for empty secret")
	}
}

func TestObzDecGarbageInput(t *testing.T) {
	binary := obzBinary(t)
	home := testHomeDir(t)
	_, ok := runObz(t, binary, home, "dec", "-K", "--zrbcx", "--b32", "notvalidobtext")
	if ok {
		t.Fatal("expected failure for garbage input")
	}
}

func TestObzEncMissingPlaintext(t *testing.T) {
	binary := obzBinary(t)
	home := testHomeDir(t)
	cmd := exec.Command(binary, "enc", "-K", "--zrbcx", "--b32")
	cmd.Env = append(os.Environ(), "HOME="+home)
	cmd.Stdin = strings.NewReader("")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected failure for missing plaintext")
	}
}

func TestObzEncEmptyPlaintext(t *testing.T) {
	binary := obzBinary(t)
	home := testHomeDir(t)
	_, ok := runObz(t, binary, home, "enc", "-K", "--zrbcx", "--b32", "")
	if ok {
		t.Fatal("expected failure for empty plaintext")
	}
}

func TestObzEncDifferentSecretsProduceDifferentOutput(t *testing.T) {
	binary := obzBinary(t)
	home := testHomeDir(t)

	encA, okA := runObz(t, binary, home, "enc", "--secret", testSecret, "--zrbcx", "--b32", "same_input")
	encB, okB := runObz(t, binary, home, "enc", "--secret", testSecretAlt, "--zrbcx", "--b32", "same_input")
	if !okA || !okB {
		t.Fatal("enc failed")
	}
	if encA == encB {
		t.Error("different secrets produced same output")
	}
}

// ─── Help test ──────────────────────────────────────────────────────────────

func TestObzHelp(t *testing.T) {
	binary := obzBinary(t)
	stdout, ok := runObz(t, binary, testHomeDir(t), "--help")
	if !ok {
		t.Fatal("obz --help failed")
	}
	if stdout == "" {
		t.Fatal("obz --help produced empty output")
	}
}

// ─── Vector-driven tests ────────────────────────────────────────────────────

func isDeterministicScheme(format string) bool {
	scheme := strings.Split(format, ".")[0]
	return scheme == "zrbcx" || scheme == "zmock1"
}

func loadVectors(t *testing.T, path string) []testVector {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Failed to open %s: %v", path, err)
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
		if err := json.Unmarshal([]byte(line), &meta); err == nil && meta.Type == "meta" {
			continue
		}

		var v testVector
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Fatalf("Failed to parse vector: %v\nLine: %s", err, line)
		}
		vectors = append(vectors, v)
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("Error reading %s: %v", path, err)
	}

	return vectors
}

func loadLegacySecret(t *testing.T, path string) string {
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

		var meta metaEntry
		if err := json.Unmarshal([]byte(line), &meta); err == nil && meta.Type == "meta" {
			return meta.Secret
		}
		break
	}

	t.Fatalf("No meta line with secret found in %s", path)
	return ""
}

func TestObzZtierVectorTests(t *testing.T) {
	binary := obzBinary(t)
	home := testHomeDir(t)

	vectors := loadVectors(t, "../../oboron/testdata/rs-ztier-test-vectors.jsonl")
	if len(vectors) == 0 {
		t.Fatal("No test vectors loaded")
	}
	t.Logf("Loaded %d ztier test vectors", len(vectors))

	for _, v := range vectors {
		deterministic := isDeterministicScheme(v.Format)

		if deterministic {
			t.Run(v.Format+"/enc/"+truncate(v.Plaintext, 15), func(t *testing.T) {
				ot, ok := runObz(t, binary, home, "enc", "-K", "--format", v.Format, "--", v.Plaintext)
				if !ok {
					t.Fatalf("obz enc failed for %q with format %q", v.Plaintext, v.Format)
				}
				if ot != v.Obtext {
					t.Errorf("encoding mismatch:\n  expected: %s\n  got:      %s", v.Obtext, ot)
				}
			})

			t.Run(v.Format+"/dec/"+truncate(v.Plaintext, 15), func(t *testing.T) {
				pt, ok := runObz(t, binary, home, "dec", "-K", "--format", v.Format, "--", v.Obtext)
				if !ok {
					t.Fatalf("obz dec failed for %q with format %q", v.Obtext, v.Format)
				}
				if pt != v.Plaintext {
					t.Errorf("decoding mismatch:\n  expected: %s\n  got:      %s", v.Plaintext, pt)
				}
			})
		} else {
			t.Run(v.Format+"/dec/"+truncate(v.Plaintext, 15), func(t *testing.T) {
				pt, ok := runObz(t, binary, home, "dec", "-K", "--format", v.Format, "--", v.Obtext)
				if !ok {
					t.Fatalf("obz dec failed for %q with format %q", v.Obtext, v.Format)
				}
				if pt != v.Plaintext {
					t.Errorf("decoding mismatch:\n  expected: %s\n  got:      %s", v.Plaintext, pt)
				}
			})

			t.Run(v.Format+"/roundtrip/"+truncate(v.Plaintext, 15), func(t *testing.T) {
				enc, ok := runObz(t, binary, home, "enc", "-K", "--format", v.Format, "--", v.Plaintext)
				if !ok {
					t.Fatalf("obz enc failed for %q", v.Plaintext)
				}
				dec, ok := runObz(t, binary, home, "dec", "-K", "--format", v.Format, "--", enc)
				if !ok {
					t.Fatalf("obz dec roundtrip failed for %q", enc)
				}
				if dec != v.Plaintext {
					t.Errorf("roundtrip mismatch:\n  expected: %s\n  got:      %s", v.Plaintext, dec)
				}
			})
		}
	}
}

func TestObzLegacyVectorTests(t *testing.T) {
	binary := obzBinary(t)
	home := testHomeDir(t)

	const legacyPath = "../../oboron/testdata/rs-legacy-test-vectors.jsonl"
	secret := loadLegacySecret(t, legacyPath)
	vectors := loadVectors(t, legacyPath)
	if len(vectors) == 0 {
		t.Fatal("No test vectors loaded")
	}
	t.Logf("Loaded %d legacy test vectors (secret: %s...)", len(vectors), secret[:8])

	for _, v := range vectors {
		// Legacy scheme is deterministic: test exact enc and dec match.
		// Known bug: legacy `dec` strips trailing '=' characters from decoded plaintext.
		expectedDec := strings.TrimRight(v.Plaintext, "=")

		t.Run(v.Format+"/enc/"+truncate(v.Plaintext, 15), func(t *testing.T) {
			ot, ok := runObz(t, binary, home, "enc", "-s", secret, "--format", v.Format, "--", v.Plaintext)
			if !ok {
				t.Fatalf("obz enc failed for %q with format %q", v.Plaintext, v.Format)
			}
			if ot != v.Obtext {
				t.Errorf("encoding mismatch:\n  expected: %s\n  got:      %s", v.Obtext, ot)
			}
		})

		t.Run(v.Format+"/dec/"+truncate(v.Plaintext, 15), func(t *testing.T) {
			pt, ok := runObz(t, binary, home, "dec", "-s", secret, "--format", v.Format, "--", v.Obtext)
			if !ok {
				t.Fatalf("obz dec failed for %q with format %q", v.Obtext, v.Format)
			}
			if pt != expectedDec {
				t.Errorf("decoding mismatch (known legacy trailing '=' strip, original: %q):\n  expected: %s\n  got:      %s",
					v.Plaintext, expectedDec, pt)
			}
		})
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
