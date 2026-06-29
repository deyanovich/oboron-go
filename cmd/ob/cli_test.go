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

// metaEntry represents an optional metadata line in a vector file (skipped if
// present; the canonical core vectors carry none).
type metaEntry struct {
	Type   string `json:"type"`
	Secret string `json:"secret"`
}

// obBinary returns the path to the ob binary built for testing.
func obBinary(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "ob")
	cmd := exec.Command("go", "build", "-o", binary, ".")
	cmd.Dir = "."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build ob binary: %v\n%s", err, out)
	}
	return binary
}

// testHomeDir returns a fresh temporary home directory for test isolation.
func testHomeDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// runOb runs the ob binary with the given args, returning stdout and exit success.
func runOb(t *testing.T, binary, home string, args ...string) (string, bool) {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Env = append(os.Environ(), "HOME="+home)
	out, err := cmd.Output()
	return strings.TrimRight(string(out), "\n\r"), err == nil
}

// Valid 128-character hex keys (512-bit). Hex is the only accepted key form.
const testKeyHex = "0000000000000000000000000000000000000000000000000000000000000000" +
	"0000000000000000000000000000000000000000000000000000000000000000"
const testKeyHexAlt = "1100000000000000000000000000000000000000000000000000000000000000" +
	"0000000000000000000000000000000000000000000000000000000000000000"

// ─── Keyless enc tests (all schemes) ────────────────────────────────────────

func TestObEncKeylessDsiv(t *testing.T) {
	binary := obBinary(t)
	home := testHomeDir(t)
	stdout, ok := runOb(t, binary, home, "enc", "-K", "--dsiv", "--b32", "test123")
	if !ok {
		t.Fatal("ob enc -K --dsiv --b32 test123 failed")
	}
	if stdout == "" {
		t.Fatal("ob enc produced empty output")
	}
}

func TestObEncKeylessPsiv(t *testing.T) {
	binary := obBinary(t)
	home := testHomeDir(t)
	stdout, ok := runOb(t, binary, home, "enc", "-K", "--psiv", "--b32", "test123")
	if !ok {
		t.Fatal("ob enc -K --psiv --b32 test123 failed")
	}
	if stdout == "" {
		t.Fatal("ob enc produced empty output")
	}
}

func TestObEncKeylessDgcmsiv(t *testing.T) {
	binary := obBinary(t)
	home := testHomeDir(t)
	stdout, ok := runOb(t, binary, home, "enc", "-K", "--dgcmsiv", "--b32", "test123")
	if !ok {
		t.Fatal("ob enc -K --dgcmsiv --b32 test123 failed")
	}
	if stdout == "" {
		t.Fatal("ob enc produced empty output")
	}
}

func TestObEncKeylessPgcmsiv(t *testing.T) {
	binary := obBinary(t)
	home := testHomeDir(t)
	stdout, ok := runOb(t, binary, home, "enc", "-K", "--pgcmsiv", "--b32", "test123")
	if !ok {
		t.Fatal("ob enc -K --pgcmsiv --b32 test123 failed")
	}
	if stdout == "" {
		t.Fatal("ob enc produced empty output")
	}
}

// ─── Explicit key enc tests ─────────────────────────────────────────────────

func TestObEncWithExplicitKeyDsiv(t *testing.T) {
	binary := obBinary(t)
	home := testHomeDir(t)
	stdout, ok := runOb(t, binary, home, "enc", "--key", testKeyHex, "--dsiv", "--b32", "test_data")
	if !ok {
		t.Fatal("ob enc with explicit key failed")
	}
	if stdout == "" {
		t.Fatal("ob enc produced empty output")
	}
}

func TestObEncWithExplicitKeyDgcmsiv(t *testing.T) {
	binary := obBinary(t)
	home := testHomeDir(t)
	stdout, ok := runOb(t, binary, home, "enc", "--key", testKeyHex, "--dgcmsiv", "--b32", "test_data")
	if !ok {
		t.Fatal("ob enc with explicit key failed")
	}
	if stdout == "" {
		t.Fatal("ob enc produced empty output")
	}
}

// ─── Enc/dec roundtrip tests ────────────────────────────────────────────────

func TestObEncDecRoundtripDsiv(t *testing.T) {
	binary := obBinary(t)
	home := testHomeDir(t)

	enc, ok := runOb(t, binary, home, "enc", "-K", "--dsiv", "--b32", "hello_world")
	if !ok || enc == "" {
		t.Fatal("enc failed")
	}

	dec, ok := runOb(t, binary, home, "dec", "-K", "--dsiv", "--b32", enc)
	if !ok {
		t.Fatal("dec failed")
	}
	if dec != "hello_world" {
		t.Errorf("roundtrip: got %q, want %q", dec, "hello_world")
	}
}

func TestObEncDecRoundtripDgcmsiv(t *testing.T) {
	binary := obBinary(t)
	home := testHomeDir(t)

	enc, ok := runOb(t, binary, home, "enc", "--key", testKeyHexAlt, "--dgcmsiv", "--b32", "hello_world")
	if !ok || enc == "" {
		t.Fatal("enc failed")
	}

	dec, ok := runOb(t, binary, home, "dec", "--key", testKeyHexAlt, "--dgcmsiv", "--b32", enc)
	if !ok {
		t.Fatal("dec failed")
	}
	if dec != "hello_world" {
		t.Errorf("roundtrip: got %q, want %q", dec, "hello_world")
	}
}

func TestObEncDecRoundtripPgcmsiv(t *testing.T) {
	binary := obBinary(t)
	home := testHomeDir(t)

	enc, ok := runOb(t, binary, home, "enc", "-K", "--pgcmsiv", "--b32", "hello_world")
	if !ok || enc == "" {
		t.Fatal("enc failed")
	}

	dec, ok := runOb(t, binary, home, "dec", "-K", "--pgcmsiv", "--b32", enc)
	if !ok {
		t.Fatal("dec failed")
	}
	if dec != "hello_world" {
		t.Errorf("roundtrip: got %q, want %q", dec, "hello_world")
	}
}

func TestObEncDecRoundtripPsiv(t *testing.T) {
	binary := obBinary(t)
	home := testHomeDir(t)

	enc, ok := runOb(t, binary, home, "enc", "-K", "--psiv", "--b32", "hello_world")
	if !ok || enc == "" {
		t.Fatal("enc failed")
	}

	dec, ok := runOb(t, binary, home, "dec", "-K", "--psiv", "--b32", enc)
	if !ok {
		t.Fatal("dec failed")
	}
	if dec != "hello_world" {
		t.Errorf("roundtrip: got %q, want %q", dec, "hello_world")
	}
}

func TestObEncDecRoundtripB64Dsiv(t *testing.T) {
	binary := obBinary(t)
	home := testHomeDir(t)

	enc, ok := runOb(t, binary, home, "enc", "-K", "--dsiv", "--b64", "hello_b64")
	if !ok || enc == "" {
		t.Fatal("enc failed")
	}

	dec, ok := runOb(t, binary, home, "dec", "-K", "--dsiv", "--b64", enc)
	if !ok {
		t.Fatal("dec failed")
	}
	if dec != "hello_b64" {
		t.Errorf("roundtrip: got %q, want %q", dec, "hello_b64")
	}
}

func TestObEncDecRoundtripHexDsiv(t *testing.T) {
	binary := obBinary(t)
	home := testHomeDir(t)

	enc, ok := runOb(t, binary, home, "enc", "-K", "--dsiv", "--hex", "hello_hex")
	if !ok || enc == "" {
		t.Fatal("enc failed")
	}

	dec, ok := runOb(t, binary, home, "dec", "-K", "--dsiv", "--hex", enc)
	if !ok {
		t.Fatal("dec failed")
	}
	if dec != "hello_hex" {
		t.Errorf("roundtrip: got %q, want %q", dec, "hello_hex")
	}
}

func TestObEncDecRoundtripWithExplicitKeyDsiv(t *testing.T) {
	binary := obBinary(t)
	home := testHomeDir(t)

	enc, ok := runOb(t, binary, home, "enc", "--key", testKeyHex, "--dsiv", "--b32", "hello_key_world")
	if !ok || enc == "" {
		t.Fatal("enc failed")
	}

	dec, ok := runOb(t, binary, home, "dec", "--key", testKeyHex, "--dsiv", "--b32", enc)
	if !ok {
		t.Fatal("dec failed")
	}
	if dec != "hello_key_world" {
		t.Errorf("roundtrip: got %q, want %q", dec, "hello_key_world")
	}
}

// ─── All schemes enc test ───────────────────────────────────────────────────

func TestObEncAllSchemes(t *testing.T) {
	binary := obBinary(t)
	home := testHomeDir(t)

	schemes := []string{"--dgcmsiv", "--dsiv", "--pgcmsiv", "--psiv"}
	for _, scheme := range schemes {
		stdout, ok := runOb(t, binary, home, "enc", "-K", scheme, "--b32", "test")
		if !ok {
			t.Errorf("enc with %s failed", scheme)
		}
		if stdout == "" {
			t.Errorf("enc with %s produced empty output", scheme)
		}
	}
}

func TestObEncAllEncodings(t *testing.T) {
	binary := obBinary(t)
	home := testHomeDir(t)

	encodings := []string{"--b32", "--b64", "--hex"}
	for _, enc := range encodings {
		stdout, ok := runOb(t, binary, home, "enc", "-K", "--dsiv", enc, "test")
		if !ok {
			t.Errorf("enc with %s failed", enc)
		}
		if stdout == "" {
			t.Errorf("enc with %s produced empty output", enc)
		}
	}
}

// ─── Short alias tests ──────────────────────────────────────────────────────

func TestObEncShortAliasDsiv(t *testing.T) {
	binary := obBinary(t)
	home := testHomeDir(t)
	stdout, ok := runOb(t, binary, home, "enc", "-K", "-s", "--b32", "test123")
	if !ok || stdout == "" {
		t.Fatal("enc with -s alias failed")
	}
}

func TestObEncShortAliasPsiv(t *testing.T) {
	binary := obBinary(t)
	home := testHomeDir(t)
	stdout, ok := runOb(t, binary, home, "enc", "-K", "-S", "--b32", "test123")
	if !ok || stdout == "" {
		t.Fatal("enc with -S alias failed")
	}
}

func TestObDecShortAliasDsiv(t *testing.T) {
	binary := obBinary(t)
	home := testHomeDir(t)

	enc, ok := runOb(t, binary, home, "enc", "-K", "-s", "--b32", "hello_alias_s")
	if !ok || enc == "" {
		t.Fatal("enc failed")
	}

	dec, ok := runOb(t, binary, home, "dec", "-K", "-s", "--b32", enc)
	if !ok {
		t.Fatal("dec failed")
	}
	if dec != "hello_alias_s" {
		t.Errorf("roundtrip: got %q, want %q", dec, "hello_alias_s")
	}
}

// ─── Error handling tests ───────────────────────────────────────────────────

func TestObEncInvalidKeyTooShort(t *testing.T) {
	binary := obBinary(t)
	home := testHomeDir(t)
	_, ok := runOb(t, binary, home, "enc", "--key", "TOOSHORT", "--dsiv", "--b32", "hello")
	if ok {
		t.Fatal("expected failure for too-short key")
	}
}

func TestObEncInvalidKeyEmpty(t *testing.T) {
	binary := obBinary(t)
	home := testHomeDir(t)
	_, ok := runOb(t, binary, home, "enc", "--key", "", "--dsiv", "--b32", "hello")
	if ok {
		t.Fatal("expected failure for empty key")
	}
}

func TestObDecGarbageInput(t *testing.T) {
	binary := obBinary(t)
	home := testHomeDir(t)
	_, ok := runOb(t, binary, home, "dec", "-K", "--dsiv", "--b32", "notvalidobtext")
	if ok {
		t.Fatal("expected failure for garbage input")
	}
}

func TestObEncMissingPlaintext(t *testing.T) {
	binary := obBinary(t)
	home := testHomeDir(t)
	// No plaintext argument - should read from stdin which is empty
	cmd := exec.Command(binary, "enc", "-K", "--dsiv", "--b32")
	cmd.Env = append(os.Environ(), "HOME="+home)
	cmd.Stdin = strings.NewReader("")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected failure for missing plaintext")
	}
}

func TestObEncEmptyPlaintext(t *testing.T) {
	binary := obBinary(t)
	home := testHomeDir(t)
	_, ok := runOb(t, binary, home, "enc", "-K", "--dsiv", "--b32", "")
	if ok {
		t.Fatal("expected failure for empty plaintext")
	}
}

func TestObEncDifferentKeysProduceDifferentOutput(t *testing.T) {
	binary := obBinary(t)
	home := testHomeDir(t)

	encA, okA := runOb(t, binary, home, "enc", "--key", testKeyHex, "--dsiv", "--b32", "same_input")
	encB, okB := runOb(t, binary, home, "enc", "--key", testKeyHexAlt, "--dsiv", "--b32", "same_input")
	if !okA || !okB {
		t.Fatal("enc failed")
	}
	if encA == encB {
		t.Error("different keys produced same output")
	}
}

// ─── Help test ──────────────────────────────────────────────────────────────

func TestObHelp(t *testing.T) {
	binary := obBinary(t)
	stdout, ok := runOb(t, binary, testHomeDir(t), "--help")
	if !ok {
		t.Fatal("ob --help failed")
	}
	if stdout == "" {
		t.Fatal("ob --help produced empty output")
	}
}

// ─── Vector-driven tests ────────────────────────────────────────────────────

func isDeterministicScheme(format string) bool {
	scheme := strings.Split(format, ".")[0]
	return scheme == "dgcmsiv" || scheme == "dsiv"
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

		// Skip metadata lines
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

func TestObVectorTests(t *testing.T) {
	binary := obBinary(t)
	home := testHomeDir(t)

	vectors := loadVectors(t, "../../oboron/testdata/test-vectors.jsonl")
	if len(vectors) == 0 {
		t.Fatal("No test vectors loaded")
	}
	t.Logf("Loaded %d a-tier test vectors", len(vectors))

	for _, v := range vectors {
		deterministic := isDeterministicScheme(v.Format)

		if deterministic {
			// For deterministic schemes: test exact enc match and dec
			t.Run(v.Format+"/enc/"+truncate(v.Plaintext, 15), func(t *testing.T) {
				ot, ok := runOb(t, binary, home, "enc", "-K", "--format", v.Format, "--", v.Plaintext)
				if !ok {
					t.Fatalf("ob enc failed for %q with format %q", v.Plaintext, v.Format)
				}
				if ot != v.Obtext {
					t.Errorf("encoding mismatch:\n  expected: %s\n  got:      %s", v.Obtext, ot)
				}
			})

			t.Run(v.Format+"/dec/"+truncate(v.Plaintext, 15), func(t *testing.T) {
				pt, ok := runOb(t, binary, home, "dec", "-K", "--format", v.Format, "--", v.Obtext)
				if !ok {
					t.Fatalf("ob dec failed for %q with format %q", v.Obtext, v.Format)
				}
				if pt != v.Plaintext {
					t.Errorf("decoding mismatch:\n  expected: %s\n  got:      %s", v.Plaintext, pt)
				}
			})
		} else {
			// For probabilistic schemes: test dec and roundtrip
			t.Run(v.Format+"/dec/"+truncate(v.Plaintext, 15), func(t *testing.T) {
				pt, ok := runOb(t, binary, home, "dec", "-K", "--format", v.Format, "--", v.Obtext)
				if !ok {
					t.Fatalf("ob dec failed for %q with format %q", v.Obtext, v.Format)
				}
				if pt != v.Plaintext {
					t.Errorf("decoding mismatch:\n  expected: %s\n  got:      %s", v.Plaintext, pt)
				}
			})

			t.Run(v.Format+"/roundtrip/"+truncate(v.Plaintext, 15), func(t *testing.T) {
				enc, ok := runOb(t, binary, home, "enc", "-K", "--format", v.Format, "--", v.Plaintext)
				if !ok {
					t.Fatalf("ob enc failed for %q", v.Plaintext)
				}
				dec, ok := runOb(t, binary, home, "dec", "-K", "--format", v.Format, "--", enc)
				if !ok {
					t.Fatalf("ob dec roundtrip failed for %q", enc)
				}
				if dec != v.Plaintext {
					t.Errorf("roundtrip mismatch:\n  expected: %s\n  got:      %s", v.Plaintext, dec)
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
