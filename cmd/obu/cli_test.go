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

// testVector represents a single obu test vector (format/plaintext/obtext).
type testVector struct {
	Format    string `json:"format"`
	Plaintext string `json:"plaintext"`
	Obtext    string `json:"obtext"`
}

type metaEntry struct {
	Type string `json:"type"`
}

// obuBinary returns the path to the obu binary built for testing.
func obuBinary(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "obu")
	cmd := exec.Command("go", "build", "-o", binary, ".")
	cmd.Dir = "."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build obu binary: %v\n%s", err, out)
	}
	return binary
}

func testHomeDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// runObu runs the obu binary with the given args, returning stdout and exit success.
func runObu(t *testing.T, binary, home string, args ...string) (string, bool) {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Env = append(os.Environ(), "HOME="+home)
	out, err := cmd.Output()
	return strings.TrimRight(string(out), "\n\r"), err == nil
}

// Valid 64-character hex secrets (256-bit).
const testSecret = "0000000000000000000000000000000000000000000000000000000000000000"
const testSecretAlt = "1100000000000000000000000000000000000000000000000000000000000000"

// ─── Keyless enc tests ──────────────────────────────────────────────────────

func TestObuEncKeylessUpcbc(t *testing.T) {
	binary := obuBinary(t)
	home := testHomeDir(t)
	stdout, ok := runObu(t, binary, home, "enc", "-K", "--upcbc", "--b32", "test123")
	if !ok {
		t.Fatal("obu enc -K --upcbc --b32 test123 failed")
	}
	if stdout == "" {
		t.Fatal("obu enc produced empty output")
	}
}

func TestObuEncKeylessZdcbc(t *testing.T) {
	binary := obuBinary(t)
	home := testHomeDir(t)
	stdout, ok := runObu(t, binary, home, "enc", "-K", "--zdcbc", "--b32", "test123")
	if !ok {
		t.Fatal("obu enc -K --zdcbc --b32 test123 failed")
	}
	if stdout == "" {
		t.Fatal("obu enc produced empty output")
	}
}

func TestObuEncWithExplicitSecret(t *testing.T) {
	binary := obuBinary(t)
	home := testHomeDir(t)
	stdout, ok := runObu(t, binary, home, "enc", "--secret", testSecret, "--zdcbc", "--b32", "test_data")
	if !ok {
		t.Fatal("obu enc with explicit secret failed")
	}
	if stdout == "" {
		t.Fatal("obu enc produced empty output")
	}
}

// ─── Enc/dec roundtrip tests ────────────────────────────────────────────────

func TestObuEncDecRoundtripZdcbc(t *testing.T) {
	binary := obuBinary(t)
	home := testHomeDir(t)

	enc, ok := runObu(t, binary, home, "enc", "-K", "--zdcbc", "--b32", "hello_obu")
	if !ok || enc == "" {
		t.Fatal("enc failed")
	}

	dec, ok := runObu(t, binary, home, "dec", "-K", "--zdcbc", "--b32", enc)
	if !ok {
		t.Fatal("dec failed")
	}
	if dec != "hello_obu" {
		t.Errorf("roundtrip: got %q, want %q", dec, "hello_obu")
	}
}

func TestObuEncDecRoundtripUpcbc(t *testing.T) {
	binary := obuBinary(t)
	home := testHomeDir(t)

	enc, ok := runObu(t, binary, home, "enc", "-K", "--upcbc", "--b32", "hello_upcbc")
	if !ok || enc == "" {
		t.Fatal("enc failed")
	}

	dec, ok := runObu(t, binary, home, "dec", "-K", "--upcbc", "--b32", enc)
	if !ok {
		t.Fatal("dec failed")
	}
	if dec != "hello_upcbc" {
		t.Errorf("roundtrip: got %q, want %q", dec, "hello_upcbc")
	}
}

func TestObuEncDecRoundtripB64(t *testing.T) {
	binary := obuBinary(t)
	home := testHomeDir(t)

	enc, ok := runObu(t, binary, home, "enc", "-K", "--zdcbc", "--b64", "hello_b64")
	if !ok || enc == "" {
		t.Fatal("enc failed")
	}

	dec, ok := runObu(t, binary, home, "dec", "-K", "--zdcbc", "--b64", enc)
	if !ok {
		t.Fatal("dec failed")
	}
	if dec != "hello_b64" {
		t.Errorf("roundtrip: got %q, want %q", dec, "hello_b64")
	}
}

func TestObuEncDecRoundtripHex(t *testing.T) {
	binary := obuBinary(t)
	home := testHomeDir(t)

	enc, ok := runObu(t, binary, home, "enc", "-K", "--zdcbc", "--hex", "hello_hex")
	if !ok || enc == "" {
		t.Fatal("enc failed")
	}

	dec, ok := runObu(t, binary, home, "dec", "-K", "--zdcbc", "--hex", enc)
	if !ok {
		t.Fatal("dec failed")
	}
	if dec != "hello_hex" {
		t.Errorf("roundtrip: got %q, want %q", dec, "hello_hex")
	}
}

func TestObuEncDecRoundtripWithExplicitSecret(t *testing.T) {
	binary := obuBinary(t)
	home := testHomeDir(t)

	enc, ok := runObu(t, binary, home, "enc", "--secret", testSecret, "--zdcbc", "--b32", "hello_key")
	if !ok || enc == "" {
		t.Fatal("enc failed")
	}

	dec, ok := runObu(t, binary, home, "dec", "--secret", testSecret, "--zdcbc", "--b32", enc)
	if !ok {
		t.Fatal("dec failed")
	}
	if dec != "hello_key" {
		t.Errorf("roundtrip: got %q, want %q", dec, "hello_key")
	}
}

// ─── Short alias tests ──────────────────────────────────────────────────────

func TestObuEncShortAliasUpcbc(t *testing.T) {
	binary := obuBinary(t)
	home := testHomeDir(t)
	stdout, ok := runObu(t, binary, home, "enc", "-K", "-u", "--b32", "test123")
	if !ok || stdout == "" {
		t.Fatal("enc with -u alias failed")
	}
}

func TestObuEncShortAliasZdcbc(t *testing.T) {
	binary := obuBinary(t)
	home := testHomeDir(t)
	stdout, ok := runObu(t, binary, home, "enc", "-K", "-z", "--b32", "test123")
	if !ok || stdout == "" {
		t.Fatal("enc with -z alias failed")
	}
}

// ─── Error handling tests ───────────────────────────────────────────────────

func TestObuEncInvalidSecretTooShort(t *testing.T) {
	binary := obuBinary(t)
	home := testHomeDir(t)
	_, ok := runObu(t, binary, home, "enc", "--secret", "TOOSHORT", "--zdcbc", "--b32", "hello")
	if ok {
		t.Fatal("expected failure for too-short secret")
	}
}

func TestObuEncRejectsBase64Secret(t *testing.T) {
	binary := obuBinary(t)
	home := testHomeDir(t)
	// 43-char base64url secrets are no longer accepted (hex-only).
	_, ok := runObu(t, binary, home, "enc", "--secret", "bhPDH_hhuTE4Kb2udezEI3qF8MaKnK5ItN7aPkjzxXc", "--zdcbc", "--b32", "hello")
	if ok {
		t.Fatal("expected failure for base64 secret (hex-only)")
	}
}

func TestObuEncInvalidSecretEmpty(t *testing.T) {
	binary := obuBinary(t)
	home := testHomeDir(t)
	_, ok := runObu(t, binary, home, "enc", "--secret", "", "--zdcbc", "--b32", "hello")
	if ok {
		t.Fatal("expected failure for empty secret")
	}
}

func TestObuDecGarbageInput(t *testing.T) {
	binary := obuBinary(t)
	home := testHomeDir(t)
	_, ok := runObu(t, binary, home, "dec", "-K", "--zdcbc", "--b32", "notvalidobtext")
	if ok {
		t.Fatal("expected failure for garbage input")
	}
}

func TestObuEncMissingPlaintext(t *testing.T) {
	binary := obuBinary(t)
	home := testHomeDir(t)
	cmd := exec.Command(binary, "enc", "-K", "--zdcbc", "--b32")
	cmd.Env = append(os.Environ(), "HOME="+home)
	cmd.Stdin = strings.NewReader("")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected failure for missing plaintext")
	}
}

func TestObuEncEmptyPlaintext(t *testing.T) {
	binary := obuBinary(t)
	home := testHomeDir(t)
	_, ok := runObu(t, binary, home, "enc", "-K", "--zdcbc", "--b32", "")
	if ok {
		t.Fatal("expected failure for empty plaintext")
	}
}

func TestObuEncDifferentSecretsProduceDifferentOutput(t *testing.T) {
	binary := obuBinary(t)
	home := testHomeDir(t)

	encA, okA := runObu(t, binary, home, "enc", "--secret", testSecret, "--zdcbc", "--b32", "same_input")
	encB, okB := runObu(t, binary, home, "enc", "--secret", testSecretAlt, "--zdcbc", "--b32", "same_input")
	if !okA || !okB {
		t.Fatal("enc failed")
	}
	if encA == encB {
		t.Error("different secrets produced same output")
	}
}

// ─── Help / version tests ───────────────────────────────────────────────────

func TestObuHelp(t *testing.T) {
	binary := obuBinary(t)
	stdout, ok := runObu(t, binary, testHomeDir(t), "--help")
	if !ok {
		t.Fatal("obu --help failed")
	}
	if stdout == "" {
		t.Fatal("obu --help produced empty output")
	}
}

func TestObuVersion(t *testing.T) {
	binary := obuBinary(t)
	stdout, ok := runObu(t, binary, testHomeDir(t), "--version")
	if !ok {
		t.Fatal("obu --version failed")
	}
	want := "obu oboron-go"
	if !strings.HasPrefix(stdout, want) || !strings.Contains(stdout, "protocol=1.0 cli=1.0") {
		t.Errorf("version output = %q, want prefix %q and protocol/cli markers", stdout, want)
	}
}

func TestObuSecretgen(t *testing.T) {
	binary := obuBinary(t)
	out, ok := runObu(t, binary, testHomeDir(t), "secretgen")
	if !ok {
		t.Fatal("secretgen failed")
	}
	if len(out) != 64 {
		t.Errorf("secretgen length = %d, want 64", len(out))
	}
}

// ─── Vector-driven tests ────────────────────────────────────────────────────

func isDeterministicScheme(format string) bool {
	return strings.Split(format, ".")[0] == "zdcbc"
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

func TestObuVectorTests(t *testing.T) {
	binary := obuBinary(t)
	home := testHomeDir(t)

	vectors := loadVectors(t, "../../obu/testdata/obu-test-vectors.jsonl")
	if len(vectors) == 0 {
		t.Fatal("No test vectors loaded")
	}
	t.Logf("Loaded %d obu test vectors", len(vectors))

	for _, v := range vectors {
		if isDeterministicScheme(v.Format) {
			t.Run(v.Format+"/enc/"+truncate(v.Plaintext, 15), func(t *testing.T) {
				ot, ok := runObu(t, binary, home, "enc", "-K", "--format", v.Format, "--", v.Plaintext)
				if !ok {
					t.Fatalf("obu enc failed for %q with format %q", v.Plaintext, v.Format)
				}
				if ot != v.Obtext {
					t.Errorf("encoding mismatch:\n  expected: %s\n  got:      %s", v.Obtext, ot)
				}
			})

			t.Run(v.Format+"/dec/"+truncate(v.Plaintext, 15), func(t *testing.T) {
				pt, ok := runObu(t, binary, home, "dec", "-K", "--format", v.Format, "--", v.Obtext)
				if !ok {
					t.Fatalf("obu dec failed for %q with format %q", v.Obtext, v.Format)
				}
				if pt != v.Plaintext {
					t.Errorf("decoding mismatch:\n  expected: %s\n  got:      %s", v.Plaintext, pt)
				}
			})
		} else {
			t.Run(v.Format+"/dec/"+truncate(v.Plaintext, 15), func(t *testing.T) {
				pt, ok := runObu(t, binary, home, "dec", "-K", "--format", v.Format, "--", v.Obtext)
				if !ok {
					t.Fatalf("obu dec failed for %q with format %q", v.Obtext, v.Format)
				}
				if pt != v.Plaintext {
					t.Errorf("decoding mismatch:\n  expected: %s\n  got:      %s", v.Plaintext, pt)
				}
			})

			t.Run(v.Format+"/roundtrip/"+truncate(v.Plaintext, 15), func(t *testing.T) {
				enc, ok := runObu(t, binary, home, "enc", "-K", "--format", v.Format, "--", v.Plaintext)
				if !ok {
					t.Fatalf("obu enc failed for %q", v.Plaintext)
				}
				dec, ok := runObu(t, binary, home, "dec", "-K", "--format", v.Format, "--", enc)
				if !ok {
					t.Fatalf("obu dec roundtrip failed for %q", enc)
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
