package oboron

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"oboron.org/go/obcrypt"
)

// negVector is a canonical negative test vector (CLI.md §10): running op on
// input under the fixed public test key MUST fail.
type negVector struct {
	Op     string `json:"op"`
	Format string `json:"format"`
	Input  string `json:"input"`
	Reason string `json:"reason"`
}

func loadNegativeVectors(t *testing.T, path string) []negVector {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	var out []negVector
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var v negVector
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Fatalf("parse %s: %v\nline: %s", path, err, line)
		}
		out = append(out, v)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return out
}

// TestGoldenNegativeVectors drives the canonical core negative vectors: every
// op/format/input must be rejected. This guards the strict decoders, the
// scheme-output minimum lengths, authentication, and empty-plaintext rejection.
func TestGoldenNegativeVectors(t *testing.T) {
	vectors := loadNegativeVectors(t, "testdata/negative-test-vectors.jsonl")
	if len(vectors) == 0 {
		t.Fatal("no negative vectors loaded")
	}
	om, err := NewOmnibKeyless()
	if err != nil {
		t.Fatalf("NewOmnibKeyless: %v", err)
	}
	for _, v := range vectors {
		v := v
		t.Run(v.Format+"/"+truncate(v.Reason, 40), func(t *testing.T) {
			var opErr error
			switch v.Op {
			case "dec":
				_, opErr = om.Dec(v.Input, v.Format)
			case "enc":
				_, opErr = om.Enc(v.Input, v.Format)
			default:
				t.Fatalf("unknown op %q", v.Op)
			}
			if opErr == nil {
				t.Errorf("%s(%q, %q) succeeded, want rejection (%s)", v.Op, v.Input, v.Format, v.Reason)
			}
		})
	}
}

// TestEncRejectsInvalidUTF8 verifies enc rejects non-UTF-8 input (spec §4.1).
func TestEncRejectsInvalidUTF8(t *testing.T) {
	om, err := NewOmnibKeyless()
	if err != nil {
		t.Fatalf("NewOmnibKeyless: %v", err)
	}
	if _, err := om.Enc(string([]byte{0xff, 0xfe}), "dsiv.c32"); err == nil {
		t.Error("Enc of non-UTF-8 input succeeded, want rejection")
	}
}

// TestDecRejectsInvalidUTF8 verifies dec rejects ciphertext that authenticates
// but decrypts to non-UTF-8 bytes (spec §4.1): such input must never yield an
// unchecked string. The obtext is crafted at the obcrypt layer.
func TestDecRejectsInvalidUTF8(t *testing.T) {
	key := HardcodedMasterKey()
	payload, err := obcrypt.Encrypt([]byte{0xff, 0xfe, 0xfd}, obcrypt.Dsiv, key)
	if err != nil {
		t.Fatalf("obcrypt.Encrypt: %v", err)
	}
	obtext := encodeToText(payload, EncodingC32)
	om, err := NewOmnibKeyless()
	if err != nil {
		t.Fatalf("NewOmnibKeyless: %v", err)
	}
	if _, err := om.Dec(obtext, "dsiv.c32"); err == nil {
		t.Error("Dec of authenticated non-UTF-8 plaintext succeeded, want rejection")
	}
}

// TestProbabilisticNonDeterminism verifies the probabilistic schemes draw a
// fresh nonce per encryption (spec §1.3, §5) — a regression guard against the
// previous wall-clock-seeded math/rand source.
func TestProbabilisticNonDeterminism(t *testing.T) {
	om, err := NewOmnibKeyless()
	if err != nil {
		t.Fatalf("NewOmnibKeyless: %v", err)
	}
	for _, format := range []string{"psiv.c32", "pgcmsiv.c32"} {
		seen := make(map[string]bool)
		for i := 0; i < 64; i++ {
			ot, err := om.Enc("collision?", format)
			if err != nil {
				t.Fatalf("Enc(%q): %v", format, err)
			}
			if seen[ot] {
				t.Errorf("%s produced a repeated obtext across encryptions: %q", format, ot)
			}
			seen[ot] = true
		}
	}
}
