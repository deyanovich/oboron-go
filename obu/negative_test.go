package obu

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

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

// TestObuNegativeVectors drives the canonical obu negative vectors: every
// op/format/input must be rejected.
func TestObuNegativeVectors(t *testing.T) {
	vectors := loadNegativeVectors(t, "testdata/obu-negative-test-vectors.jsonl")
	if len(vectors) == 0 {
		t.Fatal("no obu negative vectors loaded")
	}
	om, err := NewOmnibuKeyless()
	if err != nil {
		t.Fatalf("NewOmnibuKeyless: %v", err)
	}
	for _, v := range vectors {
		v := v
		t.Run(v.Format+"/"+v.Reason, func(t *testing.T) {
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

// TestEncRejectsTrailingPadByte verifies both obu schemes reject a plaintext
// whose final byte is the 0x01 pad byte (spec §2.1), which would otherwise be
// silently truncated on decode.
func TestEncRejectsTrailingPadByte(t *testing.T) {
	om, err := NewOmnibuKeyless()
	if err != nil {
		t.Fatalf("NewOmnibuKeyless: %v", err)
	}
	for _, format := range []string{"upcbc.hex", "zdcbc.hex"} {
		if _, err := om.Enc("ab\x01", format); err == nil {
			t.Errorf("Enc(\"ab\\x01\", %q) succeeded, want rejection", format)
		}
	}
}

// TestDecRejectsStripsToEmpty verifies both obu schemes reject input that
// decrypts and strips to zero bytes (spec §2.2). The obtexts are crafted at the
// AES layer so the decrypted block is all 0x01 (strips to empty).
func TestDecRejectsStripsToEmpty(t *testing.T) {
	secret := HardcodedSecret().Bytes()
	allPad := bytes.Repeat([]byte{0x01}, blockSize)
	om, err := NewOmnibuKeyless()
	if err != nil {
		t.Fatalf("NewOmnibuKeyless: %v", err)
	}

	// zdcbc: single 16-byte block (no prefix restructuring). The CBC IV is
	// secret[16:32]; choose C so AES-128-Dec(C) XOR IV == 0x01^16.
	t.Run("zdcbc", func(t *testing.T) {
		block, err := aes.NewCipher(secret[:blockSize])
		if err != nil {
			t.Fatal(err)
		}
		iv := secret[blockSize:SecretSize]
		x := make([]byte, blockSize)
		for i := range x {
			x[i] = allPad[i] ^ iv[i]
		}
		ct := make([]byte, blockSize)
		block.Encrypt(ct, x)
		if _, err := om.Dec(hex.EncodeToString(ct), "zdcbc.hex"); err == nil {
			t.Error("zdcbc Dec of strips-to-empty input succeeded, want rejection")
		}
	})

	// upcbc: 32-byte input = IV(16) || C(16) with a zero IV; choose C so
	// AES-256-Dec(C) XOR IV == 0x01^16.
	t.Run("upcbc", func(t *testing.T) {
		block, err := aes.NewCipher(secret[:SecretSize])
		if err != nil {
			t.Fatal(err)
		}
		iv := make([]byte, blockSize) // zero IV
		x := make([]byte, blockSize)
		for i := range x {
			x[i] = allPad[i] ^ iv[i]
		}
		ct := make([]byte, blockSize)
		block.Encrypt(ct, x)
		input := append(append([]byte{}, iv...), ct...)
		if _, err := om.Dec(hex.EncodeToString(input), "upcbc.hex"); err == nil {
			t.Error("upcbc Dec of strips-to-empty input succeeded, want rejection")
		}
	})
}
