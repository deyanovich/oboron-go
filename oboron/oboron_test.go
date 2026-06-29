package oboron

import (
	"testing"
)

// TestKeylessFixedTypesMatchVectors checks that the keyless fixed-type codecs
// (DsivB32, DgcmsivB32, …) reproduce the deterministic rev3 vectors exactly.
// This exercises the fixed-type API path (distinct from the Omnib path covered
// by TestGoldenRsVectors). The keyless codecs use the shared hardcoded key, the
// same key the vectors were generated under.
func TestKeylessFixedTypesMatchVectors(t *testing.T) {
	vectors := loadRsVectors(t, "testdata/test-vectors.jsonl")
	if len(vectors) == 0 {
		t.Fatal("No test vectors loaded")
	}

	// Codec constructors for the deterministic .b32 fixed types.
	type fixed interface {
		Enc(string) (string, error)
	}
	newFixed := func(format string) (fixed, bool) {
		switch format {
		case "dsiv.b32":
			c, _ := NewDsivB32Keyless()
			return c, true
		case "dgcmsiv.b32":
			c, _ := NewDgcmsivB32Keyless()
			return c, true
		default:
			return nil, false
		}
	}

	count := 0
	for _, v := range vectors {
		c, ok := newFixed(v.Format)
		if !ok {
			continue // only the deterministic .b32 fixed types here
		}
		t.Run(v.Format+"/"+truncate(v.Plaintext, 15), func(t *testing.T) {
			ot, err := c.Enc(v.Plaintext)
			if err != nil {
				t.Fatalf("Enc(%q) failed: %v", v.Plaintext, err)
			}
			if ot != v.Obtext {
				t.Errorf("Enc mismatch:\n  got:      %q\n  expected: %q", ot, v.Obtext)
			}
		})
		count++
	}
	if count == 0 {
		t.Fatal("no deterministic .b32 vectors exercised")
	}
	t.Logf("checked %d deterministic fixed-type vectors", count)
}
