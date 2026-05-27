package oboron

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

// Ten characters input, all combinations
const (
	ten = "0123456789"
)

// Encoding
func Benchmark_EncodeLegacy(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := ten

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.EncodeLegacy(input)
	}
}
func Benchmark_EncodeZrbcx(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := ten

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.EncodeZrbcx(input)
	}
}
func Benchmark_EncodeApgs(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := ten

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.EncodeApgs(input)
	}
}
func Benchmark_EncodeAags(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := ten

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.EncodeAags(input)
	}
}
func Benchmark_EncodeApsv(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := ten

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.EncodeApsv(input)
	}
}
func Benchmark_EncodeAasv(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := ten

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.EncodeAasv(input)
	}
}
func Benchmark_EncodeUpbc(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := ten

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.EncodeUpbc(input)
	}
}

// Decoding Autodetect
func Benchmark_DecodeAutodetectLegacy(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := ten
	encoded, _ := ob.EncodeLegacy(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.Decode(encoded)
	}
}
func Benchmark_DecodeAutodetectZrbcx(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := ten
	encoded, _ := ob.EncodeZrbcx(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.Decode(encoded)
	}
}
func Benchmark_DecodeAutodetectApgs(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := ten
	encoded, _ := ob.EncodeApgs(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.Decode(encoded)
	}
}
func Benchmark_DecodeAutodetectAags(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := ten
	encoded, _ := ob.EncodeAags(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.Decode(encoded)
	}
}
func Benchmark_DecodeAutodetectApsv(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := ten
	encoded, _ := ob.EncodeApsv(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.Decode(encoded)
	}
}
func Benchmark_DecodeAutodetectAasv(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := ten
	encoded, _ := ob.EncodeAasv(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.Decode(encoded)
	}
}
func Benchmark_DecodeAutodetectUpbc(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := ten
	encoded, _ := ob.EncodeUpbc(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.Decode(encoded)
	}
}

// Decoding explicitly
func Benchmark_DecodeLegacy(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := ten
	encoded, _ := ob.EncodeLegacy(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.DecodeLegacy(encoded)
	}
}
func Benchmark_DecodeZrbcx(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := ten
	encoded, _ := ob.EncodeZrbcx(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.DecodeZrbcx(encoded)
	}
}
func Benchmark_DecodeApgs(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := ten
	encoded, _ := ob.EncodeApgs(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.DecodeApgs(encoded)
	}
}
func Benchmark_DecodeAags(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := ten
	encoded, _ := ob.EncodeAags(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.DecodeAags(encoded)
	}
}
func Benchmark_DecodeApsv(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := ten
	encoded, _ := ob.EncodeApsv(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.DecodeApsv(encoded)
	}
}
func Benchmark_DecodeAasv(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := ten
	encoded, _ := ob.EncodeAasv(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.DecodeAasv(encoded)
	}
}
func Benchmark_DecodeUpbc(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := ten
	encoded, _ := ob.EncodeUpbc(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.DecodeUpbc(encoded)
	}
}

// Benchmarks vs SHA256

// Existing benchmarks...

// BenchmarkVsSHA256 compares oboron performance against SHA256
// for various string lengths where oboron produces ~52 char output

// Benchmark the SWEET SPOT: short strings where oboron shines
func Benchmark_OboronEncodeLegacy_1byte(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := "a" // 1 byte → 26 chars
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.EncodeLegacy(input)
	}
}
func Benchmark_SHA256_1byte(b *testing.B) {
	input := "a"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hash := sha256.Sum256([]byte(input))
		_ = hex.EncodeToString(hash[:]) // Always 64 chars
	}
}

func Benchmark_OboronEncodeLegacy_5bytes(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := "12345" // Database ID
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.EncodeLegacy(input)
	}
}
func Benchmark_SHA256_5bytes(b *testing.B) {
	input := "12345"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hash := sha256.Sum256([]byte(input))
		_ = hex.EncodeToString(hash[:])
	}
}

func Benchmark_OboronEncodeLegacy_8bytes(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := "SKU-9876" // Product SKU
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.EncodeLegacy(input)
	}
}
func Benchmark_SHA256_8bytes(b *testing.B) {
	input := "SKU-9876"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hash := sha256.Sum256([]byte(input))
		_ = hex.EncodeToString(hash[:])
	}
}

func Benchmark_OboronEncodeLegacy_13bytes(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := "product_12345" // Max size for 26-char output
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.EncodeLegacy(input)
	}
}
func Benchmark_SHA256_13bytes(b *testing.B) {
	input := "product_12345"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hash := sha256.Sum256([]byte(input))
		_ = hex.EncodeToString(hash[:])
	}
}

func Benchmark_OboronEncodeLegacy_15bytes(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := generateRandomString(15)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.EncodeLegacy(input)
	}
}
func Benchmark_SHA256_15bytes(b *testing.B) {
	input := generateRandomString(15)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hash := sha256.Sum256([]byte(input))
		_ = hex.EncodeToString(hash[:])
	}
}

func Benchmark_OboronEncodeLegacy_20bytes(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := generateRandomString(20)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.EncodeLegacy(input)
	}
}
func Benchmark_SHA256_20bytes(b *testing.B) {
	input := generateRandomString(20)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hash := sha256.Sum256([]byte(input))
		_ = hex.EncodeToString(hash[:])
	}
}

func Benchmark_OboronEncodeLegacy_30bytes(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := generateRandomString(30)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.EncodeLegacy(input)
	}
}
func Benchmark_SHA256_30bytes(b *testing.B) {
	input := generateRandomString(30)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hash := sha256.Sum256([]byte(input))
		_ = hex.EncodeToString(hash[:])
	}
}

func Benchmark_OboronEncodeLegacy_50bytes(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := generateRandomString(50)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.EncodeLegacy(input)
	}
}
func Benchmark_SHA256_50bytes(b *testing.B) {
	input := generateRandomString(50)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hash := sha256.Sum256([]byte(input))
		_ = hex.EncodeToString(hash[:])
	}
}

func Benchmark_OboronEncodeLegacy_75bytes(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := generateRandomString(75)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.EncodeLegacy(input)
	}
}
func Benchmark_SHA256_75bytes(b *testing.B) {
	input := generateRandomString(75)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hash := sha256.Sum256([]byte(input))
		_ = hex.EncodeToString(hash[:])
	}
}

func Benchmark_OboronEncodeLegacy_100bytes(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := generateRandomString(100)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.EncodeLegacy(input)
	}
}
func Benchmark_SHA256_100bytes(b *testing.B) {
	input := generateRandomString(100)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hash := sha256.Sum256([]byte(input))
		_ = hex.EncodeToString(hash[:])
	}
}

func Benchmark_OboronEncodeLegacy_200bytes(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := generateRandomString(200)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.EncodeLegacy(input)
	}
}
func Benchmark_SHA256_200bytes(b *testing.B) {
	input := generateRandomString(200)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hash := sha256.Sum256([]byte(input))
		_ = hex.EncodeToString(hash[:])
	}
}

func Benchmark_OboronEncodeLegacy_500bytes(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := generateRandomString(500)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.EncodeLegacy(input)
	}
}
func Benchmark_SHA256_500bytes(b *testing.B) {
	input := generateRandomString(500)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hash := sha256.Sum256([]byte(input))
		_ = hex.EncodeToString(hash[:])
	}
}

func Benchmark_OboronEncodeLegacy_1Kbytes(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := generateRandomString(1000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.EncodeLegacy(input)
	}
}
func Benchmark_SHA256_1Kbytes(b *testing.B) {
	input := generateRandomString(1000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hash := sha256.Sum256([]byte(input))
		_ = hex.EncodeToString(hash[:])
	}
}

func Benchmark_OboronEncodeLegacy_10Kbytes(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := generateRandomString(10000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.EncodeLegacy(input)
	}
}
func Benchmark_SHA256_10K(b *testing.B) {
	input := generateRandomString(10000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hash := sha256.Sum256([]byte(input))
		_ = hex.EncodeToString(hash[:])
	}
}

func Benchmark_OboronEncodeLegacy_100Kbytes(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := generateRandomString(100000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.EncodeLegacy(input)
	}
}
func Benchmark_SHA256_100K(b *testing.B) {
	input := generateRandomString(100000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hash := sha256.Sum256([]byte(input))
		_ = hex.EncodeToString(hash[:])
	}
}

func Benchmark_OboronEncodeLegacy_1Mbytes(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := generateRandomString(1000000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.EncodeLegacy(input)
	}
}
func Benchmark_SHA256_1M(b *testing.B) {
	input := generateRandomString(1000000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hash := sha256.Sum256([]byte(input))
		_ = hex.EncodeToString(hash[:])
	}
}

// Ob0 realistic scenarios
func Benchmark_EncodeLegacy_DatabaseIDs(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	// Pre-generate realistic database IDs (1-10 chars)
	ids := make([]string, 1000)
	for i := range ids {
		ids[i] = fmt.Sprintf("%d", i+1)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		input := ids[i%1000]
		_, _ = ob.EncodeLegacy(input)
	}
}

func Benchmark_EncodeLegacy_RandomStrings(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	// Pre-generate 1000 random strings
	inputs := make([]string, 1000)
	for i := range inputs {
		inputs[i] = generateRandomString(15 + (i % 16)) // 15-30 bytes
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		input := inputs[i%1000]
		_, _ = ob.EncodeLegacy(input)
	}
}

// Ob0 parallel execution
func Benchmark_EncodeLegacy_Parallel(b *testing.B) {
	ob, _ := NewLegacyKeyless()
	input := generateRandomString(30)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = ob.Encode(input)
		}
	})
}

func BenchmarkLegacyDecode_Parallel(b *testing.B) {
	ob, _ := NewLegacyKeyless()
	input := generateRandomString(30)
	encoded, _ := ob.Encode(input)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = ob.Decode(encoded)
		}
	})
}

// Ob0 memory allocations
func BenchmarkLegacyEncode_Allocs(b *testing.B) {
	ob, _ := NewLegacyKeyless()
	input := generateRandomString(30)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.Encode(input)
	}
}

func BenchmarkLegacyDecode_Allocs(b *testing.B) {
	ob, _ := NewLegacyKeyless()
	input := generateRandomString(30)
	encoded, _ := ob.Encode(input)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.Decode(encoded)
	}
}

// Comparison benchmarks: Ob0 vs Ob1
func BenchmarkLegacy_vs_Zrbcx_Encode_1byte(b *testing.B) {
	b.Run("Legacy", func(b *testing.B) {
		ob, _ := NewOmnibKeyless()
		input := "a"
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = ob.EncodeLegacy(input)
		}
	})

	b.Run("Zrbcx", func(b *testing.B) {
		ob, _ := NewOmnibKeyless()
		input := "a"
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = ob.EncodeZrbcx(input)
		}
	})
}

func BenchmarkLegacy_vs_Zrbcx_Encode_30bytes(b *testing.B) {
	input := generateRandomString(30)

	b.Run("Legacy", func(b *testing.B) {
		ob, _ := NewOmnibKeyless()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = ob.EncodeLegacy(input)
		}
	})

	b.Run("Zrbcx", func(b *testing.B) {
		ob, _ := NewOmnibKeyless()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = ob.EncodeZrbcx(input)
		}
	})
}

func BenchmarkLegacy_vs_Zrbcx_Decode(b *testing.B) {
	input := generateRandomString(30)

	b.Run("Legacy", func(b *testing.B) {
		ob, _ := NewOmnibKeyless()
		encoded, _ := ob.EncodeLegacy(input)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = ob.Decode(encoded)
		}
	})

	b.Run("Zrbcx", func(b *testing.B) {
		ob, _ := NewOmnibKeyless()
		encoded, _ := ob.EncodeZrbcx(input)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = ob.Decode(encoded)
		}
	})
}

func BenchmarkLegacyDecode_DetailedAllocs(b *testing.B) {
	ob, _ := NewLegacyKeyless()
	input := generateRandomString(30)
	encoded, _ := ob.Encode(input)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = ob.Decode(encoded)
	}
}

// Benchmark explicit Ob0 decode vs auto-detect
func BenchmarkLegacyDecode_Explicit(b *testing.B) {
	ob, _ := NewLegacyKeyless()
	input := "benchmark test data"
	encoded, _ := ob.Encode(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.DecodeLegacy(encoded) // Explicit Ob0
	}
}

func BenchmarkLegacyDecode_Explicit_52chars(b *testing.B) {
	ob, _ := NewLegacyKeyless()
	input := generateRandomString(30)
	encoded, _ := ob.Encode(input)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.DecodeLegacy(encoded) // Explicit Ob0
	}
}

func BenchmarkLegacyDecode_Explicit_Parallel(b *testing.B) {
	ob, _ := NewLegacyKeyless()
	input := generateRandomString(30)
	encoded, _ := ob.Encode(input)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = ob.DecodeLegacy(encoded) // Explicit Ob0
		}
	})
}

func BenchmarkLegacyDecode_Explicit_Allocs(b *testing.B) {
	ob, _ := NewLegacyKeyless()
	input := generateRandomString(30)
	encoded, _ := ob.Encode(input)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ob.DecodeLegacy(encoded) // Explicit Ob0
	}
}

// Comparison: Explicit vs Auto-detect
func BenchmarkLegacy_Decode_Explicit_vs_AutoDetect(b *testing.B) {
	ob, _ := NewLegacyKeyless()
	input := generateRandomString(30)
	encoded, _ := ob.Encode(input)

	b.Run("Explicit", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = ob.DecodeLegacy(encoded)
		}
	})

	b.Run("AutoDetect", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = ob.Decode(encoded)
		}
	})
}

// Benchmark with multiple random strings to test average performance
func BenchmarkOboronEncode_RandomStrings(b *testing.B) {
	ob, _ := NewOmnibKeyless()

	// Pre-generate 1000 random strings
	inputs := make([]string, 1000)
	for i := range inputs {
		inputs[i] = generateRandomString(15 + (i % 16)) // 15-30 bytes
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		input := inputs[i%1000]
		_, _ = ob.EncodeZrbcx(input)
	}
}

func BenchmarkSHA256_RandomStrings(b *testing.B) {
	// Pre-generate 1000 random strings
	inputs := make([]string, 1000)
	for i := range inputs {
		inputs[i] = generateRandomString(15 + (i % 16)) // 15-30 bytes
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		input := inputs[i%1000]
		hash := sha256.Sum256([]byte(input))
		_ = hex.EncodeToString(hash[:])
	}
}

// Benchmark parallel execution
func BenchmarkOboronEncode_Parallel(b *testing.B) {
	ob, _ := NewOmnibKeyless()
	input := generateRandomString(30)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = ob.EncodeZrbcx(input)
		}
	})
}

func BenchmarkSHA256_Parallel(b *testing.B) {
	input := generateRandomString(30)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() { // ← This loop was there, but inside the hash needs to be computed
			hash := sha256.Sum256([]byte(input))
			_ = hex.EncodeToString(hash[:])
		}
	})
}

// Helper: Generate random string of specified length
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_/."
	b := make([]byte, length)
	rand.Read(b)

	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}
