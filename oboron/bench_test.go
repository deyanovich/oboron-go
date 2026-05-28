package oboron

import "testing"

var benchSchemes = []Scheme{SchemeAags, SchemeAasv, SchemeApgs, SchemeApsv, SchemeUpbc}

func BenchmarkEnc(b *testing.B) {
	om, _ := NewOmnibKeyless()
	for _, scheme := range benchSchemes {
		format := string(scheme) + ".c32"
		b.Run(string(scheme), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := om.Enc("hello, world", format); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDec(b *testing.B) {
	om, _ := NewOmnibKeyless()
	for _, scheme := range benchSchemes {
		format := string(scheme) + ".c32"
		ot, _ := om.Enc("hello, world", format)
		b.Run(string(scheme), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := om.Dec(ot, format); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkAutodec(b *testing.B) {
	om, _ := NewOmnibKeyless()
	for _, scheme := range benchSchemes {
		ot, _ := om.Enc("hello, world", string(scheme)+".c32")
		b.Run(string(scheme), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := om.Autodec(ot); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
