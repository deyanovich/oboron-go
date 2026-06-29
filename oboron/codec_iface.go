package oboron

// Codec is the shared single-format obtext interface — the Go analog of Rust's
// `ObtextCodec` trait. It is satisfied by *Ob, every authenticated fixed type
// (DsivC32, …), and — through Go's structural typing, with no import of this
// package required — by the obu *obu.Obu and every obu Upcbc*/Zdcbc* fixed
// type.
//
// Omnib and obu.Omnibu deliberately do not satisfy Codec: their Enc/Dec take
// a per-call format argument, so they are not single-format codecs.
type Codec interface {
	// Enc encrypts and encodes plaintext to obtext.
	Enc(plaintext string) (string, error)
	// Dec decodes and decrypts obtext to plaintext.
	Dec(obtext string) (string, error)
	// Format returns the codec's format (scheme + encoding).
	Format() Format
	// Scheme returns the codec's scheme.
	Scheme() Scheme
	// Encoding returns the codec's text encoding.
	Encoding() Encoding
}

// Compile-time check that *Ob satisfies Codec. The generated fixed types add
// their own assertions.
var _ Codec = (*Ob)(nil)
