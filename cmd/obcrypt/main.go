// Command obcrypt is the CLI for the obcrypt crypto core: bytes-in / bytes-out
// symmetric encryption (oboron a-tier + u-tier). It mirrors the Rust
// obcrypt-cli interface so the cross-implementation conformance suite can drive
// both. obcrypt does not encode the payload — use -x/-X for hex on the wire,
// or pipe raw bytes.
package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/urfave/cli/v2"
	"oboron.org/go/internal/version"
	"oboron.org/go/obcrypt"
)

// Build metadata, set via -ldflags.
var (
	Commit    = "unknown"
	BuildTime = "unknown"
)

func main() {
	log.SetFlags(0)
	app := &cli.App{
		Name:    "obcrypt",
		Usage:   "bytes-in/bytes-out symmetric encryption (oboron a-tier + u-tier)",
		Version: fmt.Sprintf("%s (commit %s, built %s)", version.Version, Commit, BuildTime),
		Commands: []*cli.Command{
			encryptCmd(),
			decryptCmd(),
			keygenCmd(),
		},
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatalf("error: %v", err)
	}
}

func keyFlag() cli.Flag {
	return &cli.StringFlag{
		Name:    "key",
		Aliases: []string{"k"},
		Usage:   "Encryption key (128 hex chars, 512-bit; or legacy 86-char base64)",
		EnvVars: []string{"OBCRYPT_KEY"},
	}
}

func schemeFlag() cli.Flag {
	return &cli.StringFlag{
		Name:    "scheme",
		Aliases: []string{"s"},
		Usage:   "Scheme: aasv | apsv | aags | apgs | upbc",
	}
}

func encryptCmd() *cli.Command {
	return &cli.Command{
		Name:      "encrypt",
		Aliases:   []string{"e"},
		Usage:     "Encrypt plaintext bytes under a scheme",
		ArgsUsage: "[TEXT]",
		Flags: []cli.Flag{
			schemeFlag(),
			keyFlag(),
			&cli.BoolFlag{Name: "hex", Aliases: []string{"x"}, Usage: "Hex-encode the ciphertext on output"},
			&cli.BoolFlag{Name: "hex-in", Aliases: []string{"X"}, Usage: "Decode the plaintext input as hex first"},
			&cli.StringFlag{Name: "in", Usage: "Read input from file instead of TEXT/stdin"},
			&cli.StringFlag{Name: "out", Usage: "Write output to file instead of stdout"},
		},
		Action: encryptAction,
	}
}

func decryptCmd() *cli.Command {
	return &cli.Command{
		Name:      "decrypt",
		Aliases:   []string{"d"},
		Usage:     "Decrypt ciphertext bytes (scheme auto-detects from the trailing marker if not given)",
		ArgsUsage: "[CIPHERTEXT]",
		Flags: []cli.Flag{
			schemeFlag(),
			keyFlag(),
			&cli.BoolFlag{Name: "hex", Aliases: []string{"x"}, Usage: "Hex-encode the plaintext on output"},
			&cli.BoolFlag{Name: "hex-in", Aliases: []string{"X"}, Usage: "Decode the ciphertext input as hex first"},
			&cli.StringFlag{Name: "in", Usage: "Read input from file instead of CIPHERTEXT/stdin"},
			&cli.StringFlag{Name: "out", Usage: "Write output to file instead of stdout"},
		},
		Action: decryptAction,
	}
}

func keygenCmd() *cli.Command {
	return &cli.Command{
		Name:    "keygen",
		Aliases: []string{"k"},
		Usage:   "Generate a fresh random 128-character hex key",
		Action: func(c *cli.Context) error {
			key, err := obcrypt.GenerateKey()
			if err != nil {
				return err
			}
			fmt.Println(key.Hex())
			return nil
		},
	}
}

func encryptAction(c *cli.Context) error {
	key, err := resolveKey(c)
	if err != nil {
		return err
	}
	scheme, err := parseScheme(c.String("scheme"))
	if err != nil {
		return err
	}

	raw, err := readInput(c)
	if err != nil {
		return err
	}
	plaintext := raw
	if c.Bool("hex-in") {
		plaintext, err = decodeHexInput(raw, "plaintext")
		if err != nil {
			return err
		}
	}

	payload, err := obcrypt.Encrypt(plaintext, scheme, key)
	if err != nil {
		return fmt.Errorf("encrypt failed: %w", err)
	}

	if c.Bool("hex") {
		return writeOutput(c, []byte(hex.EncodeToString(payload)), false)
	}
	return writeOutput(c, payload, true)
}

func decryptAction(c *cli.Context) error {
	key, err := resolveKey(c)
	if err != nil {
		return err
	}

	raw, err := readInput(c)
	if err != nil {
		return err
	}
	payload := raw
	if c.Bool("hex-in") {
		payload, err = decodeHexInput(raw, "ciphertext")
		if err != nil {
			return err
		}
	}

	var plaintext []byte
	if s := c.String("scheme"); s != "" {
		scheme, perr := parseScheme(s)
		if perr != nil {
			return perr
		}
		plaintext, err = obcrypt.DecryptAs(payload, scheme, key)
	} else {
		plaintext, err = obcrypt.Decrypt(payload, key)
	}
	if err != nil {
		return fmt.Errorf("decrypt failed: %w", err)
	}

	if c.Bool("hex") {
		return writeOutput(c, []byte(hex.EncodeToString(plaintext)), false)
	}
	return writeOutput(c, plaintext, true)
}

// resolveKey reads the key from --key/-k or $OBCRYPT_KEY, accepting the
// canonical 128-char hex form or the deprecated 86-char base64 form.
func resolveKey(c *cli.Context) (*obcrypt.Key, error) {
	ks := c.String("key")
	if ks == "" {
		return nil, fmt.Errorf("no key given; pass --key/-k (128 hex chars) or set $OBCRYPT_KEY")
	}
	switch len(ks) {
	case obcrypt.KeySize * 2:
		return obcrypt.KeyFromHex(ks)
	case obcrypt.KeyBase64Len:
		fmt.Fprintln(os.Stderr, "warning: base64 keys are deprecated; pass a 128-character hex key instead")
		return obcrypt.KeyFromBase64(ks)
	default:
		return nil, fmt.Errorf("key must be %d hex chars or %d base64url chars, got %d",
			obcrypt.KeySize*2, obcrypt.KeyBase64Len, len(ks))
	}
}

func parseScheme(s string) (obcrypt.Scheme, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "aasv":
		return obcrypt.Aasv, nil
	case "apsv":
		return obcrypt.Apsv, nil
	case "aags":
		return obcrypt.Aags, nil
	case "apgs":
		return obcrypt.Apgs, nil
	case "upbc":
		return obcrypt.Upbc, nil
	case "":
		return 0, fmt.Errorf("no --scheme/-s given (aasv | apsv | aags | apgs | upbc)")
	default:
		return 0, fmt.Errorf("unknown scheme %q (want aasv | apsv | aags | apgs | upbc)", s)
	}
}

func decodeHexInput(raw []byte, what string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("invalid hex %s: %w", what, err)
	}
	return b, nil
}

// readInput returns the input bytes: the positional argument if present, then
// --in file, then stdin.
func readInput(c *cli.Context) ([]byte, error) {
	if c.Args().Len() > 0 {
		return []byte(c.Args().First()), nil
	}
	if path := c.String("in"); path != "" {
		return os.ReadFile(path)
	}
	return io.ReadAll(os.Stdin)
}

// writeOutput writes bytes to --out or stdout. When the output is text (hex),
// a trailing newline is added; raw byte output gets none (pipe-friendly).
func writeOutput(c *cli.Context, b []byte, rawBytes bool) error {
	if path := c.String("out"); path != "" {
		return os.WriteFile(path, b, 0o600)
	}
	if _, err := os.Stdout.Write(b); err != nil {
		return err
	}
	if !rawBytes {
		_, err := os.Stdout.Write([]byte{'\n'})
		return err
	}
	return nil
}
