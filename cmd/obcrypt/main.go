// Command obcrypt is the CLI for the obcrypt crypto core: bytes-in / bytes-out
// authenticated encryption. It mirrors the Rust obcrypt-cli interface so the
// cross-implementation conformance suite can drive both. obcrypt does not
// encode the payload — use -x/-X for hex on the wire, or pipe raw bytes.
package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/urfave/cli/v2"
	"oboron.org/go/internal/cliutil"
	"oboron.org/go/internal/version"
	"oboron.org/go/obcrypt"
)

func main() {
	log.SetFlags(0)
	// Align the --version line with ob/obu's tokenized form. obcrypt is the
	// non-spec bytes core, so it reports protocol=1.0 (the crypto layout it
	// implements) but no cli= field, and strips the git-tag "v" prefix.
	cli.VersionPrinter = func(*cli.Context) {
		fmt.Printf("obcrypt oboron-go %s protocol=1.0\n", cliutil.VersionToken(version.Version))
	}
	app := &cli.App{
		Name:    "obcrypt",
		Usage:   "bytes-in/bytes-out authenticated encryption (oboron core)",
		Version: cliutil.VersionToken(version.Version),
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
		Usage:   "Encryption key (128 hex chars, 512-bit)",
		EnvVars: []string{"OBCRYPT_KEY"},
	}
}

func schemeFlag() cli.Flag {
	return &cli.StringFlag{
		Name:    "scheme",
		Aliases: []string{"s"},
		Usage:   "Scheme: dsiv | psiv | dgcmsiv | pgcmsiv",
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
		Usage:     "Decrypt ciphertext bytes under a scheme (--scheme/-s required)",
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

	scheme, err := parseScheme(c.String("scheme"))
	if err != nil {
		return err
	}
	plaintext, err := obcrypt.Decrypt(payload, scheme, key)
	if err != nil {
		return fmt.Errorf("decrypt failed: %w", err)
	}

	if c.Bool("hex") {
		return writeOutput(c, []byte(hex.EncodeToString(plaintext)), false)
	}
	return writeOutput(c, plaintext, true)
}

// resolveKey reads the key from --key/-k or $OBCRYPT_KEY, accepting the
// canonical 128-char hex form (hex is the only accepted key form).
func resolveKey(c *cli.Context) (*obcrypt.Key, error) {
	ks := c.String("key")
	if ks == "" {
		return nil, fmt.Errorf("no key given; pass --key/-k (128 hex chars) or set $OBCRYPT_KEY")
	}
	if len(ks) != obcrypt.KeySize*2 {
		return nil, fmt.Errorf("key must be %d hex chars, got %d", obcrypt.KeySize*2, len(ks))
	}
	return obcrypt.KeyFromHex(ks)
}

func parseScheme(s string) (obcrypt.Scheme, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "dsiv":
		return obcrypt.Dsiv, nil
	case "psiv":
		return obcrypt.Psiv, nil
	case "dgcmsiv":
		return obcrypt.Dgcmsiv, nil
	case "pgcmsiv":
		return obcrypt.Pgcmsiv, nil
	case "":
		return 0, fmt.Errorf("no --scheme/-s given (dsiv | psiv | dgcmsiv | pgcmsiv)")
	default:
		return 0, fmt.Errorf("unknown scheme %q (want dsiv | psiv | dgcmsiv | pgcmsiv)", s)
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
