// Command obz is the CLI for oboron's z-tier obfuscation schemes
// (legacy and zrbcx): reversible obfuscation of a string, not
// authenticated encryption. See https://oboron.org/.
package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/urfave/cli/v2"
	"oboron.org/go/internal/version"
	"oboron.org/go/oboron"
	"oboron.org/go/oboron/ztier"
)

func main() {
	app := &cli.App{
		Name:                   "obz",
		Usage:                  "Encode and decode values with oboron z-tier obfuscation schemes",
		Version:                version.Version,
		UseShortOptionHandling: true,
		Commands: []*cli.Command{
			encCmd(),
			decCmd(),
			initCmd(),
			configCmd(),
			profileCmd(),
			secretCmd(),
			secretgenCmd(),
			completionCmd(),
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

// --- Shared flag builders ---

func secretFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "secret",
			Aliases: []string{"s"},
			Usage:   "Obfuscation secret (64 hex chars, 256-bit; or legacy 43-char base64); conflicts with --profile/--keyless",
			EnvVars: []string{"OBORON_SECRET"},
		},
		&cli.StringFlag{
			Name:    "profile",
			Aliases: []string{"p"},
			Usage:   "Use named secret profile; conflicts with --secret/--keyless",
		},
		&cli.BoolFlag{
			Name:    "keyless",
			Aliases: []string{"K"},
			Usage:   "Use hardcoded secret (INSECURE — testing only); conflicts with --secret/--profile",
		},
	}
}

func schemeFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{Name: "zrbcx", Aliases: []string{"r"}, Usage: "Use zrbcx scheme (optimized AES-CBC)"},
		&cli.BoolFlag{Name: "legacy", Aliases: []string{"l"}, Usage: "Use legacy scheme (AES-CBC)"},
	}
}

func encodingFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{Name: "c32", Aliases: []string{"c"}, Usage: "Crockford base32 encoding (default)"},
		&cli.BoolFlag{Name: "b32", Aliases: []string{"b"}, Usage: "RFC4648 base32 encoding"},
		&cli.BoolFlag{Name: "b64", Aliases: []string{"B"}, Usage: "Base64url-nopad encoding"},
		&cli.BoolFlag{Name: "hex", Aliases: []string{"x"}, Usage: "Hexadecimal encoding"},
	}
}

func formatFlag() cli.Flag {
	return &cli.StringFlag{
		Name:    "format",
		Aliases: []string{"f"},
		Usage:   `Format string e.g. "zrbcx.b64"; cannot combine with scheme/encoding flags`,
	}
}

// --- Helpers ---

func readTextInput(c *cli.Context) (string, error) {
	if c.NArg() > 0 {
		return strings.Join(c.Args().Slice(), " "), nil
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("failed to read stdin: %w", err)
	}
	return strings.TrimRight(string(data), "\n\r"), nil
}

func resolveSecret(c *cli.Context) (*ztier.Secret, error) {
	if c.Bool("keyless") {
		return ztier.HardcodedSecret(), nil
	}

	// Secret flag / env var (EnvVars handles $OBORON_SECRET automatically)
	if secretStr := c.String("secret"); secretStr != "" {
		return ztier.SecretFromString(secretStr)
	}

	// Profile from flag or config
	cfg, _ := loadConfig()
	profileName := c.String("profile")
	if profileName == "" && cfg != nil {
		profileName = cfg.Profile
	}
	if profileName == "" {
		profileName = "default"
	}

	prof, err := loadProfile(profileName)
	if err != nil {
		return nil, err
	}
	return ztier.SecretFromString(prof.Secret)
}

func resolveScheme(c *cli.Context, cfg *Config) (oboron.Scheme, error) {
	if c.String("format") != "" {
		f, err := oboron.ParseFormat(c.String("format"))
		if err != nil {
			return "", err
		}
		return f.Scheme(), nil
	}
	if c.Bool("zrbcx") {
		return oboron.SchemeZrbcx, nil
	}
	if c.Bool("legacy") {
		return oboron.SchemeLegacy, nil
	}
	if cfg != nil && cfg.Scheme != "" {
		return oboron.Scheme(cfg.Scheme), nil
	}
	return oboron.SchemeZrbcx, nil // spec default for obz
}

// formatString builds the codec format string. The legacy scheme is
// suffix-free ("legacy"); every other scheme carries its encoding (e.g.
// "zrbcx.c32").
func formatString(scheme oboron.Scheme, enc oboron.Encoding) string {
	if scheme == oboron.SchemeLegacy {
		return string(scheme)
	}
	return string(scheme) + "." + string(enc)
}

func resolveEncoding(c *cli.Context, cfg *Config) oboron.Encoding {
	if c.String("format") != "" {
		f, err := oboron.ParseFormat(c.String("format"))
		if err == nil {
			return f.Encoding()
		}
	}
	if c.Bool("c32") {
		return oboron.EncodingC32
	}
	if c.Bool("b32") {
		return oboron.EncodingB32
	}
	if c.Bool("b64") {
		return oboron.EncodingB64
	}
	if c.Bool("hex") {
		return oboron.EncodingHex
	}
	if cfg != nil && cfg.Encoding != "" {
		enc, err := oboron.ParseEncoding(cfg.Encoding)
		if err == nil {
			return enc
		}
	}
	return oboron.EncodingC32 // CLI.md §3 default
}

// --- Commands ---

func encCmd() *cli.Command {
	flags := append(secretFlags(), append(schemeFlags(), append(encodingFlags(), formatFlag())...)...)
	return &cli.Command{
		Name:      "enc",
		Aliases:   []string{"e"},
		Usage:     "Encode a plaintext string using z-tier obfuscation",
		ArgsUsage: "[TEXT]",
		Flags:     flags,
		Action:    encAction,
	}
}

func decCmd() *cli.Command {
	flags := append(secretFlags(), append(schemeFlags(), append(encodingFlags(), formatFlag())...)...)
	return &cli.Command{
		Name:      "dec",
		Aliases:   []string{"d"},
		Usage:     "Decode an obtext string using z-tier obfuscation",
		ArgsUsage: "[TEXT]",
		Flags:     flags,
		Action:    decAction,
	}
}

func initCmd() *cli.Command {
	return &cli.Command{
		Name:      "init",
		Aliases:   []string{"i"},
		Usage:     "Initialize obz configuration",
		ArgsUsage: "[NAME]",
		Action:    initAction,
	}
}

func configCmd() *cli.Command {
	return &cli.Command{
		Name:    "config",
		Aliases: []string{"c"},
		Usage:   "Manage obz configuration",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "keyless", Aliases: []string{"K"}, Usage: "Show keyless (public) config"},
		},
		Subcommands: []*cli.Command{
			{
				Name:   "show",
				Usage:  "Show current configuration (default)",
				Action: configShowAction,
			},
			{
				Name:  "set",
				Usage: "Update configuration values",
				Flags: append(schemeFlags(), append(encodingFlags(),
					&cli.StringFlag{Name: "profile", Aliases: []string{"p"}, Usage: "Set default profile"},
				)...),
				Action: configSetAction,
			},
		},
		Action: configShowAction,
	}
}

func profileCmd() *cli.Command {
	return &cli.Command{
		Name:    "profile",
		Aliases: []string{"p"},
		Usage:   "Manage secret profiles",
		Subcommands: []*cli.Command{
			{
				Name:    "list",
				Aliases: []string{"l"},
				Usage:   "List all profiles",
				Action:  profileListAction,
			},
			{
				Name:      "show",
				Aliases:   []string{"g", "get"},
				Usage:     "Show a profile",
				ArgsUsage: "[NAME]",
				Action:    profileShowAction,
			},
			{
				Name:      "activate",
				Aliases:   []string{"a", "use"},
				Usage:     "Set a profile as active",
				ArgsUsage: "<NAME>",
				Action:    profileActivateAction,
			},
			{
				Name:      "create",
				Aliases:   []string{"c"},
				Usage:     "Create a new profile",
				ArgsUsage: "<NAME>",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "secret", Aliases: []string{"s"}, Usage: "Secret (64 hex chars, or legacy 43-char base64); generates random if omitted"},
				},
				Action: profileCreateAction,
			},
			{
				Name:      "delete",
				Aliases:   []string{"d"},
				Usage:     "Delete a profile",
				ArgsUsage: "<NAME>",
				Action:    profileDeleteAction,
			},
			{
				Name:      "rename",
				Aliases:   []string{"r", "mv"},
				Usage:     "Rename a profile",
				ArgsUsage: "<OLD> <NEW>",
				Action:    profileRenameAction,
			},
			{
				Name:      "set",
				Usage:     "Update the secret of an existing profile",
				ArgsUsage: "<NAME>",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "secret", Aliases: []string{"s"}, Usage: "Secret (64 hex chars, or legacy 43-char base64)", Required: true},
				},
				Action: profileSetAction,
			},
		},
	}
}

func secretCmd() *cli.Command {
	return &cli.Command{
		Name:    "secret",
		Aliases: []string{"s"},
		Usage:   "Output the active obfuscation secret",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "profile", Aliases: []string{"p"}, Usage: "Profile name"},
			&cli.BoolFlag{Name: "keyless", Aliases: []string{"K"}, Usage: "Output the public (hardcoded) secret"},
			&cli.BoolFlag{Name: "hex", Aliases: []string{"x"}, Usage: "Output as hex (the default; explicit no-op)"},
			&cli.BoolFlag{Name: "base64", Aliases: []string{"B"}, Usage: "Output as base64 (deprecated; conflicts with --hex)"},
		},
		Action: secretAction,
	}
}

func secretgenCmd() *cli.Command {
	return &cli.Command{
		Name:   "secretgen",
		Usage:  "Print a freshly generated random z-tier secret (64-char hex) and exit",
		Action: secretgenAction,
	}
}

func completionCmd() *cli.Command {
	return &cli.Command{
		Name:  "completion",
		Usage: "Generate shell completion script",
		Subcommands: []*cli.Command{
			{Name: "bash", Usage: "bash completion", Action: completionAction("bash")},
			{Name: "zsh", Usage: "zsh completion", Action: completionAction("zsh")},
			{Name: "fish", Usage: "fish completion", Action: completionAction("fish")},
			{Name: "powershell", Usage: "powershell completion", Action: completionAction("powershell")},
		},
	}
}

// --- Action implementations ---

func encAction(c *cli.Context) error {
	text, err := readTextInput(c)
	if err != nil {
		return err
	}
	if text == "" {
		return fmt.Errorf("no input provided")
	}

	sec, err := resolveSecret(c)
	if err != nil {
		return err
	}

	cfg, _ := loadConfig()
	scheme, err := resolveScheme(c, cfg)
	if err != nil {
		return err
	}
	enc := resolveEncoding(c, cfg)

	ob, err := ztier.NewOmnibz(sec.Hex())
	if err != nil {
		return err
	}

	result, err := ob.Enc(text, formatString(scheme, enc))
	if err != nil {
		return err
	}

	fmt.Println(result)
	return nil
}

func decAction(c *cli.Context) error {
	text, err := readTextInput(c)
	if err != nil {
		return err
	}
	if text == "" {
		return fmt.Errorf("no input provided")
	}

	sec, err := resolveSecret(c)
	if err != nil {
		return err
	}

	ob, err := ztier.NewOmnibz(sec.Hex())
	if err != nil {
		return err
	}

	cfg, _ := loadConfig()

	// If a format or scheme flag is given, decode strictly; otherwise autodetect.
	if c.String("format") != "" || c.Bool("zrbcx") || c.Bool("legacy") {
		scheme, err := resolveScheme(c, cfg)
		if err != nil {
			return err
		}
		enc := resolveEncoding(c, cfg)
		result, err := ob.Dec(text, formatString(scheme, enc))
		if err != nil {
			return err
		}
		fmt.Println(result)
		return nil
	}

	// No scheme specified: autodetect the scheme (and encoding) from the obtext.
	result, err := ob.Autodec(text)
	if err != nil {
		return err
	}
	fmt.Println(result)
	return nil
}

func initAction(c *cli.Context) error {
	name := "default"
	if c.NArg() > 0 {
		name = c.Args().First()
	}

	sec, err := generateSecret()
	if err != nil {
		return err
	}

	if err := saveProfile(name, &SecretProfile{Secret: sec.Hex()}); err != nil {
		return err
	}

	cfg := &Config{Profile: name, Scheme: "zrbcx"}
	if existing, err := loadConfig(); err == nil {
		cfg.Scheme = existing.Scheme
		cfg.Encoding = existing.Encoding
	}
	cfg.Profile = name

	if err := saveConfig(cfg); err != nil {
		return err
	}

	fmt.Printf("✓ Initialized obz configuration in %s\n", obzDir())
	fmt.Printf("\nProfile %q:\n", name)
	fmt.Printf("  Secret: %s\n", sec.Hex())
	fmt.Println("\n⚠️  Keep this secret secure!")
	return nil
}

func configShowAction(c *cli.Context) error {
	if c.Bool("keyless") {
		sec := ztier.HardcodedSecret()
		fmt.Println("Keyless (public) mode:")
		fmt.Printf("  Secret: %s\n", sec.Hex())
		return nil
	}

	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("no configuration found; run 'obz init' first")
	}

	fmt.Println("Current configuration:")
	fmt.Printf("  Profile:  %s\n", cfg.Profile)
	fmt.Printf("  Scheme:   %s\n", cfg.Scheme)
	if cfg.Encoding != "" {
		fmt.Printf("  Encoding: %s\n", cfg.Encoding)
	}

	if prof, err := loadProfile(cfg.Profile); err == nil {
		fmt.Printf("  Secret:   %s\n", prof.Secret)
	}
	return nil
}

func configSetAction(c *cli.Context) error {
	cfg, err := loadConfig()
	if err != nil {
		cfg = &Config{Profile: "default", Scheme: "zrbcx"}
	}

	// Update scheme
	switch {
	case c.Bool("zrbcx"):
		cfg.Scheme = "zrbcx"
	case c.Bool("legacy"):
		cfg.Scheme = "legacy"
	}

	// Update encoding
	switch {
	case c.Bool("c32"):
		cfg.Encoding = "c32"
	case c.Bool("b32"):
		cfg.Encoding = "b32"
	case c.Bool("b64"):
		cfg.Encoding = "b64"
	case c.Bool("hex"):
		cfg.Encoding = "hex"
	}

	// Update profile
	if p := c.String("profile"); p != "" {
		cfg.Profile = p
	}

	if err := saveConfig(cfg); err != nil {
		return err
	}

	fmt.Println("✓ Configuration updated")
	fmt.Printf("  Profile:  %s\n", cfg.Profile)
	fmt.Printf("  Scheme:   %s\n", cfg.Scheme)
	if cfg.Encoding != "" {
		fmt.Printf("  Encoding: %s\n", cfg.Encoding)
	}
	return nil
}

func profileListAction(c *cli.Context) error {
	return listProfiles()
}

func profileShowAction(c *cli.Context) error {
	name := ""
	if c.NArg() > 0 {
		name = c.Args().First()
	} else {
		cfg, err := loadConfig()
		if err != nil {
			return fmt.Errorf("no profile specified and no config found; run 'obz init'")
		}
		name = cfg.Profile
	}

	prof, err := loadProfile(name)
	if err != nil {
		return err
	}

	fmt.Printf("Profile %q:\n  Secret: %s\n", name, prof.Secret)
	return nil
}

func profileActivateAction(c *cli.Context) error {
	if c.NArg() < 1 {
		return fmt.Errorf("profile name required")
	}
	name := c.Args().First()

	if _, err := loadProfile(name); err != nil {
		return err
	}

	cfg, err := loadConfig()
	if err != nil {
		cfg = &Config{Profile: name, Scheme: "zrbcx"}
	} else {
		cfg.Profile = name
	}

	if err := saveConfig(cfg); err != nil {
		return err
	}
	fmt.Printf("✓ Activated profile %q\n", name)
	return nil
}

func profileCreateAction(c *cli.Context) error {
	if c.NArg() < 1 {
		return fmt.Errorf("profile name required")
	}
	name := c.Args().First()

	var sec *ztier.Secret
	if secretStr := c.String("secret"); secretStr != "" {
		var err error
		sec, err = ztier.SecretFromString(secretStr)
		if err != nil {
			return fmt.Errorf("invalid secret: %w", err)
		}
	} else {
		var err error
		sec, err = generateSecret()
		if err != nil {
			return err
		}
	}

	return createProfile(name, sec)
}

func profileDeleteAction(c *cli.Context) error {
	if c.NArg() < 1 {
		return fmt.Errorf("profile name required")
	}
	return deleteProfile(c.Args().First())
}

func profileRenameAction(c *cli.Context) error {
	if c.NArg() < 2 {
		return fmt.Errorf("usage: obz profile rename <OLD> <NEW>")
	}
	return renameProfile(c.Args().Get(0), c.Args().Get(1))
}

func profileSetAction(c *cli.Context) error {
	if c.NArg() < 1 {
		return fmt.Errorf("profile name required")
	}
	name := c.Args().First()

	sec, err := ztier.SecretFromString(c.String("secret"))
	if err != nil {
		return fmt.Errorf("invalid secret: %w", err)
	}

	if err := saveProfile(name, &SecretProfile{Secret: sec.Hex()}); err != nil {
		return err
	}
	fmt.Printf("✓ Updated profile %q\n", name)
	return nil
}

// secretOutputBase64 reports whether secret output should use the deprecated
// base64 form. Hex is the canonical default (CLI §4.3); --base64 opts into the
// legacy form and emits a deprecation notice to stderr.
func secretOutputBase64(c *cli.Context) (bool, error) {
	if !c.Bool("base64") {
		return false, nil
	}
	if c.Bool("hex") {
		return false, fmt.Errorf("--base64 conflicts with --hex")
	}
	fmt.Fprintln(os.Stderr, "warning: base64 secret output is deprecated; hex is the canonical format")
	return true, nil
}

func secretAction(c *cli.Context) error {
	useB64, err := secretOutputBase64(c)
	if err != nil {
		return err
	}

	var sec *ztier.Secret
	if c.Bool("keyless") {
		sec = ztier.HardcodedSecret()
	} else {
		cfg, _ := loadConfig()
		profileName := c.String("profile")
		if profileName == "" && cfg != nil {
			profileName = cfg.Profile
		}
		if profileName == "" {
			profileName = "default"
		}

		prof, err := loadProfile(profileName)
		if err != nil {
			return err
		}
		sec, err = ztier.SecretFromString(prof.Secret)
		if err != nil {
			return fmt.Errorf("invalid secret in profile: %w", err)
		}
	}

	if useB64 {
		fmt.Println(sec.Base64())
	} else {
		fmt.Println(sec.Hex())
	}
	return nil
}

func secretgenAction(c *cli.Context) error {
	sec, err := generateSecret()
	if err != nil {
		return err
	}
	fmt.Println(sec.Hex())
	return nil
}

func completionAction(shell string) cli.ActionFunc {
	return func(c *cli.Context) error {
		fmt.Fprintf(os.Stderr, "Shell completion for %s is not yet implemented.\n", shell)
		fmt.Fprintf(os.Stderr, "Please file an issue at https://gitlab.com/oboron/oboron-go\n")
		return nil
	}
}
