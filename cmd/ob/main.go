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
)

func main() {
	app := &cli.App{
		Name:                   "ob",
		Usage:                  "Encrypt and encode values with oboron secure schemes",
		Version:                version.Version,
		UseShortOptionHandling: true,
		Commands: []*cli.Command{
			encCmd(),
			decCmd(),
			initCmd(),
			configCmd(),
			profileCmd(),
			keyCmd(),
			keygenCmd(),
			completionCmd(),
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

// --- Shared flag builders ---

func keyFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "key",
			Aliases: []string{"k"},
			Usage:   "Encryption key (128 hex chars, 512-bit; or legacy 86-char base64); conflicts with --profile/--keyless",
			EnvVars: []string{"OBORON_KEY"},
		},
		&cli.StringFlag{
			Name:    "profile",
			Aliases: []string{"p"},
			Usage:   "Use named key profile; conflicts with --key/--keyless",
		},
		&cli.BoolFlag{
			Name:    "keyless",
			Aliases: []string{"K"},
			Usage:   "Use hardcoded key (INSECURE — testing only); conflicts with --key/--profile",
		},
	}
}

func schemeFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{Name: "aasv", Aliases: []string{"s"}, Usage: "Use aasv scheme (deterministic AES-SIV)"},
		&cli.BoolFlag{Name: "apsv", Aliases: []string{"S"}, Usage: "Use apsv scheme (probabilistic AES-SIV)"},
		&cli.BoolFlag{Name: "aags", Aliases: []string{"g"}, Usage: "Use aags scheme (deterministic AES-GCM-SIV)"},
		&cli.BoolFlag{Name: "apgs", Aliases: []string{"G"}, Usage: "Use apgs scheme (probabilistic AES-GCM-SIV)"},
		&cli.BoolFlag{Name: "upbc", Aliases: []string{"u"}, Usage: "Use upbc scheme (probabilistic AES-256-CBC)"},
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
		Usage:   `Format string e.g. "aasv.b64"; cannot combine with scheme/encoding flags`,
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

func resolveMasterKey(c *cli.Context) (*oboron.MasterKey, error) {
	if c.Bool("keyless") {
		return oboron.HardcodedMasterKey(), nil
	}

	// Key flag / env var (EnvVars handles $OBORON_KEY automatically)
	if keyStr := c.String("key"); keyStr != "" {
		return oboron.MasterKeyFromString(keyStr)
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
	return oboron.MasterKeyFromString(prof.Key)
}

func resolveScheme(c *cli.Context, cfg *Config) (oboron.Scheme, error) {
	if c.String("format") != "" {
		f, err := oboron.ParseFormat(c.String("format"))
		if err != nil {
			return "", err
		}
		return f.Scheme(), nil
	}
	if c.Bool("aasv") {
		return oboron.SchemeAasv, nil
	}
	if c.Bool("apsv") {
		return oboron.SchemeApsv, nil
	}
	if c.Bool("aags") {
		return oboron.SchemeAags, nil
	}
	if c.Bool("apgs") {
		return oboron.SchemeApgs, nil
	}
	if c.Bool("upbc") {
		return oboron.SchemeUpbc, nil
	}
	if cfg != nil && cfg.Scheme != "" {
		return oboron.Scheme(cfg.Scheme), nil
	}
	return oboron.SchemeAasv, nil // spec default
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
	flags := append(keyFlags(), append(schemeFlags(), append(encodingFlags(), formatFlag())...)...)
	return &cli.Command{
		Name:      "enc",
		Aliases:   []string{"e"},
		Usage:     "Encrypt+encode a plaintext string",
		ArgsUsage: "[TEXT]",
		Flags:     flags,
		Action:    encAction,
	}
}

func decCmd() *cli.Command {
	flags := append(keyFlags(), append(schemeFlags(), append(encodingFlags(), formatFlag())...)...)
	return &cli.Command{
		Name:      "dec",
		Aliases:   []string{"d"},
		Usage:     "Decode+decrypt an obtext string",
		ArgsUsage: "[TEXT]",
		Flags:     flags,
		Action:    decAction,
	}
}

func initCmd() *cli.Command {
	return &cli.Command{
		Name:      "init",
		Aliases:   []string{"i"},
		Usage:     "Initialize configuration",
		ArgsUsage: "[NAME]",
		Action:    initAction,
	}
}

func configCmd() *cli.Command {
	return &cli.Command{
		Name:    "config",
		Aliases: []string{"c"},
		Usage:   "Manage configuration",
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
		Usage:   "Manage key profiles",
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
					&cli.StringFlag{Name: "key", Aliases: []string{"k"}, Usage: "Key (128 hex chars, or legacy 86-char base64); generates random if omitted"},
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
				Usage:     "Update the key of an existing profile",
				ArgsUsage: "<NAME>",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "key", Aliases: []string{"k"}, Usage: "Key (128 hex chars, or legacy 86-char base64)", Required: true},
				},
				Action: profileSetAction,
			},
		},
	}
}

func keyCmd() *cli.Command {
	return &cli.Command{
		Name:    "key",
		Aliases: []string{"k"},
		Usage:   "Output the active encryption key",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "profile", Aliases: []string{"p"}, Usage: "Profile name"},
			&cli.BoolFlag{Name: "keyless", Aliases: []string{"K"}, Usage: "Output the public (hardcoded) key"},
			&cli.BoolFlag{Name: "hex", Aliases: []string{"x"}, Usage: "Output as hex (the default; explicit no-op)"},
			&cli.BoolFlag{Name: "base64", Aliases: []string{"B"}, Usage: "Output as base64 (deprecated; conflicts with --hex)"},
		},
		Action: keyAction,
	}
}

func keygenCmd() *cli.Command {
	return &cli.Command{
		Name:   "keygen",
		Usage:  "Print a freshly generated random key (128-char hex) and exit",
		Action: keygenAction,
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

	mk, err := resolveMasterKey(c)
	if err != nil {
		return err
	}

	cfg, _ := loadConfig()
	scheme, err := resolveScheme(c, cfg)
	if err != nil {
		return err
	}
	enc := resolveEncoding(c, cfg)

	ob, err := oboron.NewOmnibFromMasterKey(mk)
	if err != nil {
		return err
	}

	result, err := ob.EncodeWithFormat(text, fmt.Sprintf("%s.%s", scheme, enc))
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

	mk, err := resolveMasterKey(c)
	if err != nil {
		return err
	}

	ob, err := oboron.NewOmnibFromMasterKey(mk)
	if err != nil {
		return err
	}

	cfg, _ := loadConfig()

	// If a format or scheme flag is given, decode strictly; otherwise autodetect.
	if c.String("format") != "" || c.Bool("aasv") || c.Bool("apsv") || c.Bool("aags") || c.Bool("apgs") || c.Bool("upbc") {
		scheme, err := resolveScheme(c, cfg)
		if err != nil {
			return err
		}
		enc := resolveEncoding(c, cfg)
		result, err := ob.DecodeWithFormat(text, fmt.Sprintf("%s.%s", scheme, enc))
		if err != nil {
			return err
		}
		fmt.Println(result)
		return nil
	}

	// Autodetect encoding too if no encoding flag
	if c.Bool("c32") || c.Bool("b32") || c.Bool("b64") || c.Bool("hex") {
		enc := resolveEncoding(c, cfg)
		result, err := ob.DecodeWithEncoding(text, enc)
		if err != nil {
			return err
		}
		fmt.Println(result)
		return nil
	}

	result, err := ob.DecodeAny(text)
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

	mk, err := generateMasterKey()
	if err != nil {
		return err
	}

	if err := saveProfile(name, &KeyProfile{Key: mk.Hex()}); err != nil {
		return err
	}

	cfg := &Config{Profile: name, Scheme: "aasv"}
	if existing, err := loadConfig(); err == nil {
		cfg.Scheme = existing.Scheme
		cfg.Encoding = existing.Encoding
	}
	cfg.Profile = name

	if err := saveConfig(cfg); err != nil {
		return err
	}

	fmt.Printf("✓ Initialized ob configuration in %s\n", oboronDir())
	fmt.Printf("\nProfile %q:\n", name)
	fmt.Printf("  Key: %s\n", mk.Hex())
	fmt.Println("\n⚠️  Keep this key secure!")
	return nil
}

func configShowAction(c *cli.Context) error {
	if c.Bool("keyless") {
		mk := oboron.HardcodedMasterKey()
		fmt.Println("Keyless (public) mode:")
		fmt.Printf("  Key: %s\n", mk.Hex())
		return nil
	}

	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("no configuration found; run 'ob init' first")
	}

	fmt.Println("Current configuration:")
	fmt.Printf("  Profile:  %s\n", cfg.Profile)
	fmt.Printf("  Scheme:   %s\n", cfg.Scheme)
	if cfg.Encoding != "" {
		fmt.Printf("  Encoding: %s\n", cfg.Encoding)
	}

	if prof, err := loadProfile(cfg.Profile); err == nil {
		fmt.Printf("  Key:      %s\n", prof.Key)
	}
	return nil
}

func configSetAction(c *cli.Context) error {
	cfg, err := loadConfig()
	if err != nil {
		cfg = &Config{Profile: "default", Scheme: "aasv"}
	}

	// Update scheme
	switch {
	case c.Bool("aasv"):
		cfg.Scheme = "aasv"
	case c.Bool("apsv"):
		cfg.Scheme = "apsv"
	case c.Bool("aags"):
		cfg.Scheme = "aags"
	case c.Bool("apgs"):
		cfg.Scheme = "apgs"
	case c.Bool("upbc"):
		cfg.Scheme = "upbc"
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
			return fmt.Errorf("no profile specified and no config found; run 'ob init'")
		}
		name = cfg.Profile
	}

	prof, err := loadProfile(name)
	if err != nil {
		return err
	}

	fmt.Printf("Profile %q:\n  Key: %s\n", name, prof.Key)
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
		cfg = &Config{Profile: name, Scheme: "aasv"}
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

	var mk *oboron.MasterKey
	if keyStr := c.String("key"); keyStr != "" {
		var err error
		mk, err = oboron.MasterKeyFromString(keyStr)
		if err != nil {
			return fmt.Errorf("invalid key: %w", err)
		}
	} else {
		var err error
		mk, err = generateMasterKey()
		if err != nil {
			return err
		}
	}

	return createProfile(name, mk)
}

func profileDeleteAction(c *cli.Context) error {
	if c.NArg() < 1 {
		return fmt.Errorf("profile name required")
	}
	return deleteProfile(c.Args().First())
}

func profileRenameAction(c *cli.Context) error {
	if c.NArg() < 2 {
		return fmt.Errorf("usage: ob profile rename <OLD> <NEW>")
	}
	return renameProfile(c.Args().Get(0), c.Args().Get(1))
}

func profileSetAction(c *cli.Context) error {
	if c.NArg() < 1 {
		return fmt.Errorf("profile name required")
	}
	name := c.Args().First()

	mk, err := oboron.MasterKeyFromString(c.String("key"))
	if err != nil {
		return fmt.Errorf("invalid key: %w", err)
	}

	if err := saveProfile(name, &KeyProfile{Key: mk.Hex()}); err != nil {
		return err
	}
	fmt.Printf("✓ Updated profile %q\n", name)
	return nil
}

// keyOutputBase64 reports whether key output should use the deprecated base64
// form. Hex is the canonical default (CLI §4.3); --base64 opts into the legacy
// form and emits a deprecation notice to stderr.
func keyOutputBase64(c *cli.Context) (bool, error) {
	if !c.Bool("base64") {
		return false, nil
	}
	if c.Bool("hex") {
		return false, fmt.Errorf("--base64 conflicts with --hex")
	}
	fmt.Fprintln(os.Stderr, "warning: base64 key output is deprecated; hex is the canonical format")
	return true, nil
}

func keyAction(c *cli.Context) error {
	useB64, err := keyOutputBase64(c)
	if err != nil {
		return err
	}

	var mk *oboron.MasterKey
	if c.Bool("keyless") {
		mk = oboron.HardcodedMasterKey()
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
		mk, err = oboron.MasterKeyFromString(prof.Key)
		if err != nil {
			return fmt.Errorf("invalid key in profile: %w", err)
		}
	}

	if useB64 {
		fmt.Println(mk.Base64())
	} else {
		fmt.Println(mk.Hex())
	}
	return nil
}

func keygenAction(c *cli.Context) error {
	mk, err := generateMasterKey()
	if err != nil {
		return err
	}
	fmt.Println(mk.Hex())
	return nil
}

func completionAction(shell string) cli.ActionFunc {
	return func(c *cli.Context) error {
		fmt.Fprintf(os.Stderr, "Shell completion for %s is not yet implemented.\n", shell)
		fmt.Fprintf(os.Stderr, "Please file an issue at https://gitlab.com/oboron/oboron-go\n")
		return nil
	}
}
