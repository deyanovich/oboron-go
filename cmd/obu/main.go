// Command obu is the CLI for oboron's obu schemes (upcbc and zdcbc):
// confidentiality-only (upcbc, AES-256-CBC) and reversible obfuscation
// (zdcbc) of a string — not authenticated encryption. See https://oboron.org/.
package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
	"oboron.org/go/internal/cliutil"
	"oboron.org/go/internal/version"
	"oboron.org/go/oboron"
	"oboron.org/go/obu"
)

// testSecretWarning is the §6.4 SHOULD warning emitted when the fixed public
// test secret is supplied via --secret or $OBORON_SECRET rather than --keyless.
// It is suppressed on a failed dec so only the uniform dec error appears.
const testSecretWarning = "warning: using the fixed public test secret (INSECURE — testing only); pass --keyless instead"

func main() {
	versionLine := fmt.Sprintf("obu oboron-go %s protocol=1.0 cli=1.0", cliutil.VersionToken(version.Version))
	cliutil.HandleVersionRequest(os.Args, versionLine)

	app := &cli.App{
		Name:                   "obu",
		Usage:                  "Encode and decode values with oboron obu schemes (upcbc, zdcbc)",
		HideVersion:            true,
		UseShortOptionHandling: true,
		Commands: []*cli.Command{
			encCmd(),
			decCmd(),
			initCmd(),
			configCmd(),
			profileCmd(),
			secretCmd(),
			secretgenCmd(),
		},
	}

	os.Exit(cliutil.Run(app, os.Args))
}

// --- Shared flag builders ---

func secretFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name: "secret",
			// No single-letter alias: OBU.md §6 forbids one, to avoid
			// confusion with the core ob CLI's -s (--dsiv) scheme flag.
			Usage:   "obu secret (64 hex chars, 256-bit); conflicts with --profile/--keyless",
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
		&cli.BoolFlag{Name: "upcbc", Aliases: []string{"u"}, Usage: "Use upcbc scheme (AES-256-CBC, confidentiality only)"},
		&cli.BoolFlag{Name: "zdcbc", Aliases: []string{"z"}, Usage: "Use zdcbc scheme (AES-128-CBC, deterministic obfuscation)"},
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
		Usage:   `Format string e.g. "upcbc.b64"; cannot combine with scheme/encoding flags`,
	}
}

func rawFlag() cli.Flag {
	return &cli.BoolFlag{
		Name:    "raw",
		Aliases: []string{"0"},
		Usage:   "Disable line framing: keep stdin's trailing newline and don't append one to stdout",
	}
}

// encDecFlags is the full flag set shared by enc and dec.
func encDecFlags() []cli.Flag {
	flags := secretFlags()
	flags = append(flags, schemeFlags()...)
	flags = append(flags, encodingFlags()...)
	flags = append(flags, formatFlag(), rawFlag())
	return flags
}

// --- Helpers ---

// validateOptions performs the usage-error (exit-2) checks that must precede any
// secret lookup or operation: at most one explicit secret source, and at most
// one TEXT argument (CLI.md §4.1; OBU.md §6.1).
func validateOptions(c *cli.Context) error {
	sources := 0
	if c.Bool("keyless") {
		sources++
	}
	if cliutil.FlagGiven(os.Args, "secret", "") {
		sources++
	}
	if cliutil.FlagGiven(os.Args, "profile", "p") {
		sources++
	}
	if sources > 1 {
		return cliutil.Usage("--secret, --keyless and --profile are mutually exclusive")
	}
	if c.NArg() > 1 {
		return cliutil.Usage("expected at most one TEXT argument")
	}
	return nil
}

// resolveFormat resolves the effective obu format string, rejecting conflicting
// scheme/encoding/--format combinations as usage errors. Only obu schemes
// (upcbc, zdcbc) are valid here.
func resolveFormat(c *cli.Context, cfg *Config) (string, error) {
	schemeCount := cliutil.CountSet(c, "upcbc", "zdcbc")
	encCount := cliutil.CountSet(c, "c32", "b32", "b64", "hex")

	if c.String("format") != "" {
		if schemeCount > 0 || encCount > 0 {
			return "", cliutil.Usage("--format cannot be combined with scheme or encoding flags")
		}
		f, err := oboron.ParseFormat(c.String("format"))
		if err != nil || !f.Scheme().IsObu() {
			return "", cliutil.Usage("invalid format %q", c.String("format"))
		}
		return f.String(), nil
	}
	if schemeCount > 1 {
		return "", cliutil.Usage("at most one scheme flag may be given")
	}
	if encCount > 1 {
		return "", cliutil.Usage("at most one encoding flag may be given")
	}
	return string(schemeFromFlags(c, cfg)) + "." + string(encodingFromFlags(c, cfg)), nil
}

func schemeFromFlags(c *cli.Context, cfg *Config) oboron.Scheme {
	switch {
	case c.Bool("upcbc"):
		return oboron.SchemeUpcbc
	case c.Bool("zdcbc"):
		return oboron.SchemeZdcbc
	}
	if cfg != nil && cfg.Scheme != "" {
		return oboron.Scheme(cfg.Scheme)
	}
	return oboron.SchemeUpcbc // built-in default for obu (OBU.md §6)
}

func encodingFromFlags(c *cli.Context, cfg *Config) oboron.Encoding {
	switch {
	case c.Bool("c32"):
		return oboron.EncodingC32
	case c.Bool("b32"):
		return oboron.EncodingB32
	case c.Bool("b64"):
		return oboron.EncodingB64
	case c.Bool("hex"):
		return oboron.EncodingHex
	}
	if cfg != nil && cfg.Encoding != "" {
		if enc, err := oboron.ParseEncoding(cfg.Encoding); err == nil {
			return enc
		}
	}
	return oboron.EncodingC32 // built-in default (CLI.md §5)
}

func isTestSecret(sec *obu.Secret) bool {
	return sec.Hex() == obu.HardcodedSecret().Hex()
}

// resolveSecret resolves the secret by the precedence keyless > --secret >
// $OBORON_SECRET > profile/config (a convenience extension) > error (OBU.md
// §6.1). The bool reports whether the fixed public test secret was supplied via
// --secret or $OBORON_SECRET (for the §6.4 warning).
func resolveSecret(c *cli.Context) (*obu.Secret, bool, error) {
	if c.Bool("keyless") {
		return obu.HardcodedSecret(), false, nil
	}
	// --secret (any form) or a non-empty $OBORON_SECRET: urfave folds both into
	// the "secret" value, with the flag taking precedence over the env var.
	if c.IsSet("secret") {
		sec, err := obu.SecretFromString(c.String("secret"))
		if err != nil {
			return nil, false, cliutil.Fail("invalid secret: %v", err)
		}
		return sec, isTestSecret(sec), nil
	}
	// An OBORON_SECRET that is set but empty is an invalid secret, not absent.
	if v, ok := os.LookupEnv("OBORON_SECRET"); ok {
		sec, err := obu.SecretFromString(v)
		if err != nil {
			return nil, false, cliutil.Fail("invalid secret: %v", err)
		}
		return sec, isTestSecret(sec), nil
	}
	// Convenience: the active/named profile (non-spec extension).
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
		return nil, false, cliutil.Fail("no secret: pass --secret, set $OBORON_SECRET, or use --keyless")
	}
	sec, err := obu.SecretFromString(prof.Secret)
	if err != nil {
		return nil, false, cliutil.Fail("invalid secret in profile: %v", err)
	}
	return sec, false, nil
}

// --- Commands ---

func encCmd() *cli.Command {
	return &cli.Command{
		Name:      "enc",
		Aliases:   []string{"e"},
		Usage:     "Encode a plaintext string using an obu scheme",
		ArgsUsage: "[TEXT]",
		Flags:     encDecFlags(),
		Action:    encAction,
	}
}

func decCmd() *cli.Command {
	return &cli.Command{
		Name:      "dec",
		Aliases:   []string{"d"},
		Usage:     "Decode an obtext string using an obu scheme",
		ArgsUsage: "[TEXT]",
		Flags:     encDecFlags(),
		Action:    decAction,
	}
}

func initCmd() *cli.Command {
	return &cli.Command{
		Name:      "init",
		Aliases:   []string{"i"},
		Usage:     "Initialize obu configuration",
		ArgsUsage: "[NAME]",
		Action:    initAction,
	}
}

func configCmd() *cli.Command {
	return &cli.Command{
		Name:    "config",
		Aliases: []string{"c"},
		Usage:   "Manage obu configuration",
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
					&cli.StringFlag{Name: "secret", Aliases: []string{"s"}, Usage: "Secret (64 hex chars); generates random if omitted"},
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
					&cli.StringFlag{Name: "secret", Aliases: []string{"s"}, Usage: "Secret (64 hex chars)", Required: true},
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
		Usage:   "Output the active obu secret (64-char hex)",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "profile", Aliases: []string{"p"}, Usage: "Profile name"},
			&cli.BoolFlag{Name: "keyless", Aliases: []string{"K"}, Usage: "Output the public (hardcoded) secret"},
		},
		Action: secretAction,
	}
}

func secretgenCmd() *cli.Command {
	return &cli.Command{
		Name:   "secretgen",
		Usage:  "Print a freshly generated random obu secret (64-char hex) and exit",
		Action: secretgenAction,
	}
}

// --- Action implementations ---

func encAction(c *cli.Context) error {
	if err := validateOptions(c); err != nil {
		return err
	}
	cfg, _ := loadConfig()
	format, err := resolveFormat(c, cfg)
	if err != nil {
		return err
	}
	sec, testSecret, err := resolveSecret(c)
	if err != nil {
		return err
	}
	raw := c.Bool("raw")
	text, err := cliutil.ReadInput(c, raw)
	if err != nil {
		return cliutil.Fail("failed to read input: %v", err)
	}
	if text == "" {
		return cliutil.Fail("empty plaintext is rejected")
	}

	om, err := obu.NewOmnibu(sec.Hex())
	if err != nil {
		return cliutil.Fail("%v", err)
	}
	out, err := om.Enc(text, format)
	if err != nil {
		return cliutil.Fail("%v", err)
	}
	if testSecret {
		fmt.Fprintln(os.Stderr, testSecretWarning)
	}
	cliutil.Output(out, raw)
	return nil
}

func decAction(c *cli.Context) error {
	if err := validateOptions(c); err != nil {
		return err
	}
	cfg, _ := loadConfig()
	// The obtext carries no scheme marker, so dec uses the resolved format
	// (defaulting to upcbc.c32); it never auto-detects.
	format, err := resolveFormat(c, cfg)
	if err != nil {
		return err
	}
	sec, testSecret, err := resolveSecret(c)
	if err != nil {
		return err
	}
	raw := c.Bool("raw")
	text, err := cliutil.ReadInput(c, raw)
	if err != nil {
		return cliutil.Fail("failed to read input: %v", err)
	}
	if text == "" {
		return cliutil.DecFail()
	}

	om, err := obu.NewOmnibu(sec.Hex())
	if err != nil {
		return cliutil.Fail("%v", err)
	}
	out, err := om.Dec(text, format)
	if err != nil {
		// Uniform dec error (CLI.md §8); the §6.4 test-secret warning is
		// suppressed here so it cannot leak on a failed dec.
		return cliutil.DecFail()
	}
	if testSecret {
		fmt.Fprintln(os.Stderr, testSecretWarning)
	}
	cliutil.Output(out, raw)
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

	cfg := &Config{Profile: name, Scheme: "upcbc"}
	if existing, err := loadConfig(); err == nil {
		cfg.Scheme = existing.Scheme
		cfg.Encoding = existing.Encoding
	}
	cfg.Profile = name

	if err := saveConfig(cfg); err != nil {
		return err
	}

	fmt.Printf("✓ Initialized obu configuration in %s\n", obuDir())
	fmt.Printf("\nProfile %q:\n", name)
	fmt.Printf("  Secret: %s\n", sec.Hex())
	fmt.Println("\n⚠️  Keep this secret secure!")
	return nil
}

func configShowAction(c *cli.Context) error {
	if c.Bool("keyless") {
		sec := obu.HardcodedSecret()
		fmt.Println("Keyless (public) mode:")
		fmt.Printf("  Secret: %s\n", sec.Hex())
		return nil
	}

	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("no configuration found; run 'obu init' first")
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
		cfg = &Config{Profile: "default", Scheme: "upcbc"}
	}

	// Update scheme
	switch {
	case c.Bool("upcbc"):
		cfg.Scheme = "upcbc"
	case c.Bool("zdcbc"):
		cfg.Scheme = "zdcbc"
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
			return fmt.Errorf("no profile specified and no config found; run 'obu init'")
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
		cfg = &Config{Profile: name, Scheme: "upcbc"}
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

	var sec *obu.Secret
	if secretStr := c.String("secret"); secretStr != "" {
		var err error
		sec, err = obu.SecretFromString(secretStr)
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
		return fmt.Errorf("usage: obu profile rename <OLD> <NEW>")
	}
	return renameProfile(c.Args().Get(0), c.Args().Get(1))
}

func profileSetAction(c *cli.Context) error {
	if c.NArg() < 1 {
		return fmt.Errorf("profile name required")
	}
	name := c.Args().First()

	sec, err := obu.SecretFromString(c.String("secret"))
	if err != nil {
		return fmt.Errorf("invalid secret: %w", err)
	}

	if err := saveProfile(name, &SecretProfile{Secret: sec.Hex()}); err != nil {
		return err
	}
	fmt.Printf("✓ Updated profile %q\n", name)
	return nil
}

func secretAction(c *cli.Context) error {
	var sec *obu.Secret
	if c.Bool("keyless") {
		sec = obu.HardcodedSecret()
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
		var perr error
		sec, perr = obu.SecretFromString(prof.Secret)
		if perr != nil {
			return fmt.Errorf("invalid secret in profile: %w", perr)
		}
	}

	fmt.Println(sec.Hex())
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
