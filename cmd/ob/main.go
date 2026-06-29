// Command ob is the CLI for oboron's authenticated schemes: it encrypts a
// UTF-8 string into compact, URL-safe obtext and decrypts it back. See
// https://oboron.org/.
package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
	"oboron.org/go/internal/cliutil"
	"oboron.org/go/internal/version"
	"oboron.org/go/oboron"
)

// testKeyWarning is the §9 SHOULD warning emitted when the fixed public test
// key is supplied via --key or $OBORON_KEY rather than --keyless. It is
// suppressed on a failed dec so only the uniform dec error appears.
const testKeyWarning = "warning: using the fixed public test key (INSECURE — testing only); pass --keyless instead"

func main() {
	versionLine := fmt.Sprintf("ob oboron-go %s protocol=1.0 cli=1.0", cliutil.VersionToken(version.Version))
	cliutil.HandleVersionRequest(os.Args, versionLine)

	app := &cli.App{
		Name:                   "ob",
		Usage:                  "Encrypt and encode values with oboron authenticated schemes",
		HideVersion:            true,
		UseShortOptionHandling: true,
		Commands: []*cli.Command{
			encCmd(),
			decCmd(),
			initCmd(),
			configCmd(),
			profileCmd(),
			keyCmd(),
			keygenCmd(),
		},
	}

	os.Exit(cliutil.Run(app, os.Args))
}

// --- Shared flag builders ---

func keyFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "key",
			Aliases: []string{"k"},
			Usage:   "Encryption key (128 hex chars, 512-bit); conflicts with --profile/--keyless",
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
		&cli.BoolFlag{Name: "dsiv", Aliases: []string{"s"}, Usage: "Use dsiv scheme (deterministic AES-SIV)"},
		&cli.BoolFlag{Name: "psiv", Aliases: []string{"S"}, Usage: "Use psiv scheme (probabilistic AES-SIV)"},
		&cli.BoolFlag{Name: "dgcmsiv", Aliases: []string{"g"}, Usage: "Use dgcmsiv scheme (deterministic AES-GCM-SIV)"},
		&cli.BoolFlag{Name: "pgcmsiv", Aliases: []string{"G"}, Usage: "Use pgcmsiv scheme (probabilistic AES-GCM-SIV)"},
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
		Usage:   `Format string e.g. "dsiv.b64"; cannot combine with scheme/encoding flags`,
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
	flags := keyFlags()
	flags = append(flags, schemeFlags()...)
	flags = append(flags, encodingFlags()...)
	flags = append(flags, formatFlag(), rawFlag())
	return flags
}

// --- Helpers ---

// validateOptions performs the usage-error (exit-2) checks that must precede any
// key lookup or operation: at most one explicit key source, and at most one TEXT
// argument (CLI.md §4.1, §6).
func validateOptions(c *cli.Context) error {
	sources := 0
	if c.Bool("keyless") {
		sources++
	}
	if cliutil.FlagGiven(os.Args, "key", "k") {
		sources++
	}
	if cliutil.FlagGiven(os.Args, "profile", "p") {
		sources++
	}
	if sources > 1 {
		return cliutil.Usage("--key, --keyless and --profile are mutually exclusive")
	}
	if c.NArg() > 1 {
		return cliutil.Usage("expected at most one TEXT argument")
	}
	return nil
}

// resolveFormat resolves the effective format string, rejecting conflicting
// scheme/encoding/--format combinations as usage errors (CLI.md §4.1, §5). obu
// schemes are not valid here.
func resolveFormat(c *cli.Context, cfg *Config) (string, error) {
	schemeCount := cliutil.CountSet(c, "dsiv", "psiv", "dgcmsiv", "pgcmsiv")
	encCount := cliutil.CountSet(c, "c32", "b32", "b64", "hex")

	if c.String("format") != "" {
		if schemeCount > 0 || encCount > 0 {
			return "", cliutil.Usage("--format cannot be combined with scheme or encoding flags")
		}
		f, err := oboron.ParseFormat(c.String("format"))
		if err != nil || f.Scheme().IsObu() {
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
	case c.Bool("dsiv"):
		return oboron.SchemeDsiv
	case c.Bool("psiv"):
		return oboron.SchemePsiv
	case c.Bool("dgcmsiv"):
		return oboron.SchemeDgcmsiv
	case c.Bool("pgcmsiv"):
		return oboron.SchemePgcmsiv
	}
	if cfg != nil && cfg.Scheme != "" {
		return oboron.Scheme(cfg.Scheme)
	}
	return oboron.SchemeDsiv // built-in default (CLI.md §5)
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

func isTestKey(mk *oboron.MasterKey) bool {
	return mk.Hex() == oboron.HardcodedMasterKey().Hex()
}

// resolveMasterKey resolves the key by the spec precedence keyless > --key >
// $OBORON_KEY > profile/config (a convenience extension) > error (CLI.md §6).
// The bool reports whether the fixed public test key was supplied via --key or
// $OBORON_KEY (for the §9 warning).
func resolveMasterKey(c *cli.Context) (*oboron.MasterKey, bool, error) {
	if c.Bool("keyless") {
		return oboron.HardcodedMasterKey(), false, nil
	}
	// --key (any form) or a non-empty $OBORON_KEY: urfave folds both into the
	// "key" value, with the flag taking precedence over the env var.
	if c.IsSet("key") {
		mk, err := oboron.MasterKeyFromString(c.String("key"))
		if err != nil {
			return nil, false, cliutil.Fail("invalid key: %v", err)
		}
		return mk, isTestKey(mk), nil
	}
	// An OBORON_KEY that is set but empty is an invalid key, not an absent one.
	if v, ok := os.LookupEnv("OBORON_KEY"); ok {
		mk, err := oboron.MasterKeyFromString(v)
		if err != nil {
			return nil, false, cliutil.Fail("invalid key: %v", err)
		}
		return mk, isTestKey(mk), nil
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
		return nil, false, cliutil.Fail("no key: pass --key, set $OBORON_KEY, or use --keyless")
	}
	mk, err := oboron.MasterKeyFromString(prof.Key)
	if err != nil {
		return nil, false, cliutil.Fail("invalid key in profile: %v", err)
	}
	return mk, false, nil
}

// --- Commands ---

func encCmd() *cli.Command {
	return &cli.Command{
		Name:      "enc",
		Aliases:   []string{"e"},
		Usage:     "Encrypt+encode a plaintext string",
		ArgsUsage: "[TEXT]",
		Flags:     encDecFlags(),
		Action:    encAction,
	}
}

func decCmd() *cli.Command {
	return &cli.Command{
		Name:      "dec",
		Aliases:   []string{"d"},
		Usage:     "Decode+decrypt an obtext string",
		ArgsUsage: "[TEXT]",
		Flags:     encDecFlags(),
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
					&cli.StringFlag{Name: "key", Aliases: []string{"k"}, Usage: "Key (128 hex chars); generates random if omitted"},
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
					&cli.StringFlag{Name: "key", Aliases: []string{"k"}, Usage: "Key (128 hex chars)", Required: true},
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
		Usage:   "Output the active encryption key (128-char hex)",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "profile", Aliases: []string{"p"}, Usage: "Profile name"},
			&cli.BoolFlag{Name: "keyless", Aliases: []string{"K"}, Usage: "Output the public (hardcoded) key"},
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
	mk, testKey, err := resolveMasterKey(c)
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

	om, err := oboron.NewOmnib(mk.Hex())
	if err != nil {
		return cliutil.Fail("%v", err)
	}
	out, err := om.Enc(text, format)
	if err != nil {
		return cliutil.Fail("%v", err)
	}
	if testKey {
		fmt.Fprintln(os.Stderr, testKeyWarning)
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
	// (defaulting to dsiv.c32); it never auto-detects (CLI.md §4.2).
	format, err := resolveFormat(c, cfg)
	if err != nil {
		return err
	}
	mk, testKey, err := resolveMasterKey(c)
	if err != nil {
		return err
	}
	raw := c.Bool("raw")
	text, err := cliutil.ReadInput(c, raw)
	if err != nil {
		return cliutil.Fail("failed to read input: %v", err)
	}
	if text == "" {
		// An empty obtext is a dec failure; report via the uniform message.
		return cliutil.DecFail()
	}

	om, err := oboron.NewOmnib(mk.Hex())
	if err != nil {
		return cliutil.Fail("%v", err)
	}
	out, err := om.Dec(text, format)
	if err != nil {
		// Every dec failure shares one uniform message (CLI.md §8); the §9
		// test-key warning is suppressed here so it cannot leak.
		return cliutil.DecFail()
	}
	if testKey {
		fmt.Fprintln(os.Stderr, testKeyWarning)
	}
	cliutil.Output(out, raw)
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

	cfg := &Config{Profile: name, Scheme: "dsiv"}
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
		cfg = &Config{Profile: "default", Scheme: "dsiv"}
	}

	// Update scheme
	switch {
	case c.Bool("dsiv"):
		cfg.Scheme = "dsiv"
	case c.Bool("psiv"):
		cfg.Scheme = "psiv"
	case c.Bool("dgcmsiv"):
		cfg.Scheme = "dgcmsiv"
	case c.Bool("pgcmsiv"):
		cfg.Scheme = "pgcmsiv"
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
		cfg = &Config{Profile: name, Scheme: "dsiv"}
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

func keyAction(c *cli.Context) error {
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
		var perr error
		mk, perr = oboron.MasterKeyFromString(prof.Key)
		if perr != nil {
			return fmt.Errorf("invalid key in profile: %w", perr)
		}
	}

	fmt.Println(mk.Hex())
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
