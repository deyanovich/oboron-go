// Package cliutil holds the shared CLI conformance plumbing for the ob and obu
// binaries (oboron CLI.md and OBU.md §6): the --version line, strict stdin/
// stdout framing, the usage-vs-operation exit-code split, flag-conflict
// detection, and the uniform dec error. Keeping it in one place ensures the two
// CLIs stay byte-for-byte consistent on the contract.
package cliutil

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/urfave/cli/v2"
)

// DecFailureMsg is the single uniform stderr message for every dec failure
// (CLI.md §8): a non-canonical encoding, a bad scheme-output length, an
// authentication failure, invalid UTF-8, or an empty plaintext all report this
// exact line, so dec does not become a distinguishing oracle.
const DecFailureMsg = "dec: invalid obtext"

// Usage builds an exit-status-2 usage error (CLI.md §8): invalid or conflicting
// flags, a malformed format identifier, an unknown command, or a wrong argument
// count.
func Usage(format string, a ...any) error {
	return cli.Exit("error: "+fmt.Sprintf(format, a...), 2)
}

// Fail builds an exit-status-1 operation failure (CLI.md §8) carrying msg.
func Fail(format string, a ...any) error {
	return cli.Exit(fmt.Sprintf(format, a...), 1)
}

// DecFail returns the uniform exit-status-1 dec failure.
func DecFail() error { return cli.Exit(DecFailureMsg, 1) }

// VersionToken strips a leading "v" from the in-code version so the --version
// line emits a bare semver token ("1.0.0"), matching the spec example and the
// Rust reference rather than the git-tag form ("v1.0.0").
func VersionToken(v string) string { return strings.TrimPrefix(v, "v") }

// HandleVersionRequest prints line and exits 0 if argv requests --version or -V
// before the "--" end-of-options marker. This makes the global version option
// work in any position (before or after the command name) without needing a key
// or stdin (CLI.md §3, §4.1).
func HandleVersionRequest(args []string, line string) {
	for _, a := range args[1:] {
		if a == "--" {
			return
		}
		if a == "--version" || a == "-V" {
			fmt.Println(line)
			os.Exit(0)
		}
	}
}

// FlagGiven reports whether the flag named long (with optional single-letter
// short) is explicitly supplied on the command line before the "--" marker, in
// any of its forms: "--long", "--long=value", "-s", "-svalue", or grouped
// "-xs". It detects an explicitly-supplied flag for mutual-exclusion checks,
// independent of an env-var default that urfave folds into the same Context
// value (which is why it scans argv rather than reading the Context). Pass an
// empty short to match the long form only.
func FlagGiven(args []string, long, short string) bool {
	for _, a := range args[1:] {
		if a == "--" {
			return false
		}
		if a == "--"+long || strings.HasPrefix(a, "--"+long+"=") {
			return true
		}
		// Short form: a single-dash group like "-s", "-svalue", or "-xs".
		if short != "" && len(a) > 1 && a[0] == '-' && a[1] != '-' {
			grp := a[1:]
			if i := strings.IndexByte(grp, '='); i >= 0 {
				grp = grp[:i]
			}
			if strings.IndexByte(grp, short[0]) >= 0 {
				return true
			}
		}
	}
	return false
}

// CountSet returns how many of the named bool flags are set on c.
func CountSet(c *cli.Context, names ...string) int {
	n := 0
	for _, name := range names {
		if c.Bool(name) {
			n++
		}
	}
	return n
}

// ReadInput returns the [TEXT] for enc/dec. A single positional argument is used
// verbatim (stdin is not read, no newline is stripped). Otherwise all of stdin
// is read; in default mode exactly one trailing line ending is removed (a
// two-byte \r\n, else a single \n, else nothing), and in raw mode nothing is
// stripped (CLI.md §7).
func ReadInput(c *cli.Context, raw bool) (string, error) {
	if c.NArg() >= 1 {
		return c.Args().First(), nil
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", err
	}
	s := string(data)
	if raw {
		return s, nil
	}
	switch {
	case strings.HasSuffix(s, "\r\n"):
		return s[:len(s)-2], nil
	case strings.HasSuffix(s, "\n"):
		return s[:len(s)-1], nil
	default:
		return s, nil
	}
}

// Output writes s to stdout, followed by a single newline unless raw (CLI.md §7).
func Output(s string, raw bool) {
	if raw {
		fmt.Print(s)
	} else {
		fmt.Println(s)
	}
}

// Run wires an App to the conformance exit-code contract and runs it: usage and
// flag-parse errors exit 2, operation failures exit 1, success exits 0, and
// diagnostics go to stderr with no log prefix. It returns the process exit code.
func Run(app *cli.App, args []string) int {
	// Take over exit handling so urfave never calls os.Exit itself; we map
	// every error to a status code below.
	app.ExitErrHandler = func(*cli.Context, error) {}
	// Suppress urfave's default help-to-stdout on a flag error and turn it into
	// a status-2 usage error.
	onUsage := func(_ *cli.Context, err error, _ bool) error {
		return Usage("%v", err)
	}
	app.OnUsageError = onUsage
	propagateUsageHandler(app.Commands, onUsage)
	app.CommandNotFound = func(_ *cli.Context, name string) {
		fmt.Fprintf(os.Stderr, "error: unknown command %q\n", name)
		os.Exit(2)
	}

	err := app.Run(args)
	if err == nil {
		return 0
	}
	if ec, ok := err.(cli.ExitCoder); ok {
		if msg := ec.Error(); msg != "" {
			fmt.Fprintln(os.Stderr, msg)
		}
		return ec.ExitCode()
	}
	// A plain (non-ExitCoder) error escaping an action is an operation failure.
	fmt.Fprintln(os.Stderr, err)
	return 1
}

// propagateUsageHandler installs onUsage on every command and subcommand so a
// flag error at any level becomes a status-2 usage error instead of urfave's
// default help-to-stdout.
func propagateUsageHandler(cmds []*cli.Command, onUsage cli.OnUsageErrorFunc) {
	for _, cmd := range cmds {
		cmd.OnUsageError = onUsage
		propagateUsageHandler(cmd.Subcommands, onUsage)
	}
}
