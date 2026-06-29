package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// runCode runs the ob binary and returns stdout, stderr, and the exit code.
// extraEnv entries (e.g. "OBORON_KEY=") are appended after a clean HOME so key
// resolution is deterministic; stdin supplies bytes when args omit a positional.
func runCode(t *testing.T, binary, home, stdin string, extraEnv []string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Env = append(append(os.Environ(), "HOME="+home), extraEnv...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run %v: %v", args, err)
		}
		code = ee.ExitCode()
	}
	return out.String(), errb.String(), code
}

// TestObExitCodes pins the CLI.md §8 status contract: usage errors → 2,
// operation failures → 1, success → 0.
func TestObExitCodes(t *testing.T) {
	bin := obBinary(t)
	home := testHomeDir(t)

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"enc ok", []string{"enc", "-K", "hi"}, 0},
		{"version global", []string{"--version"}, 0},
		{"version after command", []string{"enc", "--version"}, 0},
		{"version short -V", []string{"-V"}, 0},
		{"help", []string{"--help"}, 0},
		{"keygen", []string{"keygen"}, 0},
		{"unknown command", []string{"bogus"}, 2},
		{"unknown flag", []string{"enc", "--nope", "hi"}, 2},
		{"two scheme flags", []string{"enc", "-K", "-s", "-S", "hi"}, 2},
		{"two encoding flags", []string{"enc", "-K", "-c", "-b", "hi"}, 2},
		{"format plus scheme", []string{"enc", "-K", "-f", "dsiv.c32", "-s", "hi"}, 2},
		{"key plus keyless", []string{"enc", "-K", "-k", testKeyHex, "hi"}, 2},
		{"two positionals", []string{"enc", "-K", "foo", "bar"}, 2},
		{"uppercase format", []string{"enc", "-K", "-f", "DSIV.c32", "hi"}, 2},
		{"unknown scheme format", []string{"enc", "-K", "-f", "bogus.c32", "hi"}, 2},
		{"bad obtext", []string{"dec", "-K", "-f", "dsiv.c32", "GARBAGE!!!"}, 1},
		{"invalid key", []string{"enc", "-k", "AAAA", "hi"}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, _, code := runCode(t, bin, home, "", nil, tc.args...)
			if code != tc.want {
				t.Errorf("exit code = %d, want %d", code, tc.want)
			}
			if tc.want != 0 && stdout != "" {
				t.Errorf("failure wrote to stdout: %q", stdout)
			}
		})
	}
}

// TestObNoKeyAndEmptyEnv: a missing key source is exit 1, and an explicitly
// empty $OBORON_KEY is an invalid key (not absent), also exit 1 (CLI.md §6).
func TestObNoKeyAndEmptyEnv(t *testing.T) {
	bin := obBinary(t)
	home := testHomeDir(t)
	if _, _, code := runCode(t, bin, home, "", nil, "enc", "hi"); code != 1 {
		t.Errorf("no key source: exit %d, want 1", code)
	}
	if _, _, code := runCode(t, bin, home, "", []string{"OBORON_KEY="}, "enc", "hi"); code != 1 {
		t.Errorf("empty OBORON_KEY: exit %d, want 1", code)
	}
}

// TestObUniformDecError: every dec failure shares one stderr message and exits
// 1, so dec is not a distinguishing oracle (CLI.md §8).
func TestObUniformDecError(t *testing.T) {
	bin := obBinary(t)
	home := testHomeDir(t)
	inputs := []string{
		"37MM8KRVH8XK1G1RXYZXX3KB4JD7PRSA24", // non-canonical c32 (uppercase)
		"37mm8krvh8xk1g1rxyzxx3kb4jd7prsa20", // authentication failure
		"000000000000000000000000000000",     // too short
	}
	var msg string
	for i, in := range inputs {
		_, stderr, code := runCode(t, bin, home, "", nil, "dec", "-K", "-f", "dsiv.c32", "--", in)
		if code != 1 {
			t.Errorf("input %d: exit %d, want 1", i, code)
		}
		stderr = strings.TrimRight(stderr, "\n")
		if i == 0 {
			msg = stderr
		} else if stderr != msg {
			t.Errorf("dec error message differs (oracle): %q vs %q", stderr, msg)
		}
	}
}

// TestObRawFraming: --raw preserves bytes exactly with no added/stripped
// newline, so the enc|dec pipeline round-trips embedded and trailing newlines
// (CLI.md §7).
func TestObRawFraming(t *testing.T) {
	bin := obBinary(t)
	home := testHomeDir(t)
	plaintext := "line1\nline2\n"
	ot, _, code := runCode(t, bin, home, plaintext, nil, "enc", "-K", "--raw", "-f", "dsiv.b64")
	if code != 0 {
		t.Fatalf("enc --raw exit %d", code)
	}
	pt, _, code := runCode(t, bin, home, ot, nil, "dec", "-K", "--raw", "-f", "dsiv.b64")
	if code != 0 {
		t.Fatalf("dec --raw exit %d", code)
	}
	if pt != plaintext {
		t.Errorf("raw round-trip = %q, want %q", pt, plaintext)
	}
}

// TestObStdinNewlineStrip: default mode strips exactly one trailing line ending.
func TestObStdinNewlineStrip(t *testing.T) {
	bin := obBinary(t)
	home := testHomeDir(t)
	// "hi\n\n" must keep one trailing newline; differs from "hi".
	a, _, _ := runCode(t, bin, home, "hi\n\n", nil, "enc", "-K", "-f", "dsiv.c32")
	b, _, _ := runCode(t, bin, home, "hi", nil, "enc", "-K", "-f", "dsiv.c32")
	if strings.TrimSpace(a) == strings.TrimSpace(b) {
		t.Errorf("stdin \"hi\\n\\n\" and \"hi\" produced the same obtext; one trailing newline not preserved")
	}
}

// TestObVersionLine checks the exact --version line shape (CLI.md §3): five
// whitespace-free tokens, a bare-semver version (no leading "v"), and the
// protocol/cli fields.
func TestObVersionLine(t *testing.T) {
	bin := obBinary(t)
	home := testHomeDir(t)
	out, _, code := runCode(t, bin, home, "", nil, "--version")
	if code != 0 {
		t.Fatalf("--version exit %d", code)
	}
	line := strings.TrimRight(out, "\n")
	fields := strings.Fields(line)
	if len(fields) != 5 {
		t.Fatalf("--version line %q has %d fields, want 5", line, len(fields))
	}
	if fields[0] != "ob" || fields[1] != "oboron-go" {
		t.Errorf("prefix = %q %q, want ob oboron-go", fields[0], fields[1])
	}
	if strings.HasPrefix(fields[2], "v") {
		t.Errorf("version token %q has a leading v", fields[2])
	}
	if fields[3] != "protocol=1.0" || fields[4] != "cli=1.0" {
		t.Errorf("tail = %q %q, want protocol=1.0 cli=1.0", fields[3], fields[4])
	}
}
