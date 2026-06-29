package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

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

// TestObuExitCodes pins the status contract for the obu CLI, including the
// OBU.md §6 rule that --secret has no single-letter -s alias.
func TestObuExitCodes(t *testing.T) {
	bin := obuBinary(t)
	home := testHomeDir(t)

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"enc ok", []string{"enc", "-K", "hi"}, 0},
		{"secret long form", []string{"enc", "--secret", testSecret, "hi"}, 0},
		{"version after command", []string{"enc", "--version"}, 0},
		{"version short -V", []string{"-V"}, 0},
		{"secretgen", []string{"secretgen"}, 0},
		{"-s is not a secret alias", []string{"enc", "-s", testSecret, "hi"}, 2},
		{"two scheme flags", []string{"enc", "-K", "-u", "-z", "hi"}, 2},
		{"two encoding flags", []string{"enc", "-K", "-c", "-b", "hi"}, 2},
		{"format plus scheme", []string{"enc", "-K", "-f", "upcbc.c32", "-u", "hi"}, 2},
		{"secret plus keyless", []string{"enc", "-K", "--secret", testSecret, "hi"}, 2},
		{"two positionals", []string{"enc", "-K", "foo", "bar"}, 2},
		{"core scheme rejected", []string{"enc", "-K", "-f", "dsiv.c32", "hi"}, 2},
		{"bad obtext", []string{"dec", "-K", "-f", "zdcbc.hex", "ZZZZ"}, 1},
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

// TestObuEmptyEnvSecret: an explicitly empty $OBORON_SECRET is invalid, not
// absent (OBU.md §6.1).
func TestObuEmptyEnvSecret(t *testing.T) {
	bin := obuBinary(t)
	home := testHomeDir(t)
	if _, _, code := runCode(t, bin, home, "", []string{"OBORON_SECRET="}, "enc", "hi"); code != 1 {
		t.Errorf("empty OBORON_SECRET: exit %d, want 1", code)
	}
}

// TestObuVersionLine checks the --version shape (OBU.md §6).
func TestObuVersionLine(t *testing.T) {
	bin := obuBinary(t)
	home := testHomeDir(t)
	out, _, code := runCode(t, bin, home, "", nil, "--version")
	if code != 0 {
		t.Fatalf("--version exit %d", code)
	}
	fields := strings.Fields(strings.TrimRight(out, "\n"))
	if len(fields) != 5 || fields[0] != "obu" || fields[1] != "oboron-go" ||
		strings.HasPrefix(fields[2], "v") || fields[3] != "protocol=1.0" || fields[4] != "cli=1.0" {
		t.Errorf("unexpected --version line: %q", out)
	}
}

// TestObuSecretgenFormat: 64 lowercase hex + one trailing newline, exit 0.
func TestObuSecretgenFormat(t *testing.T) {
	bin := obuBinary(t)
	home := testHomeDir(t)
	out, _, code := runCode(t, bin, home, "", nil, "secretgen")
	if code != 0 {
		t.Fatalf("secretgen exit %d", code)
	}
	if len(out) != 65 || out[64] != '\n' {
		t.Fatalf("secretgen output length = %d, want 65 (64 hex + newline)", len(out))
	}
	for _, c := range out[:64] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("secretgen output has non-lowercase-hex char %q", string(c))
		}
	}
}
