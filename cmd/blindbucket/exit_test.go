package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExitCodes pins the exit codes ADR-021 promises: 0 on success, 2 for a
// usage mistake, 1 for anything that went wrong. Scripts branch on these, which
// is why they are a stable interface rather than a detail.
func TestExitCodes(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	for name, tc := range map[string]struct {
		args   []string
		want   int
		stderr string
	}{
		"success":            {[]string{"version"}, 0, ""},
		"no command":         {nil, 2, "Usage:"},
		"a flag's own -h":    {[]string{"keygen", "-h"}, 2, "Usage: blindbucket keygen"},
		"an unknown command": {[]string{"frobnicate"}, 1, "blindbucket: unknown command"},
		"a failed command": {[]string{"decrypt", "--keyring", keyring, "-i",
			filepath.Join(t.TempDir(), "absent"), "-o", "-"}, 1, "blindbucket: "},
	} {
		t.Run(name, func(t *testing.T) {
			saved := os.Args
			t.Cleanup(func() { os.Args = saved })
			os.Args = append([]string{"blindbucket"}, tc.args...)

			var code int
			stderr := captureStderr(t, func() {
				captureStdout(t, func() { code = mainCode() })
			})
			if code != tc.want {
				t.Errorf("exit code %d, want %d\n%s", code, tc.want, stderr)
			}
			if !strings.Contains(stderr, tc.stderr) {
				t.Errorf("stderr lacks %q:\n%s", tc.stderr, stderr)
			}
		})
	}
}

func TestPassphraseSources(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	dir := t.TempDir()
	keysList := func(extra ...string) error {
		_, _, err := runCLI(t, append([]string{"keys", "list", "--keyring", keyring}, extra...)...)
		return err
	}

	t.Run("a passphrase file", func(t *testing.T) {
		t.Setenv(passphraseEnv, "")
		file := filepath.Join(dir, "pass")
		// A trailing newline is how most editors and `echo` leave the file.
		if err := os.WriteFile(file, []byte(testPassphrase+"\n"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := keysList("--passphrase-file", file); err != nil {
			t.Errorf("the passphrase file did not open the keyring: %v", err)
		}
	})

	t.Run("an empty passphrase file", func(t *testing.T) {
		t.Setenv(passphraseEnv, "")
		file := filepath.Join(dir, "empty")
		if err := os.WriteFile(file, []byte("\n"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := keysList("--passphrase-file", file); err == nil || !strings.Contains(err.Error(), "is empty") {
			t.Errorf("got %v, want the empty file named", err)
		}
	})

	t.Run("a passphrase file that is missing", func(t *testing.T) {
		t.Setenv(passphraseEnv, "")
		err := keysList("--passphrase-file", filepath.Join(dir, "absent"))
		if err == nil || !strings.Contains(err.Error(), "reading the passphrase file") {
			t.Errorf("got %v", err)
		}
	})

	t.Run("no source at all, and no terminal", func(t *testing.T) {
		t.Setenv(passphraseEnv, "")
		// Under `go test` stdin is not a terminal, so there is no one to ask.
		if err := keysList(); err == nil || !strings.Contains(err.Error(), "no passphrase available") {
			t.Errorf("got %v, want the three ways to supply one", err)
		}
	})

	t.Run("the wrong passphrase", func(t *testing.T) {
		t.Setenv(passphraseEnv, "not the passphrase")
		if err := keysList(); err == nil {
			t.Error("the keyring opened under the wrong passphrase")
		}
	})
}
