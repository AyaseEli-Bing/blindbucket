package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LennardGeissler/blindbucket/internal/config"
)

// stripKeys removes optional keys from a keyring file, leaving it in the shape
// a release from before those keys existed wrote.
func stripKeys(t *testing.T, path string, fields ...string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, f := range fields {
		if _, ok := doc[f]; !ok {
			t.Fatalf("the keyring has no %q to strip", f)
		}
		delete(doc, f)
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// runCLI runs a command with stdout and stderr captured.
func runCLI(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	stderr = captureStderr(t, func() {
		stdout = captureStdout(t, func() { err = run(t.Context(), args) })
	})
	return stdout, stderr, err
}

func encryptFile(t *testing.T, keyring string, plain []byte) string {
	t.Helper()
	dir := t.TempDir()
	in, out := filepath.Join(dir, "plain"), filepath.Join(dir, "cipher.bb")
	if err := os.WriteFile(in, plain, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := runCLI(t, "encrypt", "--keyring", keyring, "-i", in, "-o", out); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return out
}

func decryptFile(t *testing.T, keyring, cipher string) ([]byte, error) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "back")
	if _, _, err := runCLI(t, "decrypt", "--keyring", keyring, "-i", cipher, "-o", out); err != nil {
		return nil, err
	}
	return os.ReadFile(out)
}

// TestKeygenAddsKeysToAnOlderKeyring covers the upgrade path the gateway's own
// error messages point at: a keyring from before a feature, given the key that
// feature needs, without disturbing the keys it already had.
func TestKeygenAddsKeysToAnOlderKeyring(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	plain := []byte("written before the upgrade")
	cipher := encryptFile(t, keyring, plain)
	stripKeys(t, keyring, "audit_key", "name_key", "freshness_key")

	stdout, stderr, err := runCLI(t, "keygen", "--out", keyring,
		"--add-audit-key", "--add-name-key", "--add-freshness-key")
	if err != nil {
		t.Fatalf("keygen --add-*-key: %v\n%s", err, stderr)
	}
	for _, want := range []string{"added an audit key", "added an object-name key", "added a rollback-index key"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr does not report %q:\n%s", want, stderr)
		}
	}
	// The public key is printed at once, to stderr beside the other notices, so
	// it can be recorded; and it is the one the keyring now holds.
	if !strings.Contains(stderr, "audit log public key: "+auditPubkey(t, keyring)) {
		t.Errorf("the new audit key was not printed:\n%s", stderr)
	}
	if stdout != "" {
		t.Errorf("keygen wrote to stdout: %q", stdout)
	}

	ring, err := openKeyring(t.Context(), keyring, config.Keys{Provider: "file"}, &passphraseFlags{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, ok := ring.NameKey(); !ok {
		t.Error("no name key after --add-name-key")
	}
	if _, ok := ring.FreshnessKey(); !ok {
		t.Error("no freshness key after --add-freshness-key")
	}
	back, err := decryptFile(t, keyring, cipher)
	if err != nil || !bytes.Equal(back, plain) {
		t.Errorf("an object written before the upgrade no longer decrypts: %v", err)
	}
}

// TestKeygenRefusesToReplaceAKey: each of these keys is what makes existing data
// findable or verifiable, and nothing records the old one once it is replaced.
func TestKeygenRefusesToReplaceAKey(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	before, err := os.ReadFile(keyring)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	for flag, want := range map[string]string{
		"--add-audit-key":     "already has an audit key",
		"--add-name-key":      "already has a name key",
		"--add-freshness-key": "already has a freshness key",
	} {
		t.Run(flag, func(t *testing.T) {
			_, _, err := runCLI(t, "keygen", "--out", keyring, flag)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("got %v, want a refusal mentioning %q", err, want)
			}
		})
	}
	after, err := os.ReadFile(keyring)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("a refused keygen changed the keyring")
	}
}

// TestKeygenAddEndToEnd complements TestKeygenAddRotatesTheActiveKey through the
// commands alone: what the old key wrapped still decrypts, `keys list` reports
// the new key as active, a duplicate id is refused, and --activate=false adds
// a key without switching to it.
func TestKeygenAddEndToEnd(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	plain := make([]byte, 70_000)
	if _, err := rand.Read(plain); err != nil {
		t.Fatalf("rand: %v", err)
	}
	old := encryptFile(t, keyring, plain)

	if _, stderr, err := runCLI(t, "keygen", "--out", keyring, "--kid", "2026-10", "--add"); err != nil {
		t.Fatalf("keygen --add: %v\n%s", err, stderr)
	}
	stdout, _, err := runCLI(t, "keys", "list", "--keyring", keyring, "--json")
	if err != nil {
		t.Fatalf("keys list: %v", err)
	}
	var listed struct {
		Keys []struct {
			KID    string `json:"kid"`
			Active bool   `json:"active"`
		} `json:"keys"`
	}
	if err := json.Unmarshal([]byte(stdout), &listed); err != nil {
		t.Fatalf("keys list --json: %v\n%s", err, stdout)
	}
	active := ""
	for _, k := range listed.Keys {
		if k.Active {
			active = k.KID
		}
	}
	if active != "2026-10" {
		t.Errorf("active key is %q after --add, want 2026-10", active)
	}

	if back, err := decryptFile(t, keyring, old); err != nil || !bytes.Equal(back, plain) {
		t.Errorf("an object under the old key no longer decrypts: %v", err)
	}

	t.Run("a kid that exists", func(t *testing.T) {
		if _, _, err := runCLI(t, "keygen", "--out", keyring, "--kid", "2026-10", "--add"); err == nil {
			t.Error("keygen --add accepted a key id already in the keyring")
		}
	})
	t.Run("--activate=false keeps the active key", func(t *testing.T) {
		if _, _, err := runCLI(t, "keygen", "--out", keyring, "--kid", "2026-11", "--add",
			"--activate=false"); err != nil {
			t.Fatalf("keygen: %v", err)
		}
		stdout, _, _ := runCLI(t, "keys", "list", "--keyring", keyring, "--json")
		if !strings.Contains(stdout, "2026-11") {
			t.Fatalf("2026-11 was not added:\n%s", stdout)
		}
		if err := json.Unmarshal([]byte(stdout), &listed); err != nil {
			t.Fatalf("parse: %v", err)
		}
		for _, k := range listed.Keys {
			if k.KID == "2026-11" && k.Active {
				t.Error("--activate=false activated the new key")
			}
		}
	})
}

// TestKeysRemoveEndToEnd complements TestKeysRemoveNeedsForceAndRetires: an
// object wrapped under the removed key really is unreadable afterwards, and the
// ways of naming the wrong key are refused.
func TestKeysRemoveEndToEnd(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	old := encryptFile(t, keyring, []byte("wrapped under the key being retired"))
	if _, _, err := runCLI(t, "keygen", "--out", keyring, "--kid", "2026-10", "--add"); err != nil {
		t.Fatalf("keygen --add: %v", err)
	}

	if _, _, err := runCLI(t, "keys", "remove", "--keyring", keyring, "2026-09"); err == nil ||
		!strings.Contains(err.Error(), "without --force") {
		t.Fatalf("keys remove ran without --force: %v", err)
	}
	if _, err := decryptFile(t, keyring, old); err != nil {
		t.Fatalf("a refused remove took the key anyway: %v", err)
	}

	if _, _, err := runCLI(t, "keys", "remove", "--keyring", keyring, "--force", "2026-09"); err != nil {
		t.Fatalf("keys remove --force: %v", err)
	}
	if _, err := decryptFile(t, keyring, old); err == nil {
		t.Error("an object under a removed key still decrypts")
	}

	for name, args := range map[string][]string{
		"an unknown key":     {"keys", "remove", "--keyring", keyring, "--force", "no-such-key"},
		"the active key":     {"keys", "remove", "--keyring", keyring, "--force", "2026-10"},
		"no key id":          {"keys", "remove", "--keyring", keyring, "--force"},
		"no keyring":         {"keys", "remove", "--force", "2026-10"},
		"an unknown command": {"keys", "shred"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := runCLI(t, args...); err == nil {
				t.Error("accepted")
			}
		})
	}
}

// TestServeRefusesToInventMissingKeys: a gateway that generated a missing key at
// start-up would sign logs nobody can verify, or store objects where nobody can
// find them after the next restart. Each is a start-up error naming the fix.
func TestServeRefusesToInventMissingKeys(t *testing.T) {
	provider, _ := stubProvider(t)
	for name, tc := range map[string]struct {
		strip, section, want string
	}{
		"audit":     {"audit_key", `audit: { log: "%s/audit.log" }`, "--add-audit-key"},
		"names":     {"name_key", `names: { encrypt: true }`, "--add-name-key"},
		"freshness": {"freshness_key", `freshness: { index: "%s/fresh.idx" }`, "--add-freshness-key"},
	} {
		t.Run(name, func(t *testing.T) {
			keyring := setupKeyring(t, "2026-09")
			stripKeys(t, keyring, tc.strip)
			section := tc.section
			if strings.Contains(section, "%s") {
				section = fmt.Sprintf(section, t.TempDir())
			}
			cfg := fmt.Sprintf(`
server: { listen: %q }
admin: { listen: "" }
upstream: { endpoint: %q, region: us-east-1, path_style: true, access_key_id: u, secret_access_key: s }
keys: { provider: file, keyring: %q }
clients:
  - { name: t, access_key_id: T, secret_access_key: s, buckets: ["*"] }
%s
`, freeAddr(t), provider.URL, keyring, section)
			path := filepath.Join(t.TempDir(), "blindbucket.yaml")
			if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			_, _, err := runCLI(t, "serve", "--config", path)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got %v, want a refusal naming %s", err, tc.want)
			}
		})
	}

	t.Run("the audit CLI says the same", func(t *testing.T) {
		keyring := setupKeyring(t, "2026-09")
		stripKeys(t, keyring, "audit_key")
		for _, args := range [][]string{
			{"audit", "pubkey", "--keyring", keyring},
			{"audit", "verify", "--keyring", keyring, keyring},
		} {
			if _, _, err := runCLI(t, args...); err == nil || !strings.Contains(err.Error(), "--add-audit-key") {
				t.Errorf("%v: got %v, want the command that adds the key", args, err)
			}
		}
	})
}

func TestEncryptAndDecryptOverPipes(t *testing.T) {
	keyring := setupKeyring(t, "2026-09")
	dir := t.TempDir()
	plain := []byte("through stdin and stdout")
	in := filepath.Join(dir, "plain")
	if err := os.WriteFile(in, plain, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	// "-" is stdout; captured, it is a pipe rather than a terminal.
	cipher, _, err := runCLI(t, "encrypt", "--keyring", keyring, "-i", in, "-o", "-")
	if err != nil {
		t.Fatalf("encrypt to stdout: %v", err)
	}
	cipherPath := filepath.Join(dir, "cipher.bb")
	if err := os.WriteFile(cipherPath, []byte(cipher), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	back, _, err := runCLI(t, "decrypt", "--keyring", keyring, "-i", cipherPath, "-o", "-")
	if err != nil || back != string(plain) {
		t.Fatalf("decrypt to stdout: %q, %v", back, err)
	}

	out := filepath.Join(dir, "out")

	// A device is written to directly rather than through a rename.
	if _, _, err := runCLI(t, "encrypt", "--keyring", keyring, "-i", in, "-o", os.DevNull); err != nil {
		t.Errorf("encrypt to %s: %v", os.DevNull, err)
	}

	for name, args := range map[string][]string{
		"a missing input":         {"encrypt", "--keyring", keyring, "-i", filepath.Join(dir, "absent"), "-o", out},
		"an unwritable output":    {"encrypt", "--keyring", keyring, "-i", in, "-o", filepath.Join(dir, "no", "such", "dir")},
		"no keyring":              {"encrypt", "-i", in, "-o", out},
		"decrypt with no keyring": {"decrypt", "-i", cipherPath, "-o", out},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := runCLI(t, args...); err == nil {
				t.Error("accepted")
			}
		})
	}
}
