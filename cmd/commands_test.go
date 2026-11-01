package cmd

import (
	"bytes"
	"github.com/IORDACHE00/vaultd/internal/store"
	"os"
	"testing"
)

func TestCommands(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	const pw = "test master password with sufficient length"
	original, originalSecret := readPassword, readSecretValue
	readSecretValue = func() ([]byte, error) { return []byte("one=two"), nil }
	defer func() {
		readPassword = original
		readSecretValue = originalSecret
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
	}()
	passwords := []string{}
	readPassword = func(string) (string, error) {
		if len(passwords) == 0 {
			t.Fatal("unexpected password prompt")
		}

		p := passwords[0]
		passwords = passwords[1:]
		return p, nil
	}
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	run := func(args ...string) error { t.Helper(); out.Reset(); rootCmd.SetArgs(args); return rootCmd.Execute() }
	passwords = []string{pw, "different"}

	if err := run("init"); err == nil {
		t.Fatal("confirmation mismatch accepted")
	}

	if _, err := os.Stat(store.GetVaultFilePath()); !os.IsNotExist(err) {
		t.Fatal("mismatch created vault")
	}

	passwords = []string{pw, pw}

	if err := run("init"); err != nil {
		t.Fatal(err)
	}

	passwords = []string{"other long master password", "other long master password"}

	if err := run("init"); err == nil {
		t.Fatal("reinit succeeded")
	}

	passwords = []string{pw}

	if err := run("set", "app", "KEY"); err != nil {
		t.Fatal(err)
	}

	if err := run("set", "app", "BAD-KEY"); err == nil {
		t.Fatal("bad key accepted")
	}

	passwords = []string{"wrong"}

	if err := run("set", "app", "KEY"); err == nil {
		t.Fatal("wrong password accepted")
	}

	secrets, err := loadApp(pw, "app")

	if err != nil || secrets["KEY"] != "one=two" {
		t.Fatalf("load: %v %v", secrets, err)
	}

	if err := store.Update(pw, "app", "KEY", "fresh"); err != nil {
		t.Fatal(err)
	}

	secrets, err = loadApp(pw, "app")

	if err != nil || secrets["KEY"] != "fresh" {
		t.Fatalf("stale secrets: %v %v", secrets, err)
	}

	if _, err := loadApp(pw, "missing"); err == nil {
		t.Fatal("missing profile accepted")
	}

	for _, name := range []string{"modify", "activate", "deactivate", "shell-init"} {
		if err := run(name); err == nil {
			t.Fatalf("removed command %q still available", name)
		}
	}
}
