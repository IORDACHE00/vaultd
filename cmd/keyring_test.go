package cmd

import (
	"bytes"
	"errors"
	"github.com/IORDACHE00/vaultd/internal/credentials"
	"github.com/IORDACHE00/vaultd/internal/store"
	"testing"
)

type commandKeyring struct {
	password    string
	unavailable bool
}

func (f *commandKeyring) Set(_, _, p string) error { f.password = p; return nil }
func (f *commandKeyring) Get(_, _ string) (string, error) {
	if f.unavailable {
		return "", errors.New("provider locked")
	}

	return f.password, nil
}
func (f *commandKeyring) Delete(_, _ string) error { f.password = ""; return nil }

func TestKeyringCommandsAndPasswordOverride(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if err := store.Initialize("pw"); err != nil {
		t.Fatal(err)
	}

	originalManager, originalReader, originalSecret := keyringManager, readPassword, readSecretValue
	readSecretValue = func() ([]byte, error) { return []byte("value"), nil }
	backend := &commandKeyring{}
	keyringManager = credentials.Manager{Backend: backend}
	prompts := 0
	readPassword = func(string) (string, error) { prompts++; return "pw", nil }
	manualFlag := rootCmd.PersistentFlags().Lookup("password")
	originalValue, originalChanged := manualFlag.Value.String(), manualFlag.Changed
	defer func() {
		keyringManager, readPassword, readSecretValue = originalManager, originalReader, originalSecret
		_ = manualFlag.Value.Set(originalValue)
		manualFlag.Changed = originalChanged
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	}()
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	run := func(args ...string) error {
		t.Helper()
		_ = manualFlag.Value.Set("false")
		manualFlag.Changed = false
		out.Reset()
		rootCmd.SetArgs(args)
		return rootCmd.Execute()
	}

	if err := run("keyring", "status"); err != nil || prompts != 0 {
		t.Fatal("status prompted or failed")
	}

	if err := run("keyring", "enable"); err != nil || prompts != 1 {
		t.Fatalf("enable: %v prompts=%d", err, prompts)
	}

	if err := run("set", "app", "KEY"); err != nil || prompts != 1 {
		t.Fatalf("set did not use keyring: %v", err)
	}

	if err := run("get", "app", "KEY"); err != nil || out.String() != "value\n" || prompts != 1 {
		t.Fatalf("get: %q %v", out.String(), err)
	}

	backend.unavailable = true

	if err := run("get", "app", "KEY"); err == nil || prompts != 1 || out.Len() != 0 {
		t.Fatal("keyring error silently prompted or leaked output")
	}

	if err := run("--password", "get", "app", "KEY"); err != nil || out.String() != "value\n" || prompts != 2 {
		t.Fatalf("manual bypass: %q %v", out.String(), err)
	}

	backend.unavailable = false

	if err := run("keyring", "disable"); err != nil || backend.password != "" {
		t.Fatalf("disable: %v", err)
	}

	if err := run("get", "app", "KEY"); err != nil || prompts != 3 {
		t.Fatalf("manual default not restored: %v", err)
	}
}
