package cmd

import (
	"bytes"
	"github.com/IORDACHE00/vaultd/internal/store"
	"os"
	"testing"
)

func TestGetAndSet(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if err := store.Initialize("pw"); err != nil {
		t.Fatal(err)
	}

	if err := store.Update("pw", "app", "KEY", "old"); err != nil {
		t.Fatal(err)
	}

	if err := store.Update("pw", "app", "OTHER", "keep"); err != nil {
		t.Fatal(err)
	}

	original, originalSecret := readPassword, readSecretValue
	secret := ""
	readSecretValue = func() ([]byte, error) { return []byte(secret), nil }
	defer func() {
		readPassword = original
		readSecretValue = originalSecret
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
	}()
	password := "pw"
	readPassword = func(string) (string, error) { return password, nil }
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	run := func(args ...string) error {
		t.Helper()
		out.Reset()
		rootCmd.SetArgs(args)
		return rootCmd.Execute()
	}

	if err := run("get", "app", "KEY"); err != nil || out.String() != "old\n" {
		t.Fatalf("get: %q %v", out.String(), err)
	}

	value := "new=with 'quotes'\nand $(literal)"
	secret = value

	if err := run("set", "app", "KEY"); err != nil {
		t.Fatal(err)
	}

	if err := run("get", "app", "KEY"); err != nil || out.String() != value+"\n" {
		t.Fatalf("updated get: %q %v", out.String(), err)
	}

	secret = ""

	if err := run("set", "app", "KEY"); err != nil {
		t.Fatal(err)
	}

	if err := run("get", "app", "KEY"); err != nil || out.String() != "\n" {
		t.Fatalf("empty value: %q %v", out.String(), err)
	}

	before, err := os.ReadFile(store.GetVaultFilePath())

	if err != nil {
		t.Fatal(err)
	}

	for _, args := range [][]string{
		{"get", "missing", "KEY"}, {"get", "app", "MISSING"},
		{"get", "app", "BAD-KEY"}, {"set", "app", "BAD-KEY"},
		{"set", "app", "KEY=leaky"}, {"get", "app"}, {"set"}, {"get"},
	} {
		if err := run(args...); err == nil {
			t.Fatalf("accepted %v", args)
		}
		if out.Len() != 0 {
			t.Fatalf("failed command emitted output: %q", out.String())
		}
	}

	password = "wrong"

	for _, args := range [][]string{{"get", "app", "KEY"}, {"set", "app", "KEY"}} {
		if err := run(args...); err == nil {
			t.Fatalf("wrong password accepted: %v", args)
		}
		if out.Len() != 0 {
			t.Fatal("failed command emitted output")
		}
	}

	after, err := os.ReadFile(store.GetVaultFilePath())

	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(before, after) {
		t.Fatal("failed commands changed vault")
	}

	s, err := store.Load("pw")

	if err != nil || s["app"]["OTHER"] != "keep" {
		t.Fatalf("unrelated key changed: %v %v", s, err)
	}
}
