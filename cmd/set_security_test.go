package cmd

import (
	"bytes"
	"github.com/IORDACHE00/vaultd/internal/limits"
	"github.com/IORDACHE00/vaultd/internal/store"
	"strings"
	"testing"
)

func TestPrivateSetInput(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if err := store.Initialize("pw"); err != nil {
		t.Fatal(err)
	}

	oldReader, oldSecret := readPassword, readSecretValue
	flag := setCmd.Flags().Lookup("stdin")
	oldFlag, oldChanged := flag.Value.String(), flag.Changed
	defer func() {
		readPassword, readSecretValue = oldReader, oldSecret
		flag.Value.Set(oldFlag)
		flag.Changed = oldChanged
		rootCmd.SetArgs(nil)
		rootCmd.SetIn(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	}()
	prompts := 0
	readPassword = func(string) (string, error) { prompts++; return "pw", nil }
	value := []byte("quotes'\n$(literal)\n")
	want := string(value)
	readSecretValue = func() ([]byte, error) { return value, nil }
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	run := func(args ...string) error {
		t.Helper()
		out.Reset()
		flag.Value.Set("false")
		flag.Changed = false
		rootCmd.SetArgs(args)
		return rootCmd.Execute()
	}

	if err := run("set", "app", "KEY=must-not-be-in-argv"); err == nil || prompts != 0 {
		t.Fatal("inline value was accepted or prompted")
	}

	if err := run("set", "app", "KEY"); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(value, make([]byte, len(value))) {
		t.Fatal("owned secret input was not cleared")
	}

	s, err := store.Load("pw")

	if err != nil || s["app"]["KEY"] != want {
		t.Fatalf("hidden input: %v %v", s, err)
	}

	rootCmd.SetIn(strings.NewReader("exact trailing newline\n"))

	if err := run("set", "--stdin", "app", "KEY"); err != nil {
		t.Fatal(err)
	}

	s, err = store.Load("pw")

	if err != nil || s["app"]["KEY"] != "exact trailing newline\n" {
		t.Fatal("stdin was trimmed or changed")
	}

	for _, invalid := range []string{strings.Repeat("x", int(limits.SecretBytes)+1), "nul\x00value"} {
		rootCmd.SetIn(strings.NewReader(invalid))
		if err := run("set", "--stdin", "app", "KEY"); err == nil {
			t.Fatal("invalid stdin accepted")
		}
	}

	s, err = store.Load("pw")

	if err != nil || s["app"]["KEY"] != "exact trailing newline\n" {
		t.Fatal("failed input changed vault")
	}

	rootCmd.SetIn(strings.NewReader(""))

	if err := run("set", "--stdin", "app", "KEY"); err != nil {
		t.Fatal(err)
	}

	s, err = store.Load("pw")

	if err != nil || s["app"]["KEY"] != "" {
		t.Fatal("empty secret failed")
	}
}
