package cmd

import (
	"bytes"
	"github.com/IORDACHE00/vaultd/internal/credentials"
	"github.com/IORDACHE00/vaultd/internal/store"
	"os"
	"testing"
)

func TestMigrationPasswordRotationAndKeyringGuard(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if err := store.Initialize("old-password"); err != nil {
		t.Fatal(err)
	}

	if err := store.Update("old-password", "app", "KEY", "value"); err != nil {
		t.Fatal(err)
	}

	oldManager, oldReader, oldConfirmation := keyringManager, readPassword, readConfirmation
	readConfirmation = func(string) (bool, error) { return false, nil }
	backend := &commandKeyring{}
	keyringManager = credentials.Manager{Backend: backend}
	flag := migrateCmd.Flags().Lookup("new-password")
	oldFlag, oldChanged := flag.Value.String(), flag.Changed
	defer func() {
		keyringManager, readPassword, readConfirmation = oldManager, oldReader, oldConfirmation
		flag.Value.Set(oldFlag)
		flag.Changed = oldChanged
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	}()
	var prompts []string
	readPassword = func(string) (string, error) {
		if len(prompts) == 0 {
			t.Fatal("unexpected password prompt")
		}

		p := prompts[0]
		prompts = prompts[1:]
		return p, nil
	}
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	run := func(args ...string) error {
		t.Helper()
		flag.Value.Set("false")
		flag.Changed = false
		out.Reset()
		rootCmd.SetArgs(args)
		return rootCmd.Execute()
	}

	if err := keyringManager.Enable("old-password"); err != nil {
		t.Fatal(err)
	}

	before, _ := os.ReadFile(store.GetVaultFilePath())

	if err := run("migrate"); err == nil {
		t.Fatal("migration retained a short password without confirmation")
	}

	if err := run("migrate", "--new-password"); err == nil {
		t.Fatal("rotated while keyring storage enabled")
	}

	after, _ := os.ReadFile(store.GetVaultFilePath())

	if !bytes.Equal(before, after) {
		t.Fatal("keyring guard modified vault")
	}

	if err := keyringManager.Disable(); err != nil {
		t.Fatal(err)
	}

	prompts = []string{"old-password", "short"}

	if err := run("migrate", "--new-password"); err == nil {
		t.Fatal("accepted short new password after declining confirmation")
	}

	prompts = []string{"old-password", "a long new master password", "confirmation mismatch"}

	if err := run("migrate", "--new-password"); err == nil {
		t.Fatal("accepted confirmation mismatch")
	}

	prompts = []string{"old-password", "a long new master password", "a long new master password"}

	if err := run("migrate", "--new-password"); err != nil {
		t.Fatal(err)
	}

	s, err := store.Load("a long new master password")

	if err != nil || s["app"]["KEY"] != "value" {
		t.Fatalf("rotation: %v %v", s, err)
	}

	if _, err := store.Load("old-password"); err == nil {
		t.Fatal("old password still accepted")
	}
}
