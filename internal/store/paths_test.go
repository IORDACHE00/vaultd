package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultDirectoryIsVaultd(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	legacy := filepath.Join(home, ".vault")

	if err := os.Mkdir(legacy, 0700); err != nil {
		t.Fatal(err)
	}

	legacyFile := filepath.Join(legacy, "secrets.enc")
	if err := os.WriteFile(legacyFile, []byte("leave old data alone"), 0600); err != nil {
		t.Fatal(err)
	}

	dir, err := Directory()
	if err != nil {
		t.Fatal(err)
	}

	if want := filepath.Join(home, ".vaultd"); dir != want {
		t.Fatalf("directory %q, want %q", dir, want)
	}

	if want := filepath.Join(dir, "secrets.enc"); GetVaultFilePath() != want {
		t.Fatalf("vault path %q, want %q", GetVaultFilePath(), want)
	}

	if BackupFilePath() != filepath.Join(dir, "secrets.enc.bak") {
		t.Fatal("incorrect backup path")
	}

	if _, err := Load("pw"); !os.IsNotExist(err) {
		t.Fatalf("unexpected fallback to legacy data: %v", err)
	}

	if err := Initialize("pw"); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(legacyFile)
	if err != nil || string(data) != "leave old data alone" {
		t.Fatal("changed legacy directory")
	}
}
