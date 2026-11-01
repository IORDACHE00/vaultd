package store

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"os"
	"testing"

	vaultcrypto "github.com/IORDACHE00/vaultd/internal/crypto"

	"golang.org/x/crypto/pbkdf2"
)

// Deterministic legacy ciphertext is a test fixture only; never a writer API.
func legacyFixture(t *testing.T, text, password string) []byte {
	t.Helper()
	salt := bytes.Repeat([]byte{0x41}, 16)
	key := pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}

	nonce := bytes.Repeat([]byte{0x42}, gcm.NonceSize())

	return gcm.Seal(append(salt, nonce...), nonce, []byte(text), nil)
}

func legacyVault(t *testing.T) ([]byte, []byte) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())

	if _, err := Directory(); err != nil {
		t.Fatal(err)
	}

	primary := legacyFixture(t, `{"app":{"KEY":"latest"}}`, "old password")
	backup := legacyFixture(t, `{"app":{"KEY":"previous"}}`, "old password")

	if err := os.WriteFile(GetVaultFilePath(), primary, 0600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(BackupFilePath(), backup, 0600); err != nil {
		t.Fatal(err)
	}

	return primary, backup
}

func TestExplicitLegacyMigration(t *testing.T) {
	primary, backup := legacyVault(t)
	if _, err := Load("old password"); !errors.Is(err, vaultcrypto.ErrLegacyFormat) {
		t.Fatalf("normal loads accepted legacy: %v", err)
	}

	if err := Migrate("wrong", "wrong"); err == nil {
		t.Fatal("accepted wrong password")
	}

	after, _ := os.ReadFile(GetVaultFilePath())
	if !bytes.Equal(after, primary) {
		t.Fatal("failed authentication changed primary")
	}

	if err := Migrate("old password", "old password"); err != nil {
		t.Fatal(err)
	}

	current, err := Load("old password")
	if err != nil || current["app"]["KEY"] != "latest" {
		t.Fatalf("migrated primary: %v %v", current, err)
	}

	for path, want := range map[string]string{GetVaultFilePath(): "latest", BackupFilePath(): "previous"} {
		data, err := os.ReadFile(path)
		if err != nil || !vaultcrypto.IsCurrent(data) {
			t.Fatalf("snapshot not upgraded: %s %v", path, err)
		}

		s, err := decode(data, "old password")
		if err != nil || s["app"]["KEY"] != want {
			t.Fatalf("snapshot changed: %v %v", s, err)
		}
	}

	newBackup, _ := os.ReadFile(BackupFilePath())

	if bytes.Equal(newBackup, backup) {
		t.Fatal("retained weak backup")
	}
}

func TestInterruptedRotationCanRetry(t *testing.T) {
	legacyVault(t)

	ops := diskOps()
	ops.rename = func(from, to string) error {
		if to == GetVaultFilePath() {
			return errors.New("power-loss boundary")
		}

		return os.Rename(from, to)
	}

	if err := migrateWithOps("old password", "new strong password", ops); err == nil {
		t.Fatal("ignored interrupted rotation")
	}

	primary, _ := os.ReadFile(GetVaultFilePath())
	backup, _ := os.ReadFile(BackupFilePath())

	if vaultcrypto.IsCurrent(primary) || !vaultcrypto.IsCurrent(backup) {
		t.Fatal("unexpected commit boundary")
	}

	if _, err := decode(backup, "new strong password"); err != nil {
		t.Fatal("new-password backup missing")
	}

	if err := Migrate("old password", "new strong password"); err != nil {
		t.Fatal(err)
	}

	if _, err := Load("old password"); err == nil {
		t.Fatal("old password still unlocks primary")
	}

	s, err := Load("new strong password")

	if err != nil || s["app"]["KEY"] != "latest" {
		t.Fatalf("retry lost latest data: %v %v", s, err)
	}

	b, _ := os.ReadFile(BackupFilePath())
	previous, err := decode(b, "new strong password")
	if err != nil || previous["app"]["KEY"] != "previous" {
		t.Fatalf("retry lost history: %v %v", previous, err)
	}
}

func TestRotationRetryAfterCommittedButUncertainPrimary(t *testing.T) {
	legacyVault(t)
	ops := diskOps()
	calls := 0
	ops.syncDir = func(path string) error {
		calls++

		if calls == 2 {
			return errors.New("primary directory sync uncertain")
		}

		return syncDirectory(path)
	}

	if err := migrateWithOps("old password", "new strong password", ops); err == nil {
		t.Fatal("ignored uncertain commit")
	}

	if _, err := Load("new strong password"); err != nil {
		t.Fatal("primary was not committed at expected boundary")
	}

	if err := Migrate("old password", "new strong password"); err != nil {
		t.Fatal("cannot retry already-committed rotation", err)
	}
}

func TestMigrationRefusesLiveDaemonAndCorruptBackup(t *testing.T) {
	primary, _ := legacyVault(t)
	unlock, err := Lock("daemon.lock", true)
	if err != nil {
		t.Fatal(err)
	}

	err = Migrate("old password", "old password")
	unlock()

	if err == nil {
		t.Fatal("migrated while a daemon held the lock")
	}

	if err := os.WriteFile(BackupFilePath(), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := Migrate("old password", "old password"); err == nil {
		t.Fatal("ignored corrupt backup")
	}

	after, _ := os.ReadFile(GetVaultFilePath())
	if !bytes.Equal(primary, after) {
		t.Fatal("changed primary before authenticating all snapshots")
	}
}

func TestLegacyBackupRecoveryUpgradesBothFiles(t *testing.T) {
	legacyVault(t)

	if err := os.WriteFile(GetVaultFilePath(), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := Recover("old password", true); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{GetVaultFilePath(), BackupFilePath()} {
		data, _ := os.ReadFile(path)
		if !vaultcrypto.IsCurrent(data) {
			t.Fatal("recovery retained weak format")
		}
	}

	s, err := Load("old password")
	if err != nil || s["app"]["KEY"] != "previous" {
		t.Fatalf("recovery: %v %v", s, err)
	}
}
