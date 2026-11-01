package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IORDACHE00/vaultd/internal/crypto"
)

func TestAtomicWriteFailures(t *testing.T) {
	old, err := crypto.Encrypt([]byte(`{"app":{"KEY":"old"}}`), "pw")
	if err != nil {
		t.Fatal(err)
	}

	updated, err := crypto.Encrypt([]byte(`{"app":{"KEY":"new"}}`), "pw")
	if err != nil {
		t.Fatal(err)
	}

	failure := errors.New("injected I/O failure")
	cases := []struct {
		name      string
		change    func(*atomicOps)
		committed bool
	}{
		{"write", func(o *atomicOps) { o.write = func(*os.File, []byte) (int, error) { return 0, failure } }, false},
		{"short-write", func(o *atomicOps) { o.write = func(*os.File, []byte) (int, error) { return 0, nil } }, false},
		{"file-sync", func(o *atomicOps) { o.syncFile = func(*os.File) error { return failure } }, false},
		{"readback", func(o *atomicOps) { o.readFile = func(string) ([]byte, error) { return nil, failure } }, false},
		{"corrupt-write", func(o *atomicOps) {
			o.write = func(f *os.File, b []byte) (int, error) {
				corrupt := bytes.Clone(b)
				corrupt[len(corrupt)-1] ^= 1

				return f.Write(corrupt)
			}
		}, false},
		{"rename", func(o *atomicOps) { o.rename = func(string, string) error { return failure } }, false},
		{"directory-sync", func(o *atomicOps) { o.syncDir = func(string) error { return failure } }, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "secrets.enc")
			if err := os.WriteFile(path, old, 0600); err != nil {
				t.Fatal(err)
			}

			ops := diskOps()
			tc.change(&ops)
			err := atomicWrite(path, updated, verifier("pw"), ops)

			if err == nil {
				t.Fatal("injected failure ignored")
			}

			want := old
			if tc.committed {
				want = updated

				if !strings.Contains(err.Error(), "may already be committed") {
					t.Fatal("ambiguous commit not reported")
				}
			}

			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("wrong primary after failure: %v", err)
			}

			files, _ := filepath.Glob(filepath.Join(dir, ".secrets-*"))
			if len(files) != 0 {
				t.Fatalf("temporary files leaked: %v", files)
			}
		})
	}

	t.Run("authentication", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "secrets.enc")
		if err := os.WriteFile(path, old, 0600); err != nil {
			t.Fatal(err)
		}

		if err := atomicWrite(path, updated, verifier("wrong"), diskOps()); err == nil {
			t.Fatal("unauthenticated data committed")
		}

		got, _ := os.ReadFile(path)
		if !bytes.Equal(got, old) {
			t.Fatal("authentication failure replaced primary")
		}
	})
}

func TestBackupAndRecovery(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if err := Initialize("pw"); err != nil {
		t.Fatal(err)
	}

	if err := Update("pw", "app", "KEY", "old"); err != nil {
		t.Fatal(err)
	}

	old, _ := os.ReadFile(GetVaultFilePath())
	if err := Update("pw", "app", "KEY", "new"); err != nil {
		t.Fatal(err)
	}

	backup, err := os.ReadFile(BackupFilePath())
	if err != nil || !bytes.Equal(backup, old) {
		t.Fatalf("backup mismatch: %v", err)
	}

	info, err := os.Stat(BackupFilePath())
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("backup permissions: %v", err)
	}

	if err := Recover("pw", false); err == nil {
		t.Fatal("replaced primary without explicit force")
	}

	if err := Recover("wrong", true); err == nil {
		t.Fatal("accepted wrong password")
	}

	if err := os.WriteFile(GetVaultFilePath(), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := Load("pw"); err == nil {
		t.Fatal("silently fell back to backup")
	}

	if err := Update("pw", "app", "KEY", "lost"); err == nil {
		t.Fatal("overwrote corruption or backup")
	}

	if err := Recover("pw", true); err != nil {
		t.Fatal(err)
	}

	s, err := Load("pw")

	if err != nil || s["app"]["KEY"] != "old" {
		t.Fatalf("recovery: %v %v", s, err)
	}

	afterBackup, _ := os.ReadFile(BackupFilePath())
	if !bytes.Equal(backup, afterBackup) {
		t.Fatal("recovery altered backup")
	}

	if err := os.Remove(GetVaultFilePath()); err != nil {
		t.Fatal(err)
	}

	if err := Initialize("new-password"); err == nil {
		t.Fatal("ignored recoverable backup during fresh init")
	}

	if err := Recover("pw", false); err != nil {
		t.Fatal(err)
	}

	before, _ := os.ReadFile(GetVaultFilePath())
	if err := os.WriteFile(BackupFilePath(), []byte("bad backup"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := Recover("pw", true); err == nil {
		t.Fatal("restored corrupt backup")
	}

	after, _ := os.ReadFile(GetVaultFilePath())
	if !bytes.Equal(before, after) {
		t.Fatal("failed recovery changed primary")
	}
}

func TestInterruptedSavePreservesPrimary(t *testing.T) {
	for _, stage := range []string{"backup", "primary"} {
		t.Run(stage, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())

			if err := Initialize("pw"); err != nil {
				t.Fatal(err)
			}

			if err := Update("pw", "app", "KEY", "old"); err != nil {
				t.Fatal(err)
			}

			before, _ := os.ReadFile(GetVaultFilePath())
			ops := diskOps()
			ops.rename = func(from, to string) error {
				if stage == "backup" && to == BackupFilePath() || stage == "primary" && to == GetVaultFilePath() {
					return errors.New("injected rename failure")
				}

				return os.Rename(from, to)
			}

			unlock, err := Lock("write.lock", false)
			if err != nil {
				t.Fatal(err)
			}

			err = saveWithOps(SecretsStore{"app": {"KEY": "new"}}, "pw", ops)
			unlock()

			if err == nil {
				t.Fatal("ignored failure")
			}

			after, _ := os.ReadFile(GetVaultFilePath())
			if !bytes.Equal(before, after) {
				t.Fatal("failed update changed primary")
			}

			if stage == "primary" {
				backup, _ := os.ReadFile(BackupFilePath())
				if !bytes.Equal(before, backup) {
					t.Fatal("primary failure lost recovery source")
				}
			}
		})
	}
}

func TestOrphanCleanupNeverPromotes(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if err := Initialize("pw"); err != nil {
		t.Fatal(err)
	}

	before, _ := os.ReadFile(GetVaultFilePath())
	dir := filepath.Dir(GetVaultFilePath())
	orphan := filepath.Join(dir, ".secrets-abandoned.tmp")

	if err := os.WriteFile(orphan, before, 0600); err != nil {
		t.Fatal(err)
	}

	unrelated := filepath.Join(dir, "unrelated.txt")
	if err := os.WriteFile(unrelated, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := os.Mkdir(filepath.Join(dir, ".secrets-directory"), 0700); err != nil {
		t.Fatal(err)
	}

	if err := Update("wrong", "app", "KEY", "new"); err == nil {
		t.Fatal("accepted wrong password")
	}

	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatal("orphan not cleaned")
	}

	if _, err := os.Stat(unrelated); err != nil {
		t.Fatal("removed unrelated file")
	}

	after, _ := os.ReadFile(GetVaultFilePath())
	if !bytes.Equal(before, after) {
		t.Fatal("orphan promoted or primary changed")
	}
}
