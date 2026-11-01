package store

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/IORDACHE00/vaultd/internal/limits"
	"github.com/IORDACHE00/vaultd/internal/safeio"
)

// Operations are passed explicitly so tests can inject failures without global
// hooks or interference with concurrent writers.
type atomicOps struct {
	write    func(*os.File, []byte) (int, error)
	syncFile func(*os.File) error
	readFile func(string) ([]byte, error)
	rename   func(string, string) error
	syncDir  func(string) error
}

func diskOps() atomicOps {
	return atomicOps{
		write:    func(f *os.File, b []byte) (int, error) { return f.Write(b) },
		syncFile: func(f *os.File) error { return f.Sync() },
		readFile: func(path string) ([]byte, error) { return safeio.ReadFile(path, limits.VaultBytes) },
		rename:   os.Rename,
		syncDir:  syncDirectory,
	}
}

func syncDirectory(path string) error {
	f, err := os.Open(path)

	if err != nil {
		return err
	}

	defer f.Close()
	return f.Sync()
}

// atomicWrite never replaces the destination before sync and verification.
// Readback checks integrity, not physical persistence: durability depends on
// fsync and storage honoring flushes. The caller must hold write.lock.
func atomicWrite(path string, data []byte, verify func([]byte) error, ops atomicOps) error {
	dir := filepath.Dir(path)

	f, err := os.CreateTemp(dir, ".secrets-*.tmp")
	if err != nil {
		return err
	}

	defer os.Remove(f.Name())
	defer f.Close()

	n, err := ops.write(f, data)
	if err != nil {
		return fmt.Errorf("write temporary vault: %w", err)
	}

	if n != len(data) {
		return fmt.Errorf("write temporary vault: %w", io.ErrShortWrite)
	}

	if err := ops.syncFile(f); err != nil {
		return fmt.Errorf("sync temporary vault: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("close temporary vault: %w", err)
	}

	readback, err := ops.readFile(f.Name())
	if err != nil {
		return fmt.Errorf("read back temporary vault: %w", err)
	}

	if !bytes.Equal(readback, data) {
		return fmt.Errorf("temporary vault readback does not match written data")
	}

	if err := verify(readback); err != nil {
		return fmt.Errorf("verify temporary vault: %w", err)
	}

	if err := ops.rename(f.Name(), path); err != nil {
		return fmt.Errorf("replace vault: %w", err)
	}

	if err := ops.syncDir(dir); err != nil {
		return fmt.Errorf("%s was replaced, but directory sync failed; the change may already be committed: %w", filepath.Base(path), err)
	}

	return nil
}

// Only called with write.lock held. Orphans are never promoted to the vault:
// an authenticated temporary file can still be an uncommitted update.
func cleanupTemps() error {
	dir := filepath.Dir(GetVaultFilePath())

	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	removed := false

	for _, entry := range entries {
		name := entry.Name()

		if len(name) < len(".secrets-") || name[:len(".secrets-")] != ".secrets-" {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			return err
		}

		if !info.Mode().IsRegular() {
			continue
		}

		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			return err
		}

		removed = true
	}

	if removed {
		return syncDirectory(dir)
	}

	return nil
}
