// Package credentials provides explicit opt-in Linux Secret Service storage.
// It does not change the vault's encryption format or silently remember secrets.
package credentials

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/IORDACHE00/vaultd/internal/limits"
	"github.com/IORDACHE00/vaultd/internal/safeio"
	"github.com/IORDACHE00/vaultd/internal/store"

	"github.com/zalando/go-keyring"
)

const service = "vaultd"
const markerName = "keyring.enabled"
const markerContents = "vaultd-secret-service-v1\n"

type Backend interface {
	Set(service, account, password string) error
	Get(service, account string) (string, error)
	Delete(service, account string) error
}

type SystemBackend struct{}

func linuxOnly() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("OS keyring support currently requires Linux Secret Service")
	}

	return nil
}

func (SystemBackend) Set(s, a, p string) error {
	if err := linuxOnly(); err != nil {
		return err
	}

	return keyring.Set(s, a, p)
}

func (SystemBackend) Get(s, a string) (string, error) {
	if err := linuxOnly(); err != nil {
		return "", err
	}

	return keyring.Get(s, a)
}

func (SystemBackend) Delete(s, a string) error {
	if err := linuxOnly(); err != nil {
		return err
	}

	err := keyring.Delete(s, a)

	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}

	return err
}

type Manager struct{ Backend Backend }

func markerPath() (string, error) {
	dir, err := store.Directory()
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, markerName), nil
}

func account() (string, error) {
	dir, err := store.Directory()
	if err != nil {
		return "", err
	}

	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("vault-%x", sha256.Sum256([]byte(filepath.Join(dir, "secrets.enc")))), nil
}

func (m Manager) Enabled() (bool, error) {
	path, err := markerPath()
	if err != nil {
		return false, err
	}

	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("keyring marker must be a regular file")
	}

	data, err := safeio.ReadFile(path, limits.MarkerBytes)
	if err != nil {
		return false, err
	}

	if string(data) != markerContents {
		return false, fmt.Errorf("invalid keyring marker; run 'vaultd keyring disable'")
	}

	return true, nil
}

// Password returns enabled=false without querying the OS keyring by default.
// Missing/locked/unavailable credentials never trigger a silent fallback.
func (m Manager) Password() (password string, enabled bool, err error) {
	enabled, err = m.Enabled()

	if err != nil || !enabled {
		return "", enabled, err
	}

	a, err := account()

	if err != nil {
		return "", true, err
	}

	password, err = m.Backend.Get(service, a)

	if err != nil {
		return "", true, fmt.Errorf("OS keyring unavailable; unlock it or use --password: %w", err)
	}

	if password == "" {
		return "", true, fmt.Errorf("empty OS keyring credential; use --password and re-enable keyring storage")
	}

	return password, true, nil
}

func (m Manager) Enable(password string) error {
	if password == "" {
		return fmt.Errorf("password must not be empty")
	}

	unlock, err := store.Lock("keyring.lock", false)

	if err != nil {
		return err
	}

	defer unlock()

	if err := store.CheckPassword(password); err != nil {
		return err
	}

	a, err := account()

	if err != nil {
		return err
	}

	if err := m.Backend.Set(service, a, password); err != nil {
		return fmt.Errorf("store OS keyring credential: %w", err)
	}

	readback, err := m.Backend.Get(service, a)

	if err != nil {
		return fmt.Errorf("verify OS keyring credential: %w", err)
	}

	if readback != password {
		return fmt.Errorf("OS keyring credential verification failed")
	}

	path, err := markerPath()

	if err != nil {
		return err
	}

	f, err := os.CreateTemp(filepath.Dir(path), ".keyring-*")

	if err != nil {
		return err
	}

	defer f.Close()
	defer os.Remove(f.Name())

	if _, err := f.WriteString(markerContents); err != nil {
		return err
	}

	if err := f.Sync(); err != nil {
		return err
	}

	if err := f.Close(); err != nil {
		return err
	}

	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}

	return syncDir(filepath.Dir(path))
}

func (m Manager) Disable() error {
	unlock, err := store.Lock("keyring.lock", false)

	if err != nil {
		return err
	}

	defer unlock()
	a, err := account()

	if err != nil {
		return err
	}
	// Keep the opt-in marker if removal fails: never claim the saved password
	// was removed while the keyring service could not confirm deletion.
	if err := m.Backend.Delete(service, a); err != nil {
		return fmt.Errorf("remove OS keyring credential: %w", err)
	}

	path, err := markerPath()

	if err != nil {
		return err
	}

	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}

	return syncDir(filepath.Dir(path))
}

func syncDir(path string) error {
	f, err := os.Open(path)

	if err != nil {
		return err
	}

	defer f.Close()

	if err := f.Sync(); err != nil {
		return fmt.Errorf("keyring configuration changed but directory sync failed: %w", err)
	}

	return nil
}
