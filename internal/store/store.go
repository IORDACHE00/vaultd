package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/IORDACHE00/vaultd/internal/crypto"
	"github.com/IORDACHE00/vaultd/internal/limits"
	"github.com/IORDACHE00/vaultd/internal/safeio"

	"golang.org/x/sys/unix"
)

const directoryName = ".vaultd"

type SecretsStore map[string]map[string]string

var envKey = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

func ValidKey(key string) bool { return envKey.MatchString(key) }

// Directory is shared by the vault, lock files and private IPC socket.
func Directory() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	path := filepath.Join(home, directoryName)
	// HOME must already exist; do not create an unsynced chain of ancestors.
	if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
		return "", err
	}

	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}

	if !info.IsDir() {
		return "", fmt.Errorf("%s must be a directory, not a symlink", path)
	}

	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		return "", fmt.Errorf("vault directory must be owned by the effective user")
	}

	if err := os.Chmod(path, 0700); err != nil {
		return "", err
	}

	// Persist the vault directory entry too, including its first creation.
	if err := syncDirectory(home); err != nil {
		return "", fmt.Errorf("sync vault parent directory: %w", err)
	}

	return path, nil
}

func GetVaultFilePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, directoryName, "secrets.enc")
}

// Lock serializes writers (or daemon instances). The lock file is never removed:
// unlinking it would allow different processes to lock different inodes.
func Lock(name string, nonblocking bool) (func(), error) {
	dir, err := Directory()
	if err != nil {
		return nil, err
	}

	path := filepath.Join(dir, name)

	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}

	f := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t

	if err := unix.Fstat(fd, &st); err != nil {
		f.Close()
		return nil, err
	}

	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || st.Mode&0077 != 0 {
		f.Close()
		return nil, fmt.Errorf("lock must be a private, singly-linked regular file owned by this user")
	}

	flags := unix.LOCK_EX

	if nonblocking {
		flags |= unix.LOCK_NB
	}

	if err := unix.Flock(int(f.Fd()), flags); err != nil {
		f.Close()
		return nil, err
	}

	return func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN); _ = f.Close() }, nil
}

// Load observes either the complete old file or the complete new file.
func Load(passphrase string) (SecretsStore, error) {
	if _, err := Directory(); err != nil {
		return nil, err
	}

	data, err := safeio.ReadFile(GetVaultFilePath(), limits.VaultBytes)
	if err != nil {
		return nil, err
	}

	return decode(data, passphrase)
}

func decode(data []byte, passphrase string) (SecretsStore, error) {
	return decodeWith(data, passphrase, false)
}

func decodeWith(data []byte, passphrase string, migration bool) (SecretsStore, error) {
	decrypt := crypto.Decrypt

	if migration {
		decrypt = crypto.DecryptForMigration
	}

	plain, err := decrypt(data, passphrase)
	if err != nil {
		return nil, fmt.Errorf("cannot unlock vault (wrong password or corrupt file): %w", err)
	}
	defer clear(plain)

	var s SecretsStore

	if err := json.Unmarshal(plain, &s); err != nil {
		return nil, err
	}

	if s == nil {
		s = make(SecretsStore)
	}

	return s, nil
}

// Initialize refuses to replace an existing vault, even if it is corrupt.
func Initialize(passphrase string) error {
	unlock, err := Lock("write.lock", false)
	if err != nil {
		return err
	}

	defer unlock()

	if err := cleanupTemps(); err != nil {
		return err
	}

	if _, err := os.Lstat(BackupFilePath()); err == nil {
		return fmt.Errorf("vault backup exists; recover it or explicitly remove it before initializing a fresh vault")
	} else if !os.IsNotExist(err) {
		return err
	}

	if _, err := os.Lstat(GetVaultFilePath()); err == nil {
		return fmt.Errorf("vault already exists; refusing to overwrite it")
	} else if !os.IsNotExist(err) {
		return err
	}

	return save(make(SecretsStore), passphrase)
}

// Update creates or replaces a secret under the writer lock.
func Update(passphrase, app, key, value string) error {
	if app == "" || !ValidKey(key) {
		return fmt.Errorf("app must be nonempty and key must be a valid environment variable name")
	}

	if int64(len(value)) > limits.SecretBytes || strings.ContainsRune(value, 0) {
		return fmt.Errorf("secret must be at most %d bytes and contain no NUL", limits.SecretBytes)
	}

	unlock, err := Lock("write.lock", false)
	if err != nil {
		return err
	}

	defer unlock()

	if err := cleanupTemps(); err != nil {
		return err
	}

	s, err := Load(passphrase)
	if err != nil {
		return err
	}

	if s[app] == nil {
		s[app] = make(map[string]string)
	}

	s[app][key] = value

	return save(s, passphrase)
}

func BackupFilePath() string { return GetVaultFilePath() + ".bak" }

func verifier(passphrase string) func([]byte) error {
	return func(data []byte) error {
		plain, err := crypto.Decrypt(data, passphrase)
		if err != nil {
			return err
		}

		defer clear(plain)

		if !json.Valid(plain) {
			return fmt.Errorf("invalid vault JSON")
		}

		return nil
	}
}

// CheckPassword authenticates without retaining a discarded plaintext map.
func CheckPassword(passphrase string) error {
	if _, err := Directory(); err != nil {
		return err
	}

	data, err := safeio.ReadFile(GetVaultFilePath(), limits.VaultBytes)
	if err != nil {
		return err
	}

	return verifier(passphrase)(data)
}

// save durably preserves the last authenticated primary before committing the
// new one. The backup may equal the primary after an interrupted update.
// Callers must hold write.lock.
func save(s SecretsStore, passphrase string) error {
	return saveWithOps(s, passphrase, diskOps())
}

func saveWithOps(s SecretsStore, passphrase string, ops atomicOps) error {
	data, err := encode(s, passphrase)
	if err != nil {
		return err
	}

	path := GetVaultFilePath()

	previous, err := safeio.ReadFile(path, limits.VaultBytes)
	if err == nil {
		if err := verifier(passphrase)(previous); err != nil {
			return err
		}

		if err := atomicWrite(BackupFilePath(), previous, verifier(passphrase), ops); err != nil {
			return fmt.Errorf("preserve previous vault: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	return atomicWrite(path, data, verifier(passphrase), ops)
}

// Recover is explicit rollback, never an automatic fallback on load errors.
// Preserve the recovery source so a failed restore can be retried safely.
func Recover(passphrase string, replace bool) error {
	unlock, err := Lock("write.lock", false)
	if err != nil {
		return err
	}

	defer unlock()

	if err := cleanupTemps(); err != nil {
		return err
	}

	if _, err := os.Lstat(GetVaultFilePath()); err == nil {
		if !replace {
			return fmt.Errorf("current vault exists; use 'vaultd recover --force' to replace it with the backup")
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	data, err := safeio.ReadFile(BackupFilePath(), limits.VaultBytes)
	if err != nil {
		return err
	}

	if !crypto.IsCurrent(data) {
		// Explicit legacy recovery upgrades the recovery source too.
		s, err := decodeWith(data, passphrase, true)
		if err != nil {
			return err
		}

		data, err = encode(s, passphrase)
		if err != nil {
			return err
		}

		if err := atomicWrite(BackupFilePath(), data, verifier(passphrase), diskOps()); err != nil {
			return err
		}
	} else if _, err := decode(data, passphrase); err != nil {
		return err
	}

	return atomicWrite(GetVaultFilePath(), data, verifier(passphrase), diskOps())
}
