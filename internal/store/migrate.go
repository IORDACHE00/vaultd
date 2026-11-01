package store

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/IORDACHE00/vaultd/internal/crypto"
	"github.com/IORDACHE00/vaultd/internal/limits"
	"github.com/IORDACHE00/vaultd/internal/safeio"
)

func encode(s SecretsStore, password string) ([]byte, error) {
	plain, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}

	defer clear(plain)

	data, err := crypto.Encrypt(plain, password)
	if err != nil {
		return nil, err
	}

	if int64(len(data)) > limits.VaultBytes {
		return nil, fmt.Errorf("encrypted vault exceeds %d bytes", limits.VaultBytes)
	}

	return data, nil
}

// Migrate rewrites primary AND previous-version backup with v2, optionally
// rotating the password. There is no atomic two-file transaction: backup is
// committed first. Interrupted rotations can be retried with the original and
// destination passwords; each snapshot must authenticate with one of them.
func Migrate(oldPassword, newPassword string) error {
	return migrateWithOps(oldPassword, newPassword, diskOps())
}

func migrateWithOps(oldPassword, newPassword string, ops atomicOps) error {
	if oldPassword == "" || newPassword == "" {
		return fmt.Errorf("password must not be empty")
	}

	stopDaemon, err := Lock("daemon.lock", true)
	if err != nil {
		return fmt.Errorf("stop the daemon before migrating: %w", err)
	}
	defer stopDaemon()

	unlock, err := Lock("write.lock", false)
	if err != nil {
		return err
	}

	defer unlock()

	if err := cleanupTemps(); err != nil {
		return err
	}

	read := func(path string) (SecretsStore, error) {
		data, err := safeio.ReadFile(path, limits.VaultBytes)

		if err != nil {
			return nil, err
		}

		s, err := decodeWith(data, oldPassword, true)
		if err != nil && newPassword != oldPassword {
			// Only an explicitly supplied destination password permits retry of
			// a partially committed rotation; no unauthenticated promotion.
			s, err = decodeWith(data, newPassword, true)
		}

		return s, err
	}

	primary, err := read(GetVaultFilePath())
	if err != nil {
		return fmt.Errorf("authenticate primary before migration: %w", err)
	}

	backup, err := read(BackupFilePath())
	if os.IsNotExist(err) {
		backup = primary
	} else if err != nil {
		return fmt.Errorf("authenticate backup before migration: %w", err)
	}

	// Authenticate and encrypt everything before modifying either destination.
	primaryData, err := encode(primary, newPassword)
	if err != nil {
		return err
	}

	backupData, err := encode(backup, newPassword)
	if err != nil {
		return err
	}

	if err := atomicWrite(BackupFilePath(), backupData, verifier(newPassword), ops); err != nil {
		return fmt.Errorf("migration may be partial; retry with the same original/destination passwords: %w", err)
	}

	if err := atomicWrite(GetVaultFilePath(), primaryData, verifier(newPassword), ops); err != nil {
		return fmt.Errorf("backup migrated but primary commit failed or is uncertain; retry with the same original/destination passwords: %w", err)
	}

	return nil
}
