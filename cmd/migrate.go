package cmd

import (
	"fmt"
	"github.com/IORDACHE00/vaultd/internal/store"

	"github.com/spf13/cobra"
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Upgrade primary and backup encryption; optionally rotate the password",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		oldPassword, err := readVaultPassword(cmd)

		if err != nil {
			return err
		}
		// Serialize enrollment with rotation. Enable also validates its password
		// under this lock, so a waiting enable cannot enroll a stale password.
		unlock, err := store.Lock("keyring.lock", false)

		if err != nil {
			return err
		}

		defer unlock()
		rotate, _ := cmd.Flags().GetBool("new-password")
		newPassword := oldPassword

		if rotate {
			enabled, err := keyringManager.Enabled()
			if err != nil {
				return err
			}
			if enabled {
				return fmt.Errorf("disable OS keyring storage before rotating; re-enable it after successful migration")
			}
			newPassword, err = readPassword("New vault password: ")
			if err != nil {
				return err
			}
			if err := validateNewPassword(newPassword); err != nil {
				return err
			}
			confirmation, err := readPassword("Confirm new password: ")
			if err != nil {
				return err
			}
			if newPassword != confirmation {
				return fmt.Errorf("passwords do not match")
			}
		}

		if !rotate {
			if err := validateNewPassword(newPassword); err != nil {
				return err
			}
		}

		if err := store.Migrate(oldPassword, newPassword); err != nil {
			return err
		}

		_, err = fmt.Fprintln(cmd.OutOrStdout(), "Primary and previous-version backup migrated to Argon2id v2. External old copies are unchanged; delete or secure them separately.")
		return err
	},
}

func init() {
	migrateCmd.Flags().Bool("new-password", false, "Prompt for a new master password (keyring storage must be disabled first)")
	rootCmd.AddCommand(migrateCmd)
}
