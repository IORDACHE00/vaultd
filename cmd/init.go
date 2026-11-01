package cmd

import (
	"fmt"
	"github.com/IORDACHE00/vaultd/internal/store"

	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new encrypted secrets vault",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		password, err := readPassword("New vault password: ")

		if err != nil {
			return err
		}

		if err := validateNewPassword(password); err != nil {
			return err
		}

		confirmation, err := readPassword("Confirm password: ")

		if err != nil {
			return err
		}

		if password != confirmation {
			return fmt.Errorf("passwords do not match")
		}

		if err := store.Initialize(password); err != nil {
			return err
		}

		fmt.Fprintln(cmd.OutOrStdout(), "Vault initialized at", store.GetVaultFilePath())
		return nil
	},
}

func init() { rootCmd.AddCommand(initCmd) }
