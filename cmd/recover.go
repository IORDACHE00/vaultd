package cmd

import (
	"fmt"
	"github.com/IORDACHE00/vaultd/internal/store"

	"github.com/spf13/cobra"
)

var recoverCmd = &cobra.Command{
	Use:   "recover",
	Short: "Explicitly restore the encrypted previous-version backup (rolls back secrets)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		password, err := readVaultPassword(cmd)

		if err != nil {
			return err
		}

		force, _ := cmd.Flags().GetBool("force")

		if err := store.Recover(password, force); err != nil {
			return err
		}

		_, err = fmt.Fprintln(cmd.OutOrStdout(), "Vault restored from previous-version backup. Newer changes may have been rolled back.")
		return err
	},
}

func init() {
	recoverCmd.Flags().Bool("force", false, "Replace an existing primary vault with the backup")
	rootCmd.AddCommand(recoverCmd)
}
