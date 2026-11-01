package cmd

import (
	"fmt"
	"github.com/IORDACHE00/vaultd/internal/store"

	"github.com/spf13/cobra"
)

var getCmd = &cobra.Command{
	Use:   "get [app-name] KEY",
	Short: "Print a secret value to stdout (followed by a newline)",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		app, key, err := secretArguments(cmd, args)

		if err != nil {
			return err
		}

		if !store.ValidKey(key) {
			return fmt.Errorf("provide a nonempty app name and a valid environment variable name")
		}

		password, err := readVaultPassword(cmd)

		if err != nil {
			return err
		}

		s, err := store.Load(password)

		if err != nil {
			return err
		}

		value, ok := s[app][key]

		if !ok {
			return fmt.Errorf("secret %q not found for app %q", key, app)
		}

		_, err = fmt.Fprintln(cmd.OutOrStdout(), value)
		return err
	},
}

func init() { rootCmd.AddCommand(getCmd) }
