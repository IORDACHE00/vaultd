package cmd

import (
	"fmt"
	"github.com/IORDACHE00/vaultd/internal/limits"
	"github.com/IORDACHE00/vaultd/internal/safeio"
	"github.com/IORDACHE00/vaultd/internal/store"
	"strings"

	"github.com/spf13/cobra"
)

var setCmd = &cobra.Command{
	Use:   "set [app-name] KEY",
	Short: "Create or replace a secret using hidden input (or --stdin)",
	Args:  cobra.RangeArgs(1, 2),
	RunE:  saveSecret,
}

func saveSecret(cmd *cobra.Command, args []string) error {
	app, key, err := secretArguments(cmd, args)

	if err != nil {
		return err
	}

	if strings.ContainsRune(key, '=') || !store.ValidKey(key) {
		return fmt.Errorf("use 'vaultd set KEY'; secret values in command arguments are no longer accepted")
	}

	password, err := readVaultPassword(cmd)

	if err != nil {
		return err
	}

	stdin, _ := cmd.Flags().GetBool("stdin")
	var value []byte

	if stdin {
		value, err = safeio.Read(cmd.InOrStdin(), limits.SecretBytes)
	} else {
		value, err = readSecretValue()
	}

	if err != nil {
		return err
	}

	defer clear(value)

	if err := store.Update(password, app, key, string(value)); err != nil {
		return err
	}

	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Saved secret %q for app %q\n", key, app)
	return err
}

func init() {
	setCmd.Flags().Bool("stdin", false, "Read the exact secret bytes from stdin, preserving trailing newlines")
	rootCmd.AddCommand(setCmd)
}
