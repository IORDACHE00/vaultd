package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var keyringCmd = &cobra.Command{
	Use:   "keyring",
	Short: "Opt in to Linux Secret Service password storage",
}

var keyringEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Verify and save your vault password in the Linux OS keyring",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Always ask explicitly; never enroll a possibly stale keyring password.
		password, err := readPassword("Vault password to save in OS keyring: ")

		if err != nil {
			return err
		}

		if err := keyringManager.Enable(password); err != nil {
			return err
		}

		_, err = fmt.Fprintln(cmd.OutOrStdout(), "OS keyring enabled. Same-user processes with access to your unlocked keyring remain trusted.")
		return err
	},
}

var keyringDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Remove the saved OS keyring password and return to manual prompts",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := keyringManager.Disable(); err != nil {
			return err
		}

		_, err := fmt.Fprintln(cmd.OutOrStdout(), "Saved OS keyring password removed. Stop the daemon too; it retains its in-memory password until shutdown.")
		return err
	},
}

var keyringStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show whether keyring integration is configured (does not unlock it)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		enabled, err := keyringManager.Enabled()

		if err != nil {
			return err
		}

		state := "disabled"

		if enabled {
			state = "enabled (availability depends on your Secret Service provider)"
		}

		_, err = fmt.Fprintln(cmd.OutOrStdout(), "OS keyring:", state)
		return err
	},
}

func init() {
	rootCmd.PersistentFlags().Bool("password", false, "Bypass the OS keyring and prompt for the vault password")
	keyringCmd.AddCommand(keyringEnableCmd, keyringDisableCmd, keyringStatusCmd)
	rootCmd.AddCommand(keyringCmd)
}
