package cmd

import (
	"bufio"
	"fmt"
	"github.com/IORDACHE00/vaultd/internal/credentials"
	"github.com/IORDACHE00/vaultd/internal/limits"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// Read from the controlling terminal, never stdin/stdout. Terminal input is
// hidden. The caller owns and should clear returned byte slices.
func hiddenInput(prompt string, max int64) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)

	if err != nil {
		return nil, fmt.Errorf("input requires an interactive terminal: %w", err)
	}

	defer tty.Close()

	if _, err := fmt.Fprint(tty, prompt); err != nil {
		return nil, err
	}

	value, err := term.ReadPassword(int(tty.Fd()))
	_, newlineErr := fmt.Fprintln(tty)

	if err != nil {
		clear(value)
		return nil, err
	}

	if newlineErr != nil {
		clear(value)
		return nil, newlineErr
	}

	if int64(len(value)) > max {
		clear(value)
		return nil, fmt.Errorf("input exceeds %d bytes", max)
	}

	return value, nil
}

func promptPassword(prompt string) (string, error) {
	password, err := hiddenInput(prompt, limits.PasswordBytes)

	if err != nil {
		return "", err
	}

	defer clear(password)

	if len(password) == 0 {
		return "", fmt.Errorf("password must not be empty")
	}
	// Legacy/keyring APIs still require a Go string; this copy cannot be wiped.
	return string(password), nil
}

func validateNewPassword(password string) error {
	if len(password) > limits.PasswordBytes || strings.TrimSpace(password) == "" {
		return fmt.Errorf("password must not be empty or whitespace-only and must be at most %d bytes", limits.PasswordBytes)
	}

	if utf8.RuneCountInString(password) < 16 {
		ok, err := readConfirmation("Warning: passwords shorter than 16 characters are easier to guess offline if your encrypted vault is stolen. Use this short password anyway? [y/N]: ")
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("short password declined; choose a longer, randomly generated passphrase")
		}
	}

	return nil
}

func promptConfirmation(prompt string) (bool, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)

	if err != nil {
		return false, fmt.Errorf("confirmation requires an interactive terminal: %w", err)
	}

	defer tty.Close()
	return readYesNo(tty, tty, prompt)
}

// Read confirmations from the controlling terminal, never piped secret input.
// Only an explicit y accepts; Enter/EOF cannot silently weaken the policy.
func readYesNo(input io.Reader, output io.Writer, prompt string) (bool, error) {
	reader := bufio.NewReaderSize(input, 128)

	for {
		if _, err := fmt.Fprint(output, prompt); err != nil {
			return false, err
		}
		line, err := reader.ReadSlice('\n')
		if err != nil {
			return false, fmt.Errorf("read confirmation: %w", err)
		}
		switch strings.ToLower(strings.TrimSpace(string(line))) {
		case "y":
			return true, nil
		case "n", "":
			return false, nil
		default:
			prompt = "Please answer y or n [y/N]: "
		}
	}
}

// Indirections keep command tests independent of a real terminal/keyring.
var readPassword = promptPassword
var readConfirmation = promptConfirmation
var readSecretValue = func() ([]byte, error) { return hiddenInput("Secret value: ", limits.SecretBytes) }
var keyringManager = credentials.Manager{Backend: credentials.SystemBackend{}}

func readVaultPassword(cmd *cobra.Command) (string, error) {
	manual, _ := cmd.Flags().GetBool("password")

	if !manual {
		password, enabled, err := keyringManager.Password()
		if err != nil {
			return "", err
		}
		if enabled {
			if len(password) > limits.PasswordBytes {
				return "", fmt.Errorf("OS keyring password exceeds supported size; use --password")
			}
			return password, nil
		}
	}

	return readPassword("Vault password: ")
}
