package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/IORDACHE00/vaultd/internal/limits"
	"github.com/IORDACHE00/vaultd/internal/safeio"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/spf13/cobra"
)

const profileConfigName = ".vaultd.json"

type profileConfig struct {
	Profile string `json:"profile"`
}

func validateProfile(profile string) error {
	if strings.TrimSpace(profile) == "" || strings.ContainsFunc(profile, unicode.IsControl) {
		return fmt.Errorf("profile must be nonempty and contain no control characters")
	}

	return nil
}

func readProfileConfig(path string) (profileConfig, error) {
	var config profileConfig
	info, err := os.Lstat(path)

	if err != nil {
		return config, err
	}

	if !info.Mode().IsRegular() {
		return config, fmt.Errorf("%s must be a regular file, not a symlink", path)
	}

	data, err := safeio.ReadFile(path, limits.ProfileBytes)

	if err != nil {
		return config, err
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&config); err != nil {
		return config, fmt.Errorf("invalid %s: %w", path, err)
	}

	var extra any

	if err := decoder.Decode(&extra); err != io.EOF {
		return config, fmt.Errorf("invalid %s: expected a single JSON object", path)
	}

	if err := validateProfile(config.Profile); err != nil {
		return config, fmt.Errorf("invalid %s: %w", path, err)
	}

	return config, nil
}

// findProfileConfig finds the nearest config without creating or changing it.
func findProfileConfig(dir string) (profileConfig, string, error) {
	for {
		path := filepath.Join(dir, profileConfigName)
		config, err := readProfileConfig(path)
		if err == nil {
			return config, path, nil
		}
		if !os.IsNotExist(err) {
			return profileConfig{}, "", err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return profileConfig{}, "", os.ErrNotExist
		}
		dir = parent
	}
}

// resolveProfile checks flags first so an explicit override can also bypass a
// broken project configuration. The nearest ancestor configuration wins.
func resolveProfile(cmd *cobra.Command) (string, error) {
	if cmd.Flags().Changed("profile") {
		profile, _ := cmd.Flags().GetString("profile")
		return profile, validateProfile(profile)
	}

	dir, err := os.Getwd()

	if err != nil {
		return "", err
	}

	config, _, err := findProfileConfig(dir)

	if err == nil {
		return config.Profile, nil
	}

	if !os.IsNotExist(err) {
		return "", err
	}

	fallback := filepath.Base(dir)

	if fallback == string(filepath.Separator) {
		return "", fmt.Errorf("provide --profile or run 'vaultd profile use NAME'")
	}

	return fallback, validateProfile(fallback)
}

// Accept optional positional profiles, while allowing get/set KEY to use the
// shared flag/project/folder profile selection rules.
func secretArguments(cmd *cobra.Command, args []string) (string, string, error) {
	if len(args) == 2 {
		if cmd.Flags().Changed("profile") {
			return "", "", fmt.Errorf("use either --profile or a positional profile, not both")
		}
		return args[0], args[1], validateProfile(args[0])
	}

	profile, err := resolveProfile(cmd)
	return profile, args[0], err
}

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manage the project-local default profile",
}

var profileUseCmd = &cobra.Command{
	Use:   "use [NAME]",
	Short: "Reuse a project profile, or save NAME (default: current folder name)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if cmd.Flags().Changed("profile") {
			return fmt.Errorf("profile use does not accept --profile; pass an optional NAME instead")
		}

		dir, err := os.Getwd()

		if err != nil {
			return err
		}

		profile := filepath.Base(dir)

		if len(args) == 0 {
			config, path, err := findProfileConfig(dir)
			if err == nil {
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Using profile %q from %s\n", config.Profile, path)
				return err
			}
			if !os.IsNotExist(err) {
				return err
			}
			if profile == string(filepath.Separator) {
				return fmt.Errorf("provide a profile name: vaultd profile use NAME")
			}
		} else {
			profile = args[0]
		}

		if err := validateProfile(profile); err != nil {
			return err
		}

		path := filepath.Join(dir, profileConfigName)
		// Do not silently destroy an unrelated or malformed config file.
		if _, err := readProfileConfig(path); err != nil && !os.IsNotExist(err) {
			return err
		}

		data, err := json.MarshalIndent(profileConfig{Profile: profile}, "", "  ")

		if err != nil {
			return err
		}

		data = append(data, '\n')
		f, err := os.CreateTemp(dir, ".vaultd-config-*")

		if err != nil {
			return err
		}

		defer os.Remove(f.Name())
		defer f.Close()

		if _, err := f.Write(data); err != nil {
			return err
		}

		if err := f.Chmod(0644); err != nil {
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

		_, err = fmt.Fprintf(cmd.OutOrStdout(), "Default profile %q saved to %s\n", profile, path)
		return err
	},
}

func init() {
	rootCmd.PersistentFlags().StringP("profile", "p", "", "Profile to use (overrides project config and folder name)")
	profileCmd.AddCommand(profileUseCmd)
	rootCmd.AddCommand(profileCmd)
}
