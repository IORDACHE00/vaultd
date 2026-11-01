package cmd

import (
	"errors"
	"fmt"
	"github.com/IORDACHE00/vaultd/internal/ipc"
	"github.com/IORDACHE00/vaultd/internal/store"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

// mergeEnvironment does not change vaultd's (or the parent shell's) environment.
func mergeEnvironment(inherited []string, secrets map[string]string) ([]string, error) {
	values := make(map[string]string, len(inherited)+len(secrets))

	for _, entry := range inherited {
		if key, value, ok := strings.Cut(entry, "="); ok {
			values[key] = value
		}
	}

	for key, value := range secrets {
		if !store.ValidKey(key) {
			return nil, fmt.Errorf("invalid environment variable name %q", key)
		}
		if strings.ContainsRune(value, 0) {
			return nil, fmt.Errorf("secret %q contains NUL, which environment variables cannot represent", key)
		}
		values[key] = value
	}

	keys := make([]string, 0, len(values))

	for key := range values {
		keys = append(keys, key)
	}

	sort.Strings(keys)
	env := make([]string, 0, len(keys))

	for _, key := range keys {
		env = append(env, key+"="+values[key])
	}

	return env, nil
}

// Look up commands using the environment the child will actually receive.
// Like exec.LookPath, refuse implicit execution from relative PATH entries.
func environmentExecutable(command string, env []string) (string, error) {
	if strings.ContainsRune(command, '/') {
		return exec.LookPath(command)
	}

	var path string

	for _, entry := range env {
		if strings.HasPrefix(entry, "PATH=") {
			path = strings.TrimPrefix(entry, "PATH=")
		}
	}

	var permission error

	for _, dir := range filepath.SplitList(path) {
		candidate := filepath.Join(dir, command)
		if !filepath.IsAbs(candidate) {
			candidate = "./" + candidate
		}
		found, err := exec.LookPath(candidate)
		if err == nil {
			if !filepath.IsAbs(found) {
				return "", &exec.Error{Name: command, Err: exec.ErrDot}
			}
			return found, nil
		}
		if errors.Is(err, os.ErrPermission) {
			permission = err
		}
	}

	if permission != nil {
		return "", permission
	}

	return "", &exec.Error{Name: command, Err: exec.ErrNotFound}
}

var runCmd = &cobra.Command{
	Use:   "run [--profile name] -- command [args...]",
	Short: "Run a command with the selected profile's secrets",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 || cmd.ArgsLenAtDash() != 0 {
			return fmt.Errorf("usage: vaultd run [--profile name] -- command [args...]")
		}

		if args[0] == "" {
			return fmt.Errorf("command must not be empty")
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		var app string
		var err error

		if cmd.Flags().Changed("app") {
			if cmd.Flags().Changed("profile") {
				return fmt.Errorf("use either --profile or --app, not both")
			}
			app, _ = cmd.Flags().GetString("app")
			err = validateProfile(app)
		} else {
			app, err = resolveProfile(cmd)
		}

		if err != nil {
			return err
		}

		secrets, err := ipc.SendRequest(app)

		if err != nil {
			return fmt.Errorf("cannot get secrets for %q (is 'vaultd daemon -d' running?): %w", app, err)
		}

		env, err := mergeEnvironment(os.Environ(), secrets)

		if err != nil {
			return err
		}

		path, err := environmentExecutable(args[0], env)

		if err != nil {
			return err
		}
		// Replace vaultd: terminal I/O, signals, PID, and exit status belong to
		// the launched process, with no forwarding wrapper or intermediate shell.
		return syscall.Exec(path, args, env)
	},
}

func init() {
	runCmd.Flags().StringP("app", "a", "", "Legacy profile override (prefer --profile)")
	rootCmd.AddCommand(runCmd)
}
