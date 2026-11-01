package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/IORDACHE00/vaultd/internal/ipc"
	"github.com/IORDACHE00/vaultd/internal/limits"
	"github.com/IORDACHE00/vaultd/internal/store"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

type startupConfig struct {
	Password      string        `json:"password"`
	UnlockTimeout time.Duration `json:"unlock_timeout"`
}

type startupMessage struct {
	State string `json:"state,omitempty"`
	Error string `json:"error,omitempty"`
}

// The detached child receives its password only through an inherited anonymous
// pipe, never argv, an environment variable, or a file. A second pipe provides
// explicit startup/error acknowledgements. The child owns the daemon lock.
func startDetached(cmd *cobra.Command) error {
	executable, err := os.Executable()

	if err != nil {
		return err
	}

	configR, configW, err := os.Pipe()

	if err != nil {
		return err
	}

	defer configR.Close()
	defer configW.Close()
	statusR, statusW, err := os.Pipe()

	if err != nil {
		return err
	}

	defer statusR.Close()
	defer statusW.Close()
	child := exec.Command(executable, "__daemon")
	child.ExtraFiles = []*os.File{configR, statusW}
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	// nil standard streams are connected to /dev/null by os/exec.
	if err := child.Start(); err != nil {
		return err
	}

	configR.Close()
	statusW.Close()
	success := false
	defer func() {
		if !success {
			// EOF lets a child waiting for a password clean up its socket.
			_ = configW.Close()
			done := make(chan struct{})
			go func() { _ = child.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				_ = child.Process.Kill()
				<-done
			}
		}
	}()
	decoder := json.NewDecoder(io.LimitReader(statusR, 64<<10))

	if err := startupState(statusR, decoder, "password"); err != nil {
		return err
	}

	password, err := readVaultPassword(cmd)

	if err != nil {
		return err
	}

	duration, _ := cmd.Flags().GetDuration("unlock-timeout")

	if err := json.NewEncoder(configW).Encode(startupConfig{Password: password, UnlockTimeout: duration}); err != nil {
		return err
	}

	configW.Close()

	if err := startupState(statusR, decoder, "ready"); err != nil {
		return err
	}

	success = true
	pid := child.Process.Pid
	_ = child.Process.Release()
	fmt.Fprintf(cmd.OutOrStdout(), "Vaultd detached (PID %d). Stop with 'vaultd daemon stop'.\n", pid)
	return nil
}

func startupState(pipe *os.File, decoder *json.Decoder, expected string) error {
	if err := pipe.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}

	var message startupMessage

	if err := decoder.Decode(&message); err != nil {
		return fmt.Errorf("daemon startup failed: %w", err)
	}

	if message.Error != "" {
		return fmt.Errorf("daemon startup failed: %s", message.Error)
	}

	if message.State != expected {
		return fmt.Errorf("unexpected daemon startup state %q", message.State)
	}

	return nil
}

var detachedChildCmd = &cobra.Command{
	Use:    "__daemon",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		config := os.NewFile(3, "daemon-config")
		status := os.NewFile(4, "daemon-status")

		if config == nil || status == nil {
			return fmt.Errorf("internal command requires inherited pipes")
		}

		defer config.Close()
		defer status.Close()

		for _, f := range []*os.File{config, status} {
			info, err := f.Stat()
			if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
				return fmt.Errorf("internal command requires inherited pipes")
			}
		}

		report := func(state string, err error) error {
			message := startupMessage{State: state}

			if err != nil {
				message.Error = err.Error()
			}

			return json.NewEncoder(status).Encode(message)
		}
		listener, err := ipc.Listen()

		if err != nil {
			_ = report("", err)
			return err
		}

		defer listener.Close()

		if err := report("password", nil); err != nil {
			return err
		}

		var settings startupConfig

		if err := json.NewDecoder(io.LimitReader(config, 64<<10)).Decode(&settings); err != nil {
			_ = report("", err)
			return err
		}

		config.Close()

		if len(settings.Password) == 0 || len(settings.Password) > limits.PasswordBytes || settings.UnlockTimeout < 0 {
			err := fmt.Errorf("invalid daemon startup settings")
			_ = report("", err)
			return err
		}

		if err := store.CheckPassword(settings.Password); err != nil {
			_ = report("", err)
			return err
		}

		return serveDaemon(cmd.Context(), listener, settings.Password, daemonOptions{
			unlockTimeout: settings.UnlockTimeout,
			ready: func() error {
				if err := report("ready", nil); err != nil {
					return err
				}

				return status.Close()
			},
		})
	},
}

func init() { rootCmd.AddCommand(detachedChildCmd) }
