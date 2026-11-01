package cmd

import (
	"context"
	"errors"
	"fmt"
	"github.com/IORDACHE00/vaultd/internal/ipc"
	"github.com/IORDACHE00/vaultd/internal/store"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

const defaultUnlockTimeout = 15 * time.Minute
const maxDaemonClients = 4

type daemonOptions struct {
	unlockTimeout time.Duration
	ready         func() error
	// Dependency injection also makes cancellation/drain tests deterministic.
	load func(string) (map[string]string, error)
}

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Unlock the vault and serve secrets over a private Unix socket",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		duration, _ := cmd.Flags().GetDuration("unlock-timeout")

		if duration < 0 {
			return fmt.Errorf("unlock timeout must not be negative")
		}

		detach, _ := cmd.Flags().GetBool("detach")

		if detach {
			return startDetached(cmd)
		}

		listener, err := ipc.Listen()

		if err != nil {
			return err
		}

		defer listener.Close()
		password, err := readVaultPassword(cmd)

		if err != nil {
			return err
		}

		if err := store.CheckPassword(password); err != nil {
			return err
		}

		return serveDaemon(cmd.Context(), listener, password, daemonOptions{
			unlockTimeout: duration,
			ready: func() error {
				_, err := fmt.Fprintln(cmd.OutOrStdout(), "Vaultd listening on", listener.Addr())
				return err
			},
		})
	},
}

var daemonStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Request daemon shutdown (apps already launched keep their secrets)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := ipc.Stop(); err != nil {
			return fmt.Errorf("cannot stop daemon: %w", err)
		}

		_, err := fmt.Fprintln(cmd.OutOrStdout(), "Daemon stop requested.")
		return err
	},
}

func serveDaemon(parent context.Context, listener ipc.Listener, password string, options ...daemonOptions) (result error) {
	opts := daemonOptions{unlockTimeout: defaultUnlockTimeout}

	if len(options) > 0 {
		opts = options[0]
	}

	if opts.unlockTimeout < 0 {
		return fmt.Errorf("unlock timeout must not be negative")
	}

	load := opts.load

	if load == nil {
		load = func(app string) (map[string]string, error) { return loadApp(password, app) }
	}

	var lifetime context.Context
	var cancelLifetime context.CancelFunc

	if opts.unlockTimeout > 0 {
		lifetime, cancelLifetime = context.WithTimeout(parent, opts.unlockTimeout)
	} else {
		lifetime, cancelLifetime = context.WithCancel(parent)
	}

	defer cancelLifetime()
	ctx, stop := signal.NotifyContext(lifetime, os.Interrupt, syscall.SIGTERM)
	defer stop()

	slots := make(chan struct{}, maxDaemonClients)
	active := make(map[net.Conn]struct{})
	var mu sync.Mutex
	var clients sync.WaitGroup
	stopping := false
	shutdown := func(except net.Conn) {
		mu.Lock()
		defer mu.Unlock()

		if stopping {
			return
		}

		stopping = true
		stop()
		// Keep the socket path and daemon lock until ALL workers have drained.
		_ = listener.StopAccepting()

		for conn := range active {
			if conn != except {
				_ = conn.Close()
			}
		}
	}
	watcherDone := make(chan struct{})
	go func() { defer close(watcherDone); <-ctx.Done(); shutdown(nil) }()
	defer func() {
		shutdown(nil)
		clients.Wait()
		<-watcherDone
		result = errors.Join(result, listener.Close())
	}()

	if err := ctx.Err(); err != nil {
		return err
	}

	if opts.ready != nil {
		if err := opts.ready(); err != nil {
			return err
		}
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		mu.Lock()
		if stopping {
			mu.Unlock()
			_ = conn.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			mu.Unlock()
			_ = conn.Close()
			continue
		}
		active[conn] = struct{}{}
		clients.Add(1)
		mu.Unlock()
		go func(conn net.Conn) {
			defer func() { mu.Lock(); delete(active, conn); mu.Unlock(); <-slots; clients.Done() }()
			ipc.HandleControl(conn, func(app string) (map[string]string, error) {
				if err := ctx.Err(); err != nil {
					return nil, err
				}

				secrets, err := load(app)

				if err == nil {
					err = ctx.Err()
				}

				if err != nil {
					return nil, err
				}

				return secrets, nil
			}, func() { shutdown(conn) })
		}(conn)
	}
}

func loadApp(password, app string) (map[string]string, error) {
	s, err := store.Load(password)

	if err != nil {
		return nil, err
	}

	secrets, ok := s[app]

	if !ok {
		return nil, fmt.Errorf("unknown app %q", app)
	}

	return secrets, nil
}

func init() {
	daemonCmd.Flags().BoolP("detach", "d", false, "Unlock interactively, then run in the background")
	daemonCmd.Flags().Duration("unlock-timeout", defaultUnlockTimeout, "Maximum unlocked lifetime (0 explicitly disables expiry)")
	daemonCmd.AddCommand(daemonStopCmd)
	rootCmd.AddCommand(daemonCmd)
}
