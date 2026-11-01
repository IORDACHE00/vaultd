package ipc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/IORDACHE00/vaultd/internal/limits"
	"github.com/IORDACHE00/vaultd/internal/store"
)

const timeout = 10 * time.Second
const maxRequestSize = 64 * 1024

type request struct {
	Action string `json:"action"`
	App    string `json:"app,omitempty"`
}

type response struct {
	Secrets map[string]string `json:"secrets,omitempty"`
	Error   string            `json:"error,omitempty"`
}

func SocketPath() (string, error) {
	dir, err := store.Directory()
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, "daemon.sock"), nil
}

type Listener interface {
	net.Listener
	// StopAccepting retains the socket path and lock until final Close.
	StopAccepting() error
}

type listener struct {
	*net.UnixListener
	once   sync.Once
	unlock func()
	path   string
	err    error
}

func (l *listener) StopAccepting() error { return l.UnixListener.Close() }

func (l *listener) Close() error {
	l.once.Do(func() {
		closeErr := l.UnixListener.Close()

		if errors.Is(closeErr, net.ErrClosed) {
			closeErr = nil
		}

		removeErr := os.Remove(l.path)

		if os.IsNotExist(removeErr) {
			removeErr = nil
		}

		l.err = errors.Join(closeErr, removeErr)
		l.unlock()
	})

	return l.err
}

// Listen takes the daemon lock before cleaning up a stale socket. The socket
// lives in a 0700 directory and is itself 0600: only this OS user has access.
func Listen() (Listener, error) {
	unlock, err := store.Lock("daemon.lock", true)
	if err != nil {
		return nil, fmt.Errorf("daemon already running or lock unavailable: %w", err)
	}

	ok := false
	defer func() {
		if !ok {
			unlock()
		}
	}()

	path, err := SocketPath()
	if err != nil {
		return nil, err
	}

	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to remove non-socket file at %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}

	if err := os.Chmod(path, 0600); err != nil {
		l.Close()
		return nil, err
	}

	l.SetUnlinkOnClose(false)
	ok = true

	return &listener{UnixListener: l, unlock: unlock, path: path}, nil
}

func Handle(conn net.Conn, load func(string) (map[string]string, error)) {
	HandleControl(conn, load, nil)
}

func HandleControl(conn net.Conn, load func(string) (map[string]string, error), stop func()) {
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := requireSameUID(conn); err != nil {
		return
	}

	var req request

	if err := json.NewDecoder(io.LimitReader(conn, maxRequestSize)).Decode(&req); err != nil {
		return
	}

	var r response

	switch req.Action {
	case "get":
		if req.App == "" {
			r.Error = "app must not be empty"
			break
		}

		secrets, err := load(req.App)
		if err != nil {
			r.Error = err.Error()
		} else {
			r.Secrets = secrets
		}
	case "stop":
		if stop == nil {
			r.Error = "stop not supported"
		} else {
			// This is a stop-request acknowledgment, not a drain-complete or
			// memory-erasure receipt. Final Close releases the lock after drain.
			stop()
		}
	default:
		r.Error = "unknown request action"
	}

	_ = json.NewEncoder(conn).Encode(r)
}

func Stop() error {
	_, err := send(request{Action: "stop"})
	return err
}

func SendRequest(app string) (map[string]string, error) {
	return send(request{Action: "get", App: app})
}

func send(req request) (map[string]string, error) {
	path, err := SocketPath()
	if err != nil {
		return nil, err
	}

	conn, err := net.DialTimeout("unix", path, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := requireSameUID(conn); err != nil {
		return nil, err
	}

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, err
	}

	var r response

	if err := json.NewDecoder(io.LimitReader(conn, limits.ResponseBytes)).Decode(&r); err != nil {
		return nil, err
	}

	if r.Error != "" {
		return nil, fmt.Errorf("daemon: %s", r.Error)
	}

	return r.Secrets, nil
}
