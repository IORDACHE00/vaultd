package ipc

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSocketLifecycle(t *testing.T) {
	home, err := os.MkdirTemp("", "vd-")
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(home)

	t.Setenv("HOME", home)

	path, err := SocketPath()
	if err != nil {
		t.Fatal(err)
	}

	if path != filepath.Join(home, ".vaultd", "daemon.sock") {
		t.Fatalf("unexpected socket path: %s", path)
	}
	// Unexpected regular files are never unlinked as "stale sockets".
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}

	if l, err := Listen(); err == nil {
		l.Close()
		t.Fatal("removed a non-socket file")
	}

	if data, err := os.ReadFile(path); err != nil || string(data) != "keep" {
		t.Fatal("non-socket path was changed")
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	// A stale socket from a crashed daemon can be reclaimed.
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}

	stale.SetUnlinkOnClose(false)
	stale.Close()

	l, err := Listen()
	if err != nil {
		t.Fatal(err)
	}

	defer l.Close()

	if other, err := Listen(); err == nil {
		other.Close()
		t.Fatal("second daemon allowed")
	}

	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("socket permissions: %v %v", info, err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)

		for i := 0; i < 2; i++ {
			conn, err := l.Accept()
			if err != nil {
				return
			}

			Handle(conn, func(app string) (map[string]string, error) {
				if app != "app with spaces" {
					return nil, fmt.Errorf("unknown app")
				}

				return map[string]string{"KEY": "value"}, nil
			})
		}
	}()

	secrets, err := SendRequest("app with spaces")

	if err != nil || secrets["KEY"] != "value" {
		t.Fatalf("request: %v %v", secrets, err)
	}

	if _, err := SendRequest("missing"); err == nil {
		t.Fatal("daemon error not propagated")
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("server hung")
	}

	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("socket not removed: %v", err)
	}

	l2, err := Listen()
	if err != nil {
		t.Fatal(err)
	}

	l2.Close()
}
