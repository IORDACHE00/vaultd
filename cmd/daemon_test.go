package cmd

import (
	"context"
	"github.com/IORDACHE00/vaultd/internal/ipc"
	"github.com/IORDACHE00/vaultd/internal/store"
	"os"
	"testing"
	"time"
)

func TestDaemonStop(t *testing.T) {
	home, err := os.MkdirTemp("", "vd-")

	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(home)
	t.Setenv("HOME", home)

	if err := store.Initialize("pw"); err != nil {
		t.Fatal(err)
	}

	if err := store.Update("pw", "app", "PORT", "3000"); err != nil {
		t.Fatal(err)
	}

	l, err := ipc.Listen()

	if err != nil {
		t.Fatal(err)
	}

	defer l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveDaemon(ctx, l, "pw") }()
	secrets, err := ipc.SendRequest("app")

	if err != nil || secrets["PORT"] != "3000" {
		t.Fatalf("request: %v %v", secrets, err)
	}

	if err := ipc.Stop(); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not terminate daemon")
	}

	path, _ := ipc.SocketPath()

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("socket not removed: %v", err)
	}

	if err := ipc.Stop(); err == nil {
		t.Fatal("stop with no daemon succeeded")
	}

	l2, err := ipc.Listen()

	if err != nil {
		t.Fatalf("lock not released: %v", err)
	}

	l2.Close()
}
