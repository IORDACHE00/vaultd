package ipc

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestCrashHelper(t *testing.T) {
	if os.Getenv("VAULTD_IPC_CRASH_HELPER") != "1" {
		return
	}

	l, err := Listen()
	if err != nil {
		os.Exit(2)
	}

	defer l.Close()
	fmt.Fprintln(os.Stdout, "ready")

	for {
		conn, err := l.Accept()
		if err != nil {
			os.Exit(3)
		}
		conn.Close()
	}
}

func TestKilledDaemonReclaimsSocketAndLock(t *testing.T) {
	home, err := os.MkdirTemp("", "vd-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(home)

	t.Setenv("HOME", home)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCrashHelper$")
	child.Env = append(os.Environ(), "VAULTD_IPC_CRASH_HELPER=1")
	stdout, err := child.StdoutPipe()

	if err != nil {
		t.Fatal(err)
	}

	if err := child.Start(); err != nil {
		t.Fatal(err)
	}

	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()

	ready := make([]byte, len("ready\n"))
	if _, err := io.ReadFull(stdout, ready); err != nil {
		t.Fatal(err)
	}

	if string(ready) != "ready\n" {
		t.Fatal("helper not ready")
	}

	if l, err := Listen(); err == nil {
		l.Close()
		t.Fatal("live daemon lock was bypassed")
	}

	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}

	_ = child.Wait()
	path, err := SocketPath()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected crash to leave socket: %v", err)
	}

	l, err := Listen()
	if err != nil {
		t.Fatalf("crash recovery failed: %v", err)
	}

	l.Close()
}
