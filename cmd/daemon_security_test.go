package cmd

import (
	"context"
	"errors"
	"github.com/IORDACHE00/vaultd/internal/ipc"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func privateListener(t *testing.T) ipc.Listener {
	t.Helper()
	home, err := os.MkdirTemp("", "vd-")

	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { os.RemoveAll(home) })
	t.Setenv("HOME", home)
	l, err := ipc.Listen()

	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { l.Close() })
	return l
}

func TestStopClosesClientsButRetainsLockUntilDrain(t *testing.T) {
	l := privateListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	done := make(chan error, 1)
	go func() {
		done <- serveDaemon(ctx, l, "pw", daemonOptions{
			load: func(string) (map[string]string, error) {
				close(started)
				<-release
				return map[string]string{"KEY": "must-not-arrive"}, nil
			},
		})
	}()
	request := make(chan error, 1)
	go func() { _, err := ipc.SendRequest("app"); request <- err }()

	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not enter loader")
	}

	if err := ipc.Stop(); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-request:
		if err == nil {
			t.Fatal("secret response survived stop")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stop left an accepted connection open")
	}

	if other, err := ipc.Listen(); err == nil {
		other.Close()
		t.Fatal("released daemon lock before draining loader")
	}

	select {
	case <-done:
		t.Fatal("server returned before worker drained")
	default:
	}

	releaseOnce.Do(func() { close(release) })

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not drain")
	}

	other, err := ipc.Listen()

	if err != nil {
		t.Fatal(err)
	}

	other.Close()
}

type countingListener struct {
	ipc.Listener
	accepted chan struct{}
}

func (l countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()

	if err == nil {
		l.accepted <- struct{}{}
	}

	return c, err
}

func TestDaemonAdmissionCapAndCancellation(t *testing.T) {
	base := privateListener(t)
	l := countingListener{base, make(chan struct{}, maxDaemonClients+1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveDaemon(ctx, l, "pw") }()
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()

	for i := 0; i < maxDaemonClients; i++ {
		c, err := net.Dial("unix", base.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		select {
		case <-l.accepted:
		case <-time.After(3 * time.Second):
			t.Fatal("accept timeout")
		}
	}

	extra, err := net.Dial("unix", base.Addr().String())

	if err != nil {
		t.Fatal(err)
	}

	defer extra.Close()
	extra.SetReadDeadline(time.Now().Add(2 * time.Second))
	var b [1]byte
	_, err = extra.Read(b[:])

	if err == nil {
		t.Fatal("admitted excess client")
	}

	var timeout net.Error

	if errors.As(err, &timeout) && timeout.Timeout() {
		t.Fatal("excess client was not promptly closed")
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("idle clients prevented cancellation")
	}
}

func TestUnlockExpiryAndReadinessFailure(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "expiry", true: "readiness"}[failure], func(t *testing.T) {
			l := privateListener(t)
			opts := daemonOptions{unlockTimeout: 30 * time.Millisecond}

			if failure {
				opts.ready = func() error { return errors.New("readiness failed") }
			}

			done := make(chan error, 1)
			go func() { done <- serveDaemon(context.Background(), l, "pw", opts) }()

			select {
			case err := <-done:
				if (err != nil) != failure {
					t.Fatalf("unexpected result: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("server failed to shut down")
			}

			other, err := ipc.Listen()

			if err != nil {
				t.Fatal("lifecycle leaked lock")
			}

			other.Close()
		})
	}
}
