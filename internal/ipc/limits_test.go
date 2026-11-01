package ipc

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/IORDACHE00/vaultd/internal/limits"
)

func TestOversizedResponseFailsClosed(t *testing.T) {
	home, err := os.MkdirTemp("", "vd-")
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(home)

	t.Setenv("HOME", home)

	l, err := Listen()
	if err != nil {
		t.Fatal(err)
	}

	defer l.Close()

	done := make(chan struct{})

	go func() {
		defer close(done)

		conn, err := l.Accept()
		if err != nil {
			return
		}

		defer conn.Close()

		conn.SetDeadline(time.Now().Add(5 * time.Second))

		var req request

		if err := json.NewDecoder(conn).Decode(&req); err != nil {
			return
		}

		json.NewEncoder(conn).Encode(response{Secrets: map[string]string{"KEY": strings.Repeat("x", int(limits.ResponseBytes)+1)}})
	}()

	if secrets, err := SendRequest("app"); err == nil || secrets != nil {
		t.Fatal("accepted oversized/partial response")
	}

	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("response server stuck")
	}
}
