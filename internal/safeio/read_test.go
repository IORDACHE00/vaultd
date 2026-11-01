package safeio

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBoundedReads(t *testing.T) {
	for _, text := range []string{"", "abc\n", "abcde"} {
		data, err := Read(strings.NewReader(text), 4)

		if len(text) > 4 {
			if err == nil {
				t.Fatal("oversize stream accepted")
			}

			continue
		}

		if err != nil || string(data) != text {
			t.Fatalf("stream changed: %q %v", data, err)
		}
	}

	if _, err := Read(strings.NewReader("x"), 0); err == nil {
		t.Fatal("invalid limit accepted")
	}

	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("abc\n"), 0600); err != nil {
		t.Fatal(err)
	}

	if data, err := ReadFile(file, 4); err != nil || string(data) != "abc\n" {
		t.Fatalf("file: %q %v", data, err)
	}

	if _, err := ReadFile(file, 3); err == nil {
		t.Fatal("oversize file accepted")
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}

	if _, err := ReadFile(link, 4); err == nil {
		t.Fatal("followed symlink")
	}

	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := ReadFile(fifo, 4); err == nil {
		t.Fatal("accepted FIFO")
	}

	if _, err := ReadFile(dir, 100); err == nil {
		t.Fatal("accepted directory")
	}
}
