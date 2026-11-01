package store

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestWriterCrashHelper(t *testing.T) {
	stage := os.Getenv("VAULTD_WRITER_CRASH_HELPER")
	if stage == "" {
		return
	}

	unlock, err := Lock("write.lock", false)
	if err != nil {
		os.Exit(2)
	}

	defer unlock()
	ops := diskOps()

	pause := func() {
		fmt.Fprintln(os.Stdout, "ready")
		// Parent holds the pipe open without writing, then SIGKILLs us.
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])

		os.Exit(3)
	}

	ops.rename = func(from, to string) error {
		if to == GetVaultFilePath() && stage == "before" {
			pause()
		}

		err := os.Rename(from, to)
		if err == nil && to == GetVaultFilePath() && stage == "after" {
			pause()
		}

		return err
	}

	if err := saveWithOps(SecretsStore{"app": {"KEY": "new"}}, "pw", ops); err != nil {
		os.Exit(4)
	}

	os.Exit(5)
}

// Process death is not a simulated filesystem reboot. This exercises lock
// release, orphan handling and the visibility boundary around rename; physical
// power-loss guarantees still depend on the filesystem and hardware.
func TestKilledWriterBeforeAndAfterRename(t *testing.T) {
	for _, stage := range []string{"before", "after"} {
		t.Run(stage, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())

			if err := Initialize("pw"); err != nil {
				t.Fatal(err)
			}

			if err := Update("pw", "app", "KEY", "old"); err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWriterCrashHelper$")
			child.Env = append(os.Environ(), "VAULTD_WRITER_CRASH_HELPER="+stage)

			input, err := child.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()

			output, err := child.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}

			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = child.Process.Kill(); _ = child.Wait() }()

			ready := make([]byte, len("ready\n"))
			if _, err := io.ReadFull(output, ready); err != nil {
				t.Fatal(err)
			}

			if string(ready) != "ready\n" {
				t.Fatal("writer not at rename boundary")
			}

			if err := child.Process.Kill(); err != nil {
				t.Fatal(err)
			}

			_ = child.Wait()
			s, err := Load("pw")
			want := "old"

			if stage == "after" {
				want = "new"
			}

			if err != nil || s["app"]["KEY"] != want {
				t.Fatalf("primary after crash: %v %v", s, err)
			}

			backup, err := os.ReadFile(BackupFilePath())
			if err != nil {
				t.Fatal(err)
			}

			previous, err := decode(backup, "pw")
			if err != nil || previous["app"]["KEY"] != "old" {
				t.Fatalf("recovery source lost: %v %v", previous, err)
			}

			if err := Update("pw", "app", "KEY", "next"); err != nil {
				t.Fatalf("writer lock/orphan recovery failed: %v", err)
			}
		})
	}
}
