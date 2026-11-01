package hardening

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestHardeningHelper(t *testing.T) {
	if os.Getenv("VAULTD_HARDENING_HELPER") != "1" {
		return
	}

	if err := Process(); err != nil {
		t.Fatal(err)
	}

	var limit unix.Rlimit

	if err := unix.Getrlimit(unix.RLIMIT_CORE, &limit); err != nil {
		t.Fatal(err)
	}

	if limit.Cur != 0 || limit.Max != 0 {
		t.Fatal("core limit not disabled")
	}

	dumpable, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil || dumpable != 0 {
		t.Fatalf("process remains dumpable: %d %v", dumpable, err)
	}
}

func TestProcessHardeningInSubprocess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHardeningHelper$")
	child.Env = append(os.Environ(), "VAULTD_HARDENING_HELPER=1")

	if out, err := child.CombinedOutput(); err != nil {
		t.Fatalf("hardening: %s %v", out, err)
	}
}
