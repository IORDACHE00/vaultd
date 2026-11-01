//go:build linux

package hardening

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Process must run before collecting secrets. RLIMIT_CORE is inherited by run's
// target; PR_SET_DUMPABLE itself is normally reset by exec. Neither protects
// against root or guarantees erasure of Go strings/cipher key schedules.
func Process() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("disable core files: %w", err)
	}

	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("disable process dumpability: %w", err)
	}

	return nil
}
