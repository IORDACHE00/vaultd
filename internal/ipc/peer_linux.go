//go:build linux

package ipc

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// Same UID is the trust boundary, not per-application authentication.
func requireSameUID(conn net.Conn) error {
	c, ok := conn.(syscall.Conn)
	if !ok {
		return fmt.Errorf("connection does not support peer credentials")
	}

	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}

	var peer *unix.Ucred
	var socketErr error

	if err := raw.Control(func(fd uintptr) {
		peer, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return err
	}

	if socketErr != nil {
		return socketErr
	}

	if peer == nil || peer.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("unexpected Unix socket peer UID")
	}

	return nil
}
