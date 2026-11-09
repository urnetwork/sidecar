//go:build linux && !android && !sdk_mobile_bind

// The peer check on Linux (§5.8): SO_PEERCRED's uid must be the daemon's own. Same-user agents may call it (owner
// decision 47); no other uid may.

package sidecar

import (
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// Refuses a peer whose uid is not this process's, or whose uid cannot be read.
func checkDaemonPeer(conn net.Conn) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("not a unix socket")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return err
	}
	var ucred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		ucred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if credErr != nil {
		return credErr
	}
	return checkDaemonPeerUid(int(ucred.Uid), os.Getuid())
}

// Refuses a peer uid other than the daemon's.
func checkDaemonPeerUid(peerUid int, uid int) error {
	if peerUid != uid {
		return fmt.Errorf("a peer of another uid")
	}
	return nil
}
