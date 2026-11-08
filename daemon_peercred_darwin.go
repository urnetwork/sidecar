//go:build darwin && !ios && !sdk_mobile_bind

// The peer check on macOS (§5.8): LOCAL_PEERCRED's uid must be the daemon's own, the socket sitting in a 0700
// directory besides. Same-user agents may call it (owner decision 47); no other uid may.

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
	var xucred *unix.Xucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		xucred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return err
	}
	if credErr != nil {
		return credErr
	}
	return checkDaemonPeerUid(int(xucred.Uid), os.Getuid())
}

// Refuses a peer uid other than the daemon's.
func checkDaemonPeerUid(peerUid int, uid int) error {
	if peerUid != uid {
		return fmt.Errorf("a peer of another uid")
	}
	return nil
}
