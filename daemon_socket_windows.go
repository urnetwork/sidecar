//go:build windows

// The daemon's named pipe on Windows (§5.9): \\.\pipe\urnetwork-ur-<sid>-<i>, through go-winio, with a DACL that
// grants the user's SID alone, so no other account can open it (§5.8). The pipe carries the same hello and protocol
// as a Unix socket.

package sidecar

import (
	"context"
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// The user's SID, as the pipe's name and DACL name it.
func daemonUserSid() (string, error) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String(), nil
}

// §5.9's pipe path for the instance.
func DaemonSocketPath(instance string) (string, error) {
	if !isSidecarInstanceName(instance) {
		return "", errInvalidInstanceName
	}
	sid, err := daemonUserSid()
	if err != nil {
		return "", err
	}
	return daemonPipePath(sid, instance), nil
}

// The pipe path of a user's instance.
func daemonPipePath(sid string, instance string) string {
	return `\\.\pipe\urnetwork-ur-` + sid + "-" + instance
}

// Listens on the pipe, its DACL granting the user's SID alone: protected (P), so no inherited entry widens it.
func listenDaemon(socketPath string) (net.Listener, error) {
	sid, err := daemonUserSid()
	if err != nil {
		return nil, err
	}
	return winio.ListenPipe(socketPath, &winio.PipeConfig{
		SecurityDescriptor: fmt.Sprintf("D:P(A;;GA;;;%s)", sid),
	})
}

// Dials the daemon's pipe.
func dialDaemon(ctx context.Context, socketPath string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, socketPath)
}
