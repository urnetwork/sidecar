//go:build !js && !ios && !android && !windows && !ios_extension

// The daemon's socket on Unix (§5.9): $XDG_RUNTIME_DIR/ur/<i>.sock on Linux, and on macOS under DARWIN_USER_TEMP_DIR,
// $TMPDIR, within the 104-byte sun_path. A path that would not fit, or a system with neither directory, falls back to
// /tmp/ur-<uid>/<i>.sock. The socket's directory is 0700 and the caller's own, and a directory another user owns or
// opened wider is refused rather than used, since the peer check alone would not stop another user's listener
// standing in the path (LOCAL_PEERCRED in a 0700 directory, §5.8).

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
)

// The most bytes of a socket path, sun_path less its NUL: 104 on macOS (§5.9), 108 on Linux.
func daemonSunPathMaxByteCount(goos string) int {
	if goos == "linux" {
		return 107
	}
	return 103
}

// §5.9's socket path for the instance on this system.
func DaemonSocketPath(instance string) (string, error) {
	return daemonSocketPathFor(instance, runtime.GOOS, os.Getenv, os.Getuid())
}

// DaemonSocketPath with its system as arguments, for a test.
func daemonSocketPathFor(instance string, goos string, getEnvironment func(string) string, uid int) (string, error) {
	if !isSidecarInstanceName(instance) {
		return "", errInvalidInstanceName
	}
	name := instance + ".sock"
	fallback := filepath.Join("/tmp", "ur-"+strconv.Itoa(uid), name)
	base := ""
	switch goos {
	case "darwin":
		base = getEnvironment("TMPDIR")
	default:
		base = getEnvironment("XDG_RUNTIME_DIR")
	}
	if base == "" || !filepath.IsAbs(base) {
		return fallback, nil
	}
	socketPath := filepath.Join(base, "ur", name)
	if daemonSunPathMaxByteCount(goos) < len(socketPath) {
		return fallback, nil
	}
	return socketPath, nil
}

// Makes the socket's directory 0700, or checks the one there is the caller's and 0700.
func prepareDaemonSocketDirectory(directory string) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("the socket directory is not a directory")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("the socket directory belongs to another user")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("the socket directory is open to other users")
	}
	return nil
}

// Listens on socketPath, removing a socket a killed daemon left. The caller holds the instance's lock, so no live
// daemon owns the path.
func listenDaemon(socketPath string) (net.Listener, error) {
	if daemonSunPathMaxByteCount(runtime.GOOS) < len(socketPath) {
		return nil, fmt.Errorf("the socket path is past sun_path's %d bytes", daemonSunPathMaxByteCount(runtime.GOOS))
	}
	if err := prepareDaemonSocketDirectory(filepath.Dir(socketPath)); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(socketPath); err == nil {
		if info.Mode().Type() != fs.ModeSocket {
			return nil, fmt.Errorf("something other than a socket is at the socket's path")
		}
		if err := os.Remove(socketPath); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	if unixListener, ok := listener.(*net.UnixListener); ok {
		// the daemon removes its own socket when it stops
		unixListener.SetUnlinkOnClose(true)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}

// Dials the daemon's socket.
func dialDaemon(ctx context.Context, socketPath string) (net.Conn, error) {
	dialer := &net.Dialer{}
	return dialer.DialContext(ctx, "unix", socketPath)
}
