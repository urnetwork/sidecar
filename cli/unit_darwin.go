// The macOS host's unit environment: the user's LaunchAgents and gui domain (§5.8). And the gateway's sockets the
// LaunchAgent's Sockets hold (DESIGN-COMPUTE §8.4), which the daemon checks in by launch_activate_socket, reached
// through purego with CGO_ENABLED=0: launchd answers the descriptors in an array the caller frees. A daemon launchd did
// not start, or a LaunchAgent with no gateway socket, takes none.

package main

import (
	"errors"
	"net"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"github.com/ebitengine/purego"

	"github.com/urnetwork/sidecar"
)

// This user's environment for a LaunchAgent.
func hostUnitEnv() (*unitEnv, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return &unitEnv{goos: "darwin", home: home, uid: os.Getuid()}, nil
}

// launchd's check-in and libc's free, loaded once.
type darwinLaunchd struct {
	activateSocket func(name string, fds *uintptr, count *uintptr) int32
	free           func(pointer uintptr)
}

var loadDarwinLaunchd = sync.OnceValues(func() (*darwinLaunchd, error) {
	libSystem, err := purego.Dlopen(darwinLibSystemPath, purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		return nil, err
	}
	self := &darwinLaunchd{}
	purego.RegisterLibFunc(&self.activateSocket, libSystem, "launch_activate_socket")
	purego.RegisterLibFunc(&self.free, libSystem, "free")
	return self, nil
})

// The gateway's sockets launchd holds for this daemon, each made a listener of its own and launchd's descriptor
// closed; none where launchd did not start it (ESRCH) or holds no gateway socket (ENOENT).
func urGatewayInheritedListeners(log sidecar.Logger) []net.Listener {
	launchd, err := loadDarwinLaunchd()
	if err != nil {
		log.Warningf("[gateway]launchd's sockets are not read: %s", err)
		return nil
	}
	fdsPointer := uintptr(0)
	count := uintptr(0)
	code := launchd.activateSocket(unitGatewaySocketName, &fdsPointer, &count)
	if code != 0 {
		if errno := syscall.Errno(code); !errors.Is(errno, syscall.ESRCH) && !errors.Is(errno, syscall.ENOENT) {
			log.Warningf("[gateway]launchd's gateway sockets are not checked in: %s", errno)
		}
		return nil
	}
	if fdsPointer == 0 {
		return nil
	}
	defer launchd.free(fdsPointer)
	fds := unsafe.Slice((*int32)(*(*unsafe.Pointer)(unsafe.Pointer(&fdsPointer))), int(count))
	listeners := []net.Listener{}
	for _, fd := range fds {
		passed := os.NewFile(uintptr(fd), unitGatewaySocketName)
		if passed == nil {
			continue
		}
		listener, err := net.FileListener(passed)
		passed.Close()
		if err != nil {
			log.Warningf("[gateway]a socket launchd holds does not listen: %s", err)
			continue
		}
		listeners = append(listeners, listener)
	}
	return listeners
}
