//go:build !ios_extension && !sidecar_http && !(linux && !android) && !(darwin && !ios) && !windows

// No discoverer (DESIGN-COMPUTE §26.5's last row, §26.4's devices, R-LSTN-9): iOS and Android show an app no other
// app's sockets, the browser lists nothing, and every leg but desktop Linux, macOS and Windows has no table to read, so
// such a device's list holds its forwards, maps and services alone. Desktop Linux's, macOS's and Windows' discoverers
// are listeners_discover_linux.go's, listeners_discover_darwin.go's and listeners_discover_windows.go's.

package sidecar

// None on this leg: ErrListenersNoDiscovery.
func NewListenersDiscoverer(settings *ListenersSettings) (ListenersDiscoverer, error) {
	return nil, ErrListenersNoDiscovery
}
