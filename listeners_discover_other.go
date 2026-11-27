//go:build !ios_extension && !sidecar_http && !(linux && !android)

// No discoverer (DESIGN-COMPUTE §26.5's last row, §26.4's devices, R-LSTN-9): iOS and Android show an app no other
// app's sockets, the browser lists nothing, and every leg but desktop Linux, macOS and Windows has no table to read, so
// such a device's list holds its forwards, maps and services alone. macOS's and Windows' discoverers are LSTN-M13-03's;
// until they land those desktops list no sockets either.

package sidecar

// None on this leg: ErrListenersNoDiscovery.
func NewListenersDiscoverer(settings *ListenersSettings) (ListenersDiscoverer, error) {
	return nil, ErrListenersNoDiscovery
}
