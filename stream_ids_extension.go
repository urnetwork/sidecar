//go:build ios_extension && !sidecar_http

// The forwarding host uses bridge links and opens no sidecar peer streams.

package sidecar

// The shared dispatcher's default reservation cannot open a stream or touch the host's store.
func reserveStoredStreamIds(store SidecarStore) (uint64, error) {
	return 0, errSubprotocolClosed
}
