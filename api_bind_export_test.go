//go:build !sidecar_http && !js

// The bridge api_bind_sockets_test.go's external test reads a running sidecar's token through, so it can present the
// token the sidecar adopted at another service. Tests only.

package sidecar

// The token sidecar's api client presents now, the one its keychain and connect's holders hold too: "" with no
// generation running.
func SidecarByJwtForTest(sidecar *Sidecar) string {
	return sidecar.sidecarApi.currentByJwt()
}
