//go:build sidecar_http

// The sidecar_http leg's transport: net/http's, which is fetch in the page Worker (§5.4, §18.10).

package sidecar

import (
	"net/http"
)

// What a SidecarApi sends through on this leg. Nothing else here reaches net/http's default
// transport, so no request reaches fetch without passing absoluteUrlTransport.
func defaultSidecarApiTransport() http.RoundTripper {
	return &absoluteUrlTransport{transport: http.DefaultTransport}
}
