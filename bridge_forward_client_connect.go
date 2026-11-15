//go:build !sidecar_http

// The connect legs' transport for a VPN component's forwarding client (bridge_forward_client.go): SidecarApi's own,
// dialing only by the component's client strategy, so F's requests bind to the egress interface and resolve names in
// process as every sidecar request does, never through net/http's default transport, whose sockets follow the tunnel's
// default route back into the component.

package sidecar

import (
	"context"
	"net/http"

	"github.com/urnetwork/connect"
)

// The transport a forwarding client takes from strategy, the component's client strategy, until ctx ends.
func NewForwardingTransport(ctx context.Context, strategy *connect.ClientStrategy) http.RoundTripper {
	return newSidecarApiTransport(ctx, strategy)
}
