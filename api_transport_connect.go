//go:build !sidecar_http

// The connect legs' transport for SidecarApi (§5.4): net/http, dialing only by a client strategy's
// ConnectSettings().DialContext (connect/net_http.go:777, connect/net.go:232). Never net/http's
// default transport, whose unbound sockets and OS name resolution follow a tunnel's default route
// back into this process (connect/net_http.go's comment on HttpPostStreamWithStrategyRaw): the
// strategy's dial binds the socket to the egress interface, resolves names in-process, and takes
// its ProxySettings, so C8's proxy support (M4) reaches api dials with no change here.

package sidecar

import (
	"context"
	"net/http"

	"github.com/urnetwork/connect"
)

// Refuses every request, closing its body as http.RoundTripper requires: a connect leg has no
// transport until the core installs its client strategy's, and never falls back to net/http's.
type noSidecarApiTransport struct{}

// Refuses the request, sending nothing.
func (self noSidecarApiTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Body != nil {
		request.Body.Close()
	}
	return nil, errSidecarApiNoTransport
}

// What a SidecarApi sends through on a connect leg before the core installs a strategy's transport:
// nothing.
func defaultSidecarApiTransport() http.RoundTripper {
	return &absoluteUrlTransport{transport: noSidecarApiTransport{}}
}

// The transport a SidecarApi takes from strategy, the client strategy its sidecar dials with, until
// ctx ends. It keeps strategy's TLS roots and timeouts, never takes the environment's proxy, and
// drops its idle connections when the host's network changes or memory runs short, as the
// strategy's own pools do, since a pooled socket is bound to the old path.
func newSidecarApiTransport(ctx context.Context, strategy *connect.ClientStrategy) http.RoundTripper {
	connectSettings := strategy.ConnectSettings()
	transport := &http.Transport{
		// nil: no proxy from the environment, which would skip the egress binding
		Proxy:               nil,
		DialContext:         connectSettings.DialContext,
		TLSHandshakeTimeout: connectSettings.TlsTimeout,
		IdleConnTimeout:     connectSettings.IdleConnTimeout,
		ForceAttemptHTTP2:   true,
		// connect's progress bound for native HTTP/2 (connect/net_http.go's nativeHttp2Config)
		HTTP2: &http.HTTP2Config{
			WriteByteTimeout: connectSettings.ConnectTimeout,
		},
	}
	if connectSettings.TlsConfig != nil {
		// a clone shares the session cache, so a re-dial resumes (connect/net_tls.go)
		transport.TLSClientConfig = connectSettings.TlsConfig.Clone()
	}
	unsubNetworkChange := connect.AddNetworkChangeListener(transport.CloseIdleConnections)
	unsubMemoryShed := connect.AddMemoryShedder(transport.CloseIdleConnections)
	go connect.HandleError(func() {
		<-ctx.Done()
		unsubNetworkChange()
		unsubMemoryShed()
		transport.CloseIdleConnections()
	})
	return &absoluteUrlTransport{transport: transport}
}
