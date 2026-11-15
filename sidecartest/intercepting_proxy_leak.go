//go:build sidecar_leaktest

// The intercepting proxy's leak for §22.7's self-test (leak_enabled.go): a value in an HTTPS body an agent sends
// through the proxy, which decrypts it as a cloud sandbox's proxy would, so its capture must catch it.

package sidecartest

import (
	"context"
	"net/http"
	"testing"
)

var _ = RegisterLeak(&Leak{
	Class: PrivacyClassInterceptingProxy,
	// an HTTPS body holds any byte
	Binary: true,
	// inside the request's own text, its line and headers
	Embeds: true,
	Put: func(t testing.TB, net *Net, value []byte) {
		origin, err := NewInterceptingOrigin(nil, "api.cloudagent.example")
		if err != nil {
			t.Fatal(err)
		}
		defer origin.Close()
		settings := DefaultInterceptingProxySettings()
		settings.Dial = origin.Dial
		settings.TargetRoots = origin.Roots()
		proxy, err := NewInterceptingProxy(net.Capture(), settings)
		if err != nil {
			t.Fatal(err)
		}
		defer proxy.Close()
		roots := origin.Roots()
		roots.AddCert(proxy.Certificate())
		ctx, cancel := context.WithTimeout(context.Background(), settings.HandshakeTimeout)
		defer cancel()
		conn, err := proxy.Dial(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if status, _, err := InterceptingProxyRequest(ctx, conn, roots, "api.cloudagent.example", http.MethodPost, "/sidecar/notes", "", value); err != nil || status != http.StatusOK {
			t.Fatalf("the leak's request: %d %v", status, err)
		}
	},
})
