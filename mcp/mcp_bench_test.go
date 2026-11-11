//go:build !js && !ios && !android && !sdk_mobile_bind

// BenchmarkMcpCallOverhead: the framework's own cost of one R call, input to shaped result, on the effective
// settings, held to §16.10's 5 ms a call. A benchmark run is the review phase's; go test runs none.

package mcp

import (
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

func BenchmarkMcpCallOverhead(b *testing.B) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	server := newTestMcpServer(newFakeMcpDaemon(), clock)
	catalog := NewMcpCatalog(server.settings.Mcp, clock, nil)
	addTestTools(catalog)
	call := &McpCall{
		Session:   server.newSession(&sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp}),
		NetworkId: sidecar.NewId(),
		Network:   newFakeMcpToolNetwork(&fakeMcpNetwork{}, testToolCredential),
	}
	arguments := []byte(`{"text":"a small result"}`)
	b.ResetTimer()
	started := time.Now()
	for i := 0; i < b.N; i += 1 {
		if _, err := testToolHandle(b, catalog, call, "test_read", arguments); err != nil {
			b.Fatal(err)
		}
	}
	if perCall := time.Since(started) / time.Duration(b.N); 5*time.Millisecond < perCall {
		b.Errorf("%s a call, past §16.10's 5 ms", perCall)
	}
}
