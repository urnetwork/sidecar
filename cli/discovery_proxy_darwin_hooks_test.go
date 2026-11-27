//go:build darwin && !ios && !sdk_mobile_bind && sidecar_testhooks

// The macOS advertising proxy's refusal at its read (discovery_proxy.refused.after), over a fake connection: a refusal
// that lands after an apply read whether mDNSResponder refused an instance is left to the next apply, which its wake
// brings and which withdraws the instance once and counts it, and no apply under the same set registers it again.
// Every event lands on one channel in the order the proxy's goroutine makes it.

package main

import (
	"context"
	"fmt"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/urnetwork/sidecar"
)

func TestDarwinDiscoveryProxyLeavesALateRefusalToTheNextApply(t *testing.T) {
	events := make(chan string, 64)
	connection := newTestDarwinProxyConnection()
	connection.events = events
	proxy := newUrDarwinDiscoveryProxy(context.Background(), nil, defaultUrDiscoveryProxySettings(), func() (urDarwinDnsSdConnection, error) {
		return connection, nil
	}, func(status urDiscoveryProxyStatus) {
		events <- fmt.Sprintf("apply %d %d", status.RegisteredCount, status.RefusedCount)
	})
	defer proxy.Close()
	// each event in turn
	expect := func(wants ...string) {
		t.Helper()
		for _, want := range wants {
			if event := testDarwinDnsSdNext(t, events, want); event != want {
				t.Fatalf("waiting for %q heard %q", want, event)
			}
		}
	}
	// the connection's first apply comes before any set, so no wake of the set's is left behind it
	expect("apply 0 0")
	registrations := []*sidecar.BridgeDiscoveryRegistration{
		testDarwinProxyRegistration("Files", "_smb._tcp", "nas", "host-a", "100.80.128.9", 445, ""),
	}
	proxy.Set(registrations, nil)
	expect("register Files", "apply 1 0")

	// the next apply reads that Files stands, and its refusal lands right after the read
	var armed atomic.Bool
	armed.Store(true)
	sidecar.SetTestHooks(&sidecar.TestHooks{Barrier: func(name string, key string) {
		if name == "discovery_proxy.refused.after" && armed.Swap(false) {
			connection.refuse("Files")
		}
	}})
	defer sidecar.SetTestHooks(nil)
	proxy.poke()
	// that apply keeps Files and registers nothing, publishing it refused; the refusal's wake brings the next, which
	// withdraws it once and counts it
	expect("apply 0 1", "cancel Files", "apply 0 1")
	// another wake under the same set registers nothing
	proxy.poke()
	expect("apply 0 1")
	if count := connection.registerCount("Files"); count != 1 {
		t.Fatalf("Files was registered %d times under one set", count)
	}
	// the set's next change tries it again
	proxy.Set(slices.Clone(registrations), nil)
	expect("register Files", "apply 1 0")
}
