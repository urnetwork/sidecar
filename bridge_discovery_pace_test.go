//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// A viewer's pace toward one host (§17.7.1's call row): a host that answers every watch at once, with a new version
// each time, is asked again no sooner than WatchMinInterval after the last call began, not at its round-trip rate.

package sidecar

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

func TestBridgeDiscoveryViewerPacesAHostThatAnswersAtOnce(t *testing.T) {
	clock := newDiscoveryTestClock()
	net := newDiscoveryTestNet()
	hostId, hostClientId := Id{0xA1}, Id{0xA2}
	host := net.dispatcher(hostId, hostClientId)
	var version atomic.Uint64
	if _, err := host.Handle(protocol.MessageType_DNS_SD_WATCH, func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
		return proto.Marshal(&protocol.DnsSdWatchResult{Version: version.Add(1), Serving: true})
	}, nil); err != nil {
		t.Fatal(err)
	}
	settings := DefaultBridgeDiscoverySettings()
	viewer, err := NewBridgeDiscoveryComponent(&BridgeDiscoveryArgs{
		SidecarId: Id{0xB1},
		Routes: func() *BridgeDiscoveryRoutes {
			return &BridgeDiscoveryRoutes{
				Blocks:    []netip.Prefix{netip.MustParsePrefix("100.80.0.0/16")},
				Addresses: []netip.Addr{netip.MustParseAddr("100.80.1.3")},
				Hosts: []BridgeDiscoveryHost{{
					SidecarId: hostId, ClientId: hostClientId, Name: "host-a",
					Prefixes: []netip.Prefix{netip.MustParsePrefix("100.80.1.2/32")},
				}},
			}
		},
		Viewing:  func() bool { return true },
		Clock:    clock,
		Settings: settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(viewer.Close)
	viewer.loadState(newDiscoveryTestStore())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := viewer.attach(ctx, net.dispatcher(Id{0xB1}, Id{0xB2})); err != nil {
		t.Fatal(err)
	}
	start := clock.Now()
	for i := 1; i <= 3; i += 1 {
		// the call answered at once, and the next waits out the interval from its start
		at := start.Add(time.Duration(i) * settings.WatchMinInterval)
		clock.awaitWaitAt(t, at)
		if calls := net.calls.Value(); calls != i {
			t.Fatalf("%d calls before %v passed, want %d", calls, at.Sub(start), i)
		}
		clock.Advance(settings.WatchMinInterval)
	}
}

// A proxy switch hands the viewer's view out again, unchanged, so the platform's proxy, which reads the switch at each
// view, follows it at once.
func TestBridgeDiscoveryProxySwitchRedeliversTheView(t *testing.T) {
	deliveries := NewMonitorValue(0)
	world := newDiscoveryTestWorldOf(t, &discoveryTestWorldOptions{onView: func(view []*BridgeDiscoveryViewInstance) {
		deliveries.Update(func(count int) int { return count + 1 })
	}})
	world.attach()
	world.awaitView("[Host Files@100.80.1.2:445 Synthetic Printer@192.168.50.20:631]")
	before := deliveries.Value()
	if err := world.viewer.Set(DaemonBridgeDiscoveryProxy, DaemonBridgeDiscoveryOff, false); err != nil {
		t.Fatal(err)
	}
	discoveryTestAwait(t, deliveries, func(count int) bool { return before < count })
	if world.viewer.ProxyOn() {
		t.Fatal("the proxy is on after its switch went off")
	}
	world.awaitView("[Host Files@100.80.1.2:445 Synthetic Printer@192.168.50.20:631]")
}
