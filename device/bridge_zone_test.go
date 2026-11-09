// Private names (bridge_zone.go): a name of the table owned and answering its address whatever its case or trailing
// dot, under each zone, while the zone's apex, deeper names, other zones and published names pass; no zone before a
// state; and a new state's names in force at once through the same LocalZone.

package device_test

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/sidecartest"
)

// An IPv4 address as BridgeState.names holds one.
func zoneTestAddress(literal string) uint32 {
	octets := netip.MustParseAddr(literal).As4()
	return uint32(octets[0])<<24 | uint32(octets[1])<<16 | uint32(octets[2])<<8 | uint32(octets[3])
}

// The zone the tests answer from: two clients under the network's zone and an alias zone.
func zoneTestZone() *device.BridgeZone {
	return device.NewBridgeZone(
		map[string]uint32{"laptop": zoneTestAddress("100.80.1.4"), "Build-Box": zoneTestAddress("100.80.1.9")},
		[]string{"acme.ur.example", "Alias.Example."},
		nil,
	)
}

// A name of the table is owned and answers its address for every query type, whatever its case and a trailing dot,
// under each zone, with NameTtl's 60 s.
func TestBridgeZoneAnswersANameOfTheTable(t *testing.T) {
	zone := zoneTestZone()
	cases := []struct {
		host string
		want string
	}{
		{host: "laptop.acme.ur.example", want: "100.80.1.4"},
		{host: "LAPTOP.Acme.UR.example.", want: "100.80.1.4"},
		{host: "build-box.acme.ur.example", want: "100.80.1.9"},
		{host: "laptop.alias.example", want: "100.80.1.4"},
	}
	for _, c := range cases {
		for _, qtype := range []uint16{1, 28, 65, 15, 16} {
			addrs, ttl, owned := zone.Answer(c.host, qtype)
			if !owned || ttl != 60 || !slices.Equal(addrs, []netip.Addr{netip.MustParseAddr(c.want)}) {
				t.Fatalf("%s type %d: %v, ttl %d, owned %v", c.host, qtype, addrs, ttl, owned)
			}
		}
	}
	if zone.NameCount() != 2 {
		t.Fatalf("%d names", zone.NameCount())
	}
}

// Every other name passes: the zone's apex, a name under a client's, another zone, a published name and the root.
func TestBridgeZonePassesOtherNames(t *testing.T) {
	zone := zoneTestZone()
	for _, host := range []string{"acme.ur.example", "www.laptop.acme.ur.example", "laptop.other.example", "app.acme.ur.example", "", "."} {
		if addrs, _, owned := zone.Answer(host, 1); owned || addrs != nil {
			t.Fatalf("%q was owned: %v", host, addrs)
		}
	}
}

// Before a state there is no zone; once a state names clients, its names answer, and the next state's answer through
// the same LocalZone at once.
func TestBridgeLocalZoneFollowsTheState(t *testing.T) {
	log := device.NewBridgeLogFixtureForTest(t)
	log.Base(true)
	log.Tick()
	bridgeBridge, err := device.NewBridge(context.Background(), log.EmptyStore(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bridgeBridge.Close)
	if bridgeBridge.LocalZone() != nil {
		t.Fatal("a zone before any posture")
	}
	if err := bridgeBridge.SetPending(log.Pending()); err != nil {
		t.Fatal(err)
	}
	if bridgeBridge.LocalZone() != nil {
		t.Fatal("a zone while pending")
	}
	rules := (&sidecartest.BridgeRulesFixture{Block: "100.80.0.0/16"}).Bytes()
	state, stateLog := log.State(rules, true)
	state.Names = map[string]uint32{"laptop": zoneTestAddress("100.80.1.4")}
	state.NameZones = []string{"acme.ur.example"}
	if err := bridgeBridge.SetState(state, stateLog); err != nil {
		t.Fatal(err)
	}
	zone := bridgeBridge.LocalZone()
	if zone == nil {
		t.Fatal("no zone with a state")
	}
	if addrs, _, owned := zone.Answer("laptop.acme.ur.example", 1); !owned || addrs[0] != netip.MustParseAddr("100.80.1.4") {
		t.Fatalf("the first state answered %v, %v", addrs, owned)
	}
	log.Tick()
	next, nextLog := log.State(rules, true)
	next.Names = map[string]uint32{"laptop": zoneTestAddress("100.80.2.4"), "desk": zoneTestAddress("100.80.2.5")}
	next.NameZones = []string{"acme.ur.example"}
	if err := bridgeBridge.SetState(next, nextLog); err != nil {
		t.Fatal(err)
	}
	if addrs, _, owned := zone.Answer("laptop.acme.ur.example", 1); !owned || addrs[0] != netip.MustParseAddr("100.80.2.4") {
		t.Fatalf("the next state's name answered %v, %v", addrs, owned)
	}
	if _, _, owned := zone.Answer("desk.acme.ur.example", 1); !owned {
		t.Fatal("the next state's new name did not answer")
	}
	if status := bridgeBridge.Status(); status.NameCount != 2 {
		t.Fatalf("status names %d", status.NameCount)
	}
}
