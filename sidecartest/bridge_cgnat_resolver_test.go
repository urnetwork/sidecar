//go:build !sidecar_http && !ios_extension

// The CGNAT fixture's carrier resolver case (TEST-M8-01; §17.4, D-BRIDGE-12), which closes ledger T4-16: "the CGNAT
// fixture lacks a carrier resolver in the block". The sender's carrier numbers it from the network's own block: its
// interface address, its gateway and its resolver are block addresses. Carved, each keeps the carrier path, the
// resolver for DNS's UDP and TCP both, no exported route covers them, and the overlay still resolves and still carries
// a connection to a host in the same block. The mutant is a platform whose report drops the resolver, which a reading
// of interface subnets alone does (connect.LocalIpv4Networks; §17.4): the block captures the resolver and the case
// fails. BRIDGE-M8-03's T6 form of this case is the tests repo's.

package sidecartest_test

import (
	"bytes"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A host in the block's lower half and a sender, on a world of the test's own.
func cgnatResolverWorld(t *testing.T) (*sidecartest.BridgeNet, *sidecartest.BridgeNetHost, *sidecartest.BridgeNetSender) {
	t.Helper()
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	world := sidecartest.NewBridgeNet(t, net, nil)
	t.Cleanup(world.Close)
	hostDevice := world.AddDevice("host")
	senderDevice := world.AddDevice("sender")
	host := world.StartHost(hostDevice, &sidecartest.BridgeNetHostSettings{Address: netip.MustParseAddr("100.80.7.20")})
	sender := world.StartSender(senderDevice, nil)
	return world, host, sender
}

// Whether the sender's status holds the alarm for a carved address a host is assigned (D-BRIDGE-16).
func cgnatCarvedAddressAlarm(sender *sidecartest.BridgeNetSender) bool {
	return slices.ContainsFunc(sender.Bridge.Status().Alarms, func(alarm device.BridgeAlarm) bool {
		return alarm.Kind == device.BridgeAlarmCarvedAddress
	})
}

// A carrier resolver inside the block keeps its /32 carve-out: DNS to it takes the carrier path over UDP and TCP, no
// exported route covers it, the overlay resolver and a host's overlay address in the same block keep theirs, and a
// connection to the host still carries. Before the carve the block holds the resolver, so the fixture shows the carve.
func TestBridgeCgnatCarrierResolverKeepsItsCarve(t *testing.T) {
	world, host, sender := cgnatResolverWorld(t)
	block := world.Settings().Block
	carrier := sidecartest.DefaultBridgeNetCarrier(block)
	if !netip.MustParsePrefix("100.64.0.0/10").Contains(carrier.Resolver) || !block.Contains(carrier.Resolver) {
		t.Fatalf("the carrier's resolver %s is not shared address space inside the block %s", carrier.Resolver, block)
	}
	if udp, tcp := sender.DnsTakesDefaultRoute(carrier.Resolver); udp || tcp {
		t.Fatal("DNS to an unassigned block address took the default route before the carve: the fixture proves nothing")
	}
	sender.SetCarrier(carrier)
	for _, err := range sender.CarrierErrors(block, carrier) {
		t.Error(err)
	}
	routes := sender.Bridge.Routes()
	if !slices.Contains(routes, netip.PrefixFrom(host.Address, 32)) {
		t.Errorf("the export lost the host's overlay address to the carve: %v", routes)
	}
	if cgnatCarvedAddressAlarm(sender) {
		t.Error("a carrier path on unassigned block addresses raised the carved-address alarm")
	}
	if sender.TakesDefaultRoute(netip.AddrPortFrom(host.Address, host.Upstream.TcpPort())) {
		t.Fatal("the host's overlay address lost its link to the carve")
	}
	conn, err := sender.DialTcp(netip.AddrPortFrom(host.Address, host.Upstream.TcpPort()))
	if err != nil {
		t.Fatalf("the overlay connection beside the carrier path: %v", err)
	}
	payload := []byte("beside the carrier's resolver")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if !host.Upstream.WaitFor(world.Settings().WaitTimeout, func(accepts []sidecartest.BridgeNetAccept, datagrams [][]byte) bool {
		return slices.ContainsFunc(accepts, func(accept sidecartest.BridgeNetAccept) bool { return bytes.Equal(accept.Bytes, payload) })
	}) {
		t.Fatal("the overlay payload never reached the host")
	}
	// the path changes, as a phone leaving the carrier for Wi-Fi: the old resolver is the block's again
	sender.Bridge.SetLocalAddresses([]netip.Addr{})
	if udp, tcp := sender.DnsTakesDefaultRoute(carrier.Resolver); udp || tcp {
		t.Error("the carrier's resolver kept its carve after the path that needed it was gone")
	}
}

// The mutant: a platform report that drops the resolver's carve-out, naming the interface and the gateway alone. The
// case fails on the resolver, for UDP and TCP, and on nothing else.
func TestBridgeCgnatDroppingTheResolverCarveFails(t *testing.T) {
	world, _, sender := cgnatResolverWorld(t)
	block := world.Settings().Block
	carrier := sidecartest.DefaultBridgeNetCarrier(block)
	sender.Bridge.SetLocalAddresses([]netip.Addr{carrier.Interface, carrier.Gateway})
	errs := sender.CarrierErrors(block, carrier)
	text := fmt.Sprint(errs)
	if len(errs) != 2 || !strings.Contains(text, "a UDP query to the carrier's resolver") || !strings.Contains(text, "a TCP query to the carrier's resolver") {
		t.Fatalf("a report without the resolver's carve read %v", errs)
	}
	// and a report that names nothing fails on each address of the path
	sender.Bridge.SetLocalAddresses([]netip.Addr{})
	if errs := sender.CarrierErrors(block, carrier); len(errs) != 4 {
		t.Fatalf("a report with no carve read %v", errs)
	}
	// the honest report on the same sender passes, so the failures above are the missing carves'
	sender.SetCarrier(carrier)
	if errs := sender.CarrierErrors(block, carrier); len(errs) != 0 {
		t.Fatalf("the whole report read %v", errs)
	}
}

// A carrier whose resolver is the very address the overlay's resolver takes, <block>.0.53: the physical path wins it,
// DNS to it leaves by the carrier, and the export leaves it out (§17.4: each local /32 is carved "out of the router's
// table and every exported route"). A carrier whose interface address is a host's overlay address raises the alarm
// that tells an admin to cycle the block (D-BRIDGE-16).
func TestBridgeCgnatCarrierResolverAtTheOverlayResolversAddress(t *testing.T) {
	world, host, sender := cgnatResolverWorld(t)
	block := world.Settings().Block
	overlay := sidecartest.BridgeNetOverlayResolver(block)
	if udp, tcp := sender.DnsTakesDefaultRoute(overlay); udp || tcp {
		t.Fatal("DNS to the overlay resolver took the default route with no carrier")
	}
	if !slices.Contains(sender.Bridge.Routes(), netip.PrefixFrom(overlay, 32)) {
		t.Fatalf("the export holds no overlay resolver: %v", sender.Bridge.Routes())
	}
	carrier := sidecartest.DefaultBridgeNetCarrier(block)
	carrier.Resolver = overlay
	sender.SetCarrier(carrier)
	for _, err := range sender.CarrierErrors(block, carrier) {
		t.Error(err)
	}
	if cgnatCarvedAddressAlarm(sender) {
		t.Error("a carved resolver address no host is assigned raised the carved-address alarm")
	}
	carrier.Interface = host.Address
	sender.SetCarrier(carrier)
	for _, err := range sender.CarrierErrors(block, carrier) {
		t.Error(err)
	}
	if !cgnatCarvedAddressAlarm(sender) {
		t.Error("a carrier interface address that is a host's overlay address raised no alarm")
	}
}
