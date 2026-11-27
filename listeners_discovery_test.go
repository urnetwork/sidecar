//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

package sidecar

import (
	"slices"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// The listed set feeds discovery's listed entries (BridgeDiscoveryArgs.Listed): each socket and map entry with its
// description and its label's type, which discovery names "<description> :<port>" where its type is on the list; a
// label's type none keeps its entry out.
func TestListenersListedSetFeedsDiscovery(t *testing.T) {
	tcp := protocol.ListenersProtocol_LISTENERS_PROTOCOL_TCP
	labels := &testListLabels{labels: map[ListenersListedPort]*ListenersLabel{
		{Protocol: tcp, Port: 3000}: {Text: "shop", Type: "_http._tcp"},
		{Protocol: tcp, Port: 8080}: {Text: "secret", Type: ListenersLabelTypeNone},
	}}
	list := testListOf([]*ListenersSocket{
		testListSocket(tcp, "0.0.0.0", 3000, "node"),
		testListSocket(tcp, "0.0.0.0", 8080, "python3"),
		testListSocket(tcp, "0.0.0.0", 8000, "python3"),
	}, labels, DefaultListenersSettings())
	entries := list.Listed.DiscoveryEntries()
	if len(entries) != 3 || entries[0].Protocol != "tcp" || entries[0].Port != 3000 || entries[0].Description != "shop" ||
		entries[0].Type != "_http._tcp" || entries[1].Port != 8000 || entries[1].Type != "" || entries[2].Type != ListenersLabelTypeNone {
		t.Fatalf("entries %+v %+v %+v", *entries[0], *entries[1], *entries[2])
	}
	instances := bridgeDiscoveryListedInstances(entries, []string{"_http._tcp"}, map[string]bool{}, protocol.DefaultDnsSdWireSettings())
	names := []string{}
	for _, instance := range instances {
		names = append(names, instance.GetName())
	}
	if !slices.Equal(names, []string{"shop :3000", "python3 :8000"}) {
		t.Errorf("instances %v", names)
	}
}
