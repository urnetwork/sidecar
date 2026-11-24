//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// The advertising proxy's names (Q-BRIDGE-11; owner decision 778): a remote name a local instance holds takes its
// host's suffix and gives the name back when the local one goes; two remote instances of one name both take theirs;
// the same device seen on the LAN is never registered twice; a suffixed name fits 63 octets.

package sidecar

import (
	"slices"
	"strings"
	"testing"
)

func TestBridgeDiscoveryRegistrationsName(t *testing.T) {
	remote := func(name string, host string, label string) *BridgeDiscoveryViewInstance {
		return &BridgeDiscoveryViewInstance{Name: name, Service: "_smb._tcp", HostLabel: label, HostName: host}
	}
	names := func(registrations []*BridgeDiscoveryRegistration) []string {
		out := []string{}
		for _, registration := range registrations {
			out = append(out, registration.Name+"@"+registration.Target)
		}
		slices.Sort(out)
		return out
	}
	view := []*BridgeDiscoveryViewInstance{
		remote("Files", "host-a", "nas"),
		remote("Files", "host-b", "nas2"),
		remote("Photos", "host-a", "nas"),
		remote("Printer Share", "host-a", "printer"),
	}
	local := []*BridgeDiscoveryGathered{
		{Name: "photos", Service: "_SMB._tcp", HostName: "Desk.local."},
		{Name: "Printer Share", Service: "_smb._tcp", HostName: "Printer.local."},
		{Name: "Files", Service: "_smb._tcp", HostName: "proxy.local.", LocalOnly: true},
	}
	got := names(BridgeDiscoveryRegistrations(view, local, 63))
	want := []string{"Files (host-a)@nas.host-a", "Files (host-b)@nas2.host-b", "Photos (host-a)@nas.host-a"}
	if !slices.Equal(got, want) {
		t.Fatalf("registered %v\nwant %v", got, want)
	}
	// the local photos share goes, and the remote one takes its name back
	got = names(BridgeDiscoveryRegistrations(view, local[1:], 63))
	if !slices.Contains(got, "Photos@nas.host-a") {
		t.Fatalf("the name was not given back: %v", got)
	}
	long := strings.Repeat("ü", 40)
	suffixed := bridgeDiscoverySuffixedName(long, "host-a", 63)
	if 63 < len(suffixed) || !strings.HasSuffix(suffixed, " (host-a)") || !strings.HasPrefix(suffixed, "ü") {
		t.Fatalf("a cut name %q of %d octets", suffixed, len(suffixed))
	}
}
