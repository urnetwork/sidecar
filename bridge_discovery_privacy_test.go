//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// §22.7's canaries for discovery (from M6; §17.7.1, owner decision 778): the instance names, TXT values and host names
// a host's gatherer finds reach the viewer's view, which is where they belong, and no log line of either side's, at
// every level, through a host's gathering and publishing, a watch, a viewer's checks and both listings (CC4's logs;
// I-13).

package sidecar_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

func TestBridgeDiscoveryGatheredNamesReachNoLog(t *testing.T) {
	capture := sidecartest.NewPrivacyCapture()
	ownName := capture.CanaryText("discovery instance name")
	ownHost := capture.CanaryText("discovery host name")
	sharedName := capture.CanaryText("discovery instance name")
	sharedHost := capture.CanaryText("discovery host name")
	txtValue := capture.CanaryText("discovery txt value")
	txt := append([]byte{byte(len("model=") + len(txtValue))}, []byte("model="+txtValue)...)
	expires := sidecar.BridgeDiscoveryPrivacyNow.Add(24 * time.Hour)
	own := &sidecar.BridgeDiscoveryGathered{
		Name: ownName, Service: "_smb._tcp", Port: 445, Txt: txt, HostName: ownHost + ".local.",
		Addresses: []netip.Addr{netip.MustParseAddr("192.168.50.2")}, Own: true, Expires: expires,
	}
	shared := &sidecar.BridgeDiscoveryGathered{
		Name: sharedName, Service: "_ipp._tcp", Port: 631, Txt: txt, HostName: sharedHost + ".local.",
		Addresses: []netip.Addr{netip.MustParseAddr("192.168.50.30")}, Expires: expires,
	}
	world := sidecar.NewBridgeDiscoveryPrivacyWorld(t, capture.Logger("discovery"),
		[]string{sidecar.BridgeDiscoveryHostLabel(shared.HostName)}, own, shared)
	world.Attach()
	want := "[" + ownName + "@100.80.1.2:445 " + sharedName + "@192.168.50.30:631]"
	if sharedName < ownName {
		want = "[" + sharedName + "@192.168.50.30:631 " + ownName + "@100.80.1.2:445]"
	}
	world.AwaitView(want)
	// the canaries did reach the view, the TXT with both and the shared device's host label with its instance (an own
	// instance's target is its host's own label), so the scan below is not vacuous
	held := 0
	for _, instance := range world.View() {
		switch {
		case string(instance.Txt) != string(txt):
		case instance.Name == ownName && instance.Own:
			held += 1
		case instance.Name == sharedName && instance.HostLabel == sidecar.BridgeDiscoveryHostLabel(sharedHost):
			held += 1
		}
	}
	if held != 2 {
		t.Fatalf("the view holds %d of the canaried instances", held)
	}
	hostDevices, viewerDevices := world.Devices()
	if len(hostDevices.Published) == 0 || len(viewerDevices.Remote) == 0 {
		t.Fatalf("the listings: host %+v, viewer %+v", hostDevices.Published, viewerDevices.Remote)
	}
	if findings := capture.Scan(); 0 < len(findings) {
		for _, finding := range findings {
			t.Error(finding)
		}
	}
}
