//go:build darwin && !ios && !sdk_mobile_bind

// The macOS gatherer end to end over this machine's mDNSResponder, its links the LocalOnly one alone so nothing
// reaches a LAN: a LocalOnly instance of a listed type is browsed, resolved and looked up into a report carrying its
// name, port, TXT, target and address, marked LocalOnly so the host never publishes it; its withdrawal leaves the next
// report; an unlisted type never shows; and the gatherer returns when its context ends.

package main

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

func TestDarwinGathererBrowsesResolvesAndLooksUp(t *testing.T) {
	registrar := testDarwinDnsSdConnection(t)
	service := "_urtest" + testDarwinDnsSdLabel(t, "")[:6] + "._tcp"
	unlisted := "_urtest" + testDarwinDnsSdLabel(t, "")[:6] + "._tcp"
	host := testDarwinDnsSdLabel(t, "urtest-lan-") + ".local."
	name := "Office NAS " + testDarwinDnsSdLabel(t, "")
	records := make(chan error, 2)
	if _, err := registrar.RegisterRecord(darwinDnsSdFlagsUnique, darwinDnsSdInterfaceIndexLocalOnly, host, darwinDnsSdTypeA,
		[]byte{192, 168, 1, 20}, 0, func(err error) { records <- err }); err != nil {
		t.Fatal(err)
	}
	if err := testDarwinDnsSdNext(t, records, "record"); err != nil {
		t.Fatal(err)
	}
	registered := make(chan *darwinDnsSdRegisterReply, 4)
	handle := func(reply *darwinDnsSdRegisterReply) { registered <- reply }
	registration, err := registrar.Register(darwinDnsSdFlagsNoAutoRename, darwinDnsSdInterfaceIndexLocalOnly, name, service, "local.",
		host, 445, []byte("\x07model=x"), handle)
	if err != nil {
		t.Fatal(err)
	}
	testDarwinDnsSdNext(t, registered, "registration")
	if _, err := registrar.Register(darwinDnsSdFlagsNoAutoRename, darwinDnsSdInterfaceIndexLocalOnly, name, unlisted, "local.", host,
		446, nil, handle); err != nil {
		t.Fatal(err)
	}
	testDarwinDnsSdNext(t, registered, "unlisted registration")

	settings := defaultUrDnsSdGatherSettings()
	settings.ReportDelay = time.Millisecond
	gatherer := &urDarwinGatherer{
		settings: settings,
		links:    func() []uint32 { return []uint32{darwinDnsSdInterfaceIndexLocalOnly} },
		connect: func() (urDarwinGatherConnection, error) {
			return newDarwinDnsSdConnection()
		},
		localAddresses: func() []netip.Addr { return nil },
	}
	reports := make(chan []*sidecar.BridgeDiscoveryGathered, 64)
	ctx, cancel := context.WithCancel(context.Background())
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		gatherer.Gather(ctx, []string{service}, func(gathered []*sidecar.BridgeDiscoveryGathered) { reports <- gathered })
	}()
	defer func() {
		cancel()
		testDarwinDnsSdNext(t, returned, "return")
	}()
	var found *sidecar.BridgeDiscoveryGathered
	for found == nil {
		for _, item := range testDarwinDnsSdNext(t, reports, "report") {
			if item.Service != service {
				t.Fatalf("an unlisted type was gathered: %+v", item)
			}
			found = item
		}
	}
	if found.Name != name || found.Port != 445 || string(found.Txt) != "\x07model=x" || found.HostName != host ||
		len(found.Addresses) != 1 || found.Addresses[0] != netip.MustParseAddr("192.168.1.20") || !found.LocalOnly || found.Own ||
		!found.Expires.After(time.Now()) {
		t.Fatalf("gathered %+v", found)
	}
	registrar.Cancel(registration)
	for gone := false; !gone; {
		gone = len(testDarwinDnsSdNext(t, reports, "report after withdrawal")) == 0
	}
}
