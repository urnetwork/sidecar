// The conformance suite for dnsservice.DnsRestoreStore (§12.6; DNS-M5-15): what restore.go declares,
// run on FakeDnsRestoreStore here and on dnshost.RestoreStore in server, so the fake stays honest
// (D-TEST-2). The facts a listing reads, a network's label and its open §21 case, are set up each
// store's own way through the subject, and every case runs on a root of its own.
//
// dns_ns waits for its §2.8 row, so the suite takes either answer to StopNs: the stopped NS read back
// and started again, or ErrDnsNsStateUnavailable with nothing kept, as plan-DNS-running-ns's interim
// has the real store answer.

package sidecartest

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/miekg/dns"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/dnsservice"
)

// What the suite needs of a store's world beyond the interface.
type DnsRestoreStoreSubject struct {
	Store dnsservice.DnsRestoreStore
	// A root the store knows, a fresh one each call.
	NewRoot func(ctx context.Context) (string, error)
	// A network with a label in root.
	NewNetwork func(ctx context.Context, root string) (label string, networkId sidecar.Id, err error)
	// Opens a §21 case on the network.
	OpenCase func(ctx context.Context, networkId sidecar.Id) error
	// How many admin events the store wrote for the network naming the incident.
	AdminEventCount func(ctx context.Context, networkId sidecar.Id, incidentId sidecar.Id) (int, error)
}

type dnsRestoreSuiteCase struct {
	name string
	run  func(ctx context.Context, subject *DnsRestoreStoreSubject, root string) error
}

// Runs every case on subject, each on a fresh root. t is a TB so a server test env's attempt can run it.
func RunDnsRestoreStoreSuite(t testing.TB, subject *DnsRestoreStoreSubject) {
	t.Helper()
	for _, suiteCase := range dnsRestoreSuiteCases() {
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), dnsSuiteCaseTimeout)
			defer cancel()
			root, err := subject.NewRoot(ctx)
			if err != nil {
				t.Errorf("%s: %v", suiteCase.name, err)
				return
			}
			if err := suiteCase.run(ctx, subject, root); err != nil {
				t.Errorf("%s: %v", suiteCase.name, err)
			}
		}()
	}
}

func dnsRestoreSuiteCases() []dnsRestoreSuiteCase {
	return []dnsRestoreSuiteCase{
		{name: "each RRset is listed once an incident, by its network", run: caseDnsRestoreListsOnce},
		{name: "a network with an open case is flagged, and another is not", run: caseDnsRestoreFlags},
		{name: "a network gets one admin event an incident", run: caseDnsRestoreAdminEvents},
		{name: "a stopped NS reads back until started, or none is kept", run: caseDnsRestoreNsState},
	}
}

// The listing's entry at owner and type, or nil.
func dnsRestoreSuiteEntry(listing *dnsservice.DnsRestoreListing, owner string, rrType uint16) *dnsservice.DnsRestoreEntry {
	for index := range listing.Entries {
		if listing.Entries[index].Owner == owner && listing.Entries[index].Type == rrType {
			return &listing.Entries[index]
		}
	}
	return nil
}

func caseDnsRestoreListsOnce(ctx context.Context, subject *DnsRestoreStoreSubject, root string) error {
	label, networkId, err := subject.NewNetwork(ctx, root)
	if err != nil {
		return err
	}
	incidentId := sidecar.NewId()
	www := dnsservice.DnsRecordKey{Owner: "www." + label + "." + root, Type: dns.TypeA}
	own := dnsservice.DnsRecordKey{Owner: root, Type: dns.TypeTXT}
	listing, err := subject.Store.ListRestoreChanges(ctx, root, incidentId, []dnsservice.DnsRecordKey{www, own, www})
	if err != nil {
		return err
	}
	if len(listing.Entries) != 2 || listing.IncidentId != incidentId {
		return fmt.Errorf("listed %+v", listing)
	}
	if entry := dnsRestoreSuiteEntry(listing, www.Owner, www.Type); entry == nil || entry.NetworkId == nil || *entry.NetworkId != networkId {
		return fmt.Errorf("the network's RRset %+v", entry)
	}
	if entry := dnsRestoreSuiteEntry(listing, own.Owner, own.Type); entry == nil || entry.NetworkId != nil {
		return fmt.Errorf("the root's own RRset %+v", entry)
	}
	again, err := subject.Store.ListRestoreChanges(ctx, root, incidentId, []dnsservice.DnsRecordKey{www, {Owner: "mx." + label + "." + root, Type: dns.TypeAAAA}})
	if err != nil {
		return err
	}
	if len(again.Entries) != 3 {
		return fmt.Errorf("a second listing holds %d", len(again.Entries))
	}
	other, err := subject.Store.ListRestoreChanges(ctx, root, sidecar.NewId(), []dnsservice.DnsRecordKey{www})
	if err != nil || len(other.Entries) != 1 {
		return fmt.Errorf("another incident %+v %v", other, err)
	}
	return nil
}

func caseDnsRestoreFlags(ctx context.Context, subject *DnsRestoreStoreSubject, root string) error {
	flaggedLabel, flaggedNetworkId, err := subject.NewNetwork(ctx, root)
	if err != nil {
		return err
	}
	otherLabel, _, err := subject.NewNetwork(ctx, root)
	if err != nil {
		return err
	}
	if err := subject.OpenCase(ctx, flaggedNetworkId); err != nil {
		return err
	}
	flagged := dnsservice.DnsRecordKey{Owner: flaggedLabel + "." + root, Type: dns.TypeMX}
	other := dnsservice.DnsRecordKey{Owner: otherLabel + "." + root, Type: dns.TypeMX}
	listing, err := subject.Store.ListRestoreChanges(ctx, root, sidecar.NewId(), []dnsservice.DnsRecordKey{flagged, other})
	if err != nil {
		return err
	}
	if entry := dnsRestoreSuiteEntry(listing, flagged.Owner, flagged.Type); entry == nil || !entry.Flagged {
		return fmt.Errorf("the open case's network %+v", entry)
	}
	if entry := dnsRestoreSuiteEntry(listing, other.Owner, other.Type); entry == nil || entry.Flagged {
		return fmt.Errorf("the other network %+v", entry)
	}
	return nil
}

func caseDnsRestoreAdminEvents(ctx context.Context, subject *DnsRestoreStoreSubject, root string) error {
	label, networkId, err := subject.NewNetwork(ctx, root)
	if err != nil {
		return err
	}
	incidentId := sidecar.NewId()
	for _, owner := range []string{"a.", "b.", "a."} {
		key := dnsservice.DnsRecordKey{Owner: owner + label + "." + root, Type: dns.TypeTXT}
		if _, err := subject.Store.ListRestoreChanges(ctx, root, incidentId, []dnsservice.DnsRecordKey{key}); err != nil {
			return err
		}
	}
	if count, err := subject.AdminEventCount(ctx, networkId, incidentId); err != nil || count != 1 {
		return fmt.Errorf("%d events for one incident %v", count, err)
	}
	secondId := sidecar.NewId()
	if _, err := subject.Store.ListRestoreChanges(ctx, root, secondId, []dnsservice.DnsRecordKey{{Owner: "a." + label + "." + root, Type: dns.TypeTXT}}); err != nil {
		return err
	}
	if count, err := subject.AdminEventCount(ctx, networkId, secondId); err != nil || count != 1 {
		return fmt.Errorf("%d events for a second incident %v", count, err)
	}
	return nil
}

func caseDnsRestoreNsState(ctx context.Context, subject *DnsRestoreStoreSubject, root string) error {
	err := subject.Store.StopNs(ctx, root, "ns2", dnsservice.DnsNsStoppedNoSoa)
	stopped, readErr := subject.Store.StoppedNs(ctx, root)
	if readErr != nil {
		return readErr
	}
	if errors.Is(err, dnsservice.ErrDnsNsStateUnavailable) {
		if len(stopped) != 0 {
			return fmt.Errorf("no state kept, yet %v stopped", stopped)
		}
		if err := subject.Store.StartNs(ctx, root, "ns2"); !errors.Is(err, dnsservice.ErrDnsNsStateUnavailable) {
			return fmt.Errorf("start with no state kept: %v", err)
		}
		return nil
	}
	if err != nil {
		return err
	}
	if len(stopped) != 1 || stopped[0] != "ns2" {
		return fmt.Errorf("stopped %v", stopped)
	}
	if err := subject.Store.StartNs(ctx, root, "ns2"); err != nil {
		return err
	}
	if stopped, err := subject.Store.StoppedNs(ctx, root); err != nil || len(stopped) != 0 {
		return fmt.Errorf("after start %v %v", stopped, err)
	}
	return nil
}
