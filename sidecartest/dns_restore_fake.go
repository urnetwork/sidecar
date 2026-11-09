// T2's dnsservice.DnsRestoreStore, DnsReadyStore and DnsCanaryVerdictStore (§12.6; DNS-M5-15,
// DNS-M5-17): dns_ns's stopped NS, a restore's lists with each listed network's admin event, and
// dns_canary_verdict's rows, in memory. A test says which label is which network's and which networks
// have an open §21 case, as dns_label and abuse_case would. It holds the lists to the promises the
// model keeps: each RRset once an incident, one admin event a network an incident, flags as the case
// stood at listing. Safe for concurrent use.

package sidecartest

import (
	"context"
	"slices"
	"strings"
	"sync"

	"github.com/miekg/dns"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/dnsservice"
)

// One listed RRset and its incident.
type fakeDnsRestoreEntry struct {
	incidentId sidecar.Id
	entry      dnsservice.DnsRestoreEntry
}

// One admin event a restore wrote: its network and incident.
type FakeDnsRestoreAdminEvent struct {
	NetworkId  sidecar.Id
	IncidentId sidecar.Id
}

// T2's store. See the file header.
type FakeDnsRestoreStore struct {
	clock Clock

	stateLock sync.Mutex
	// Answer ErrDnsNsStateUnavailable to StopNs and StartNs, as the server does until dns_ns exists.
	nsStateUnavailable  bool
	rootStoppedNs       map[string][]string
	rootLabelNetworkIds map[string]map[string]sidecar.Id
	openNetworkIds      map[sidecar.Id]bool
	rootEntries         map[string][]*fakeDnsRestoreEntry
	adminEvents         []FakeDnsRestoreAdminEvent
	rootVerdicts        map[string]map[string]dnsservice.DnsCanaryVerdict
}

var (
	_ dnsservice.DnsRestoreStore       = (*FakeDnsRestoreStore)(nil)
	_ dnsservice.DnsReadyStore         = (*FakeDnsRestoreStore)(nil)
	_ dnsservice.DnsCanaryVerdictStore = (*FakeDnsRestoreStore)(nil)
)

// clock may be nil, for a fresh clock; it stamps list times.
func NewFakeDnsRestoreStore(clock Clock) *FakeDnsRestoreStore {
	if clock == nil {
		clock = NewFakeClock(DefaultClockStart())
	}
	return &FakeDnsRestoreStore{
		clock:               clock,
		rootStoppedNs:       map[string][]string{},
		rootLabelNetworkIds: map[string]map[string]sidecar.Id{},
		openNetworkIds:      map[sidecar.Id]bool{},
		rootEntries:         map[string][]*fakeDnsRestoreEntry{},
		rootVerdicts:        map[string]map[string]dnsservice.DnsCanaryVerdict{},
	}
}

// Makes StopNs and StartNs answer ErrDnsNsStateUnavailable, as dnshost.RestoreStore does until dns_ns
// exists.
func (self *FakeDnsRestoreStore) SetNsStateUnavailable(unavailable bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.nsStateUnavailable = unavailable
}

// Says label in root is networkId's, as a dns_label row would.
func (self *FakeDnsRestoreStore) SetLabel(root string, label string, networkId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	root = dns.CanonicalName(root)
	if self.rootLabelNetworkIds[root] == nil {
		self.rootLabelNetworkIds[root] = map[string]sidecar.Id{}
	}
	self.rootLabelNetworkIds[root][label] = networkId
}

// Opens or closes networkId's §21 case.
func (self *FakeDnsRestoreStore) SetOpenCase(networkId sidecar.Id, open bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.openNetworkIds[networkId] = open
}

// Sets ns stopped or running by hand, as the runbook's ns stop and start do.
func (self *FakeDnsRestoreStore) SetStopped(root string, ns string, stopped bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.setStoppedWithLock(dns.CanonicalName(root), ns, stopped)
}

func (self *FakeDnsRestoreStore) setStoppedWithLock(root string, ns string, stopped bool) {
	stoppedNs := slices.DeleteFunc(self.rootStoppedNs[root], func(stoppedLabel string) bool { return stoppedLabel == ns })
	if stopped {
		stoppedNs = append(stoppedNs, ns)
	}
	self.rootStoppedNs[root] = stoppedNs
}

func (self *FakeDnsRestoreStore) StoppedNs(ctx context.Context, root string) ([]string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.rootStoppedNs[root]), nil
}

func (self *FakeDnsRestoreStore) StopNs(ctx context.Context, root string, ns string, reason string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.nsStateUnavailable {
		return dnsservice.ErrDnsNsStateUnavailable
	}
	self.setStoppedWithLock(root, ns, true)
	return nil
}

func (self *FakeDnsRestoreStore) StartNs(ctx context.Context, root string, ns string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.nsStateUnavailable {
		return dnsservice.ErrDnsNsStateUnavailable
	}
	self.setStoppedWithLock(root, ns, false)
	return nil
}

// The network of the label directly below root that owner sits under, as the model maps it.
func (self *FakeDnsRestoreStore) ownerNetworkWithLock(root string, owner string) (sidecar.Id, bool) {
	rest, ok := strings.CutSuffix(owner, "."+root)
	if !ok || rest == "" {
		return sidecar.Id{}, false
	}
	labels := dns.SplitDomainName(rest + ".")
	networkId, ok := self.rootLabelNetworkIds[root][labels[len(labels)-1]]
	return networkId, ok
}

func (self *FakeDnsRestoreStore) ListRestoreChanges(ctx context.Context, root string, incidentId sidecar.Id, keys []dnsservice.DnsRecordKey) (*dnsservice.DnsRestoreListing, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	listedKeys := map[dnsservice.DnsRecordKey]bool{}
	listedNetworkIds := map[sidecar.Id]bool{}
	for _, entry := range self.rootEntries[root] {
		if entry.incidentId != incidentId {
			continue
		}
		listedKeys[dnsservice.DnsRecordKey{Owner: entry.entry.Owner, Type: entry.entry.Type}] = true
		if entry.entry.NetworkId != nil {
			listedNetworkIds[*entry.entry.NetworkId] = true
		}
	}
	now := self.clock.Now()
	for _, key := range keys {
		if listedKeys[key] {
			continue
		}
		listedKeys[key] = true
		entry := &fakeDnsRestoreEntry{incidentId: incidentId, entry: dnsservice.DnsRestoreEntry{Owner: key.Owner, Type: key.Type, ListTime: now}}
		if networkId, ok := self.ownerNetworkWithLock(root, key.Owner); ok {
			entry.entry.NetworkId = &networkId
			entry.entry.Flagged = self.openNetworkIds[networkId]
			if !listedNetworkIds[networkId] {
				listedNetworkIds[networkId] = true
				self.adminEvents = append(self.adminEvents, FakeDnsRestoreAdminEvent{NetworkId: networkId, IncidentId: incidentId})
			}
		}
		self.rootEntries[root] = append(self.rootEntries[root], entry)
	}
	return self.listingWithLock(root, incidentId), nil
}

// An incident's whole list.
func (self *FakeDnsRestoreStore) listingWithLock(root string, incidentId sidecar.Id) *dnsservice.DnsRestoreListing {
	listing := &dnsservice.DnsRestoreListing{Root: root, IncidentId: incidentId}
	for _, entry := range self.rootEntries[root] {
		if entry.incidentId == incidentId {
			listing.Entries = append(listing.Entries, entry.entry)
		}
	}
	return listing
}

// An incident's whole list, as the incident record holds it.
func (self *FakeDnsRestoreStore) Listing(root string, incidentId sidecar.Id) *dnsservice.DnsRestoreListing {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.listingWithLock(dns.CanonicalName(root), incidentId)
}

// Every admin event a listing wrote, in order.
func (self *FakeDnsRestoreStore) AdminEvents() []FakeDnsRestoreAdminEvent {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.adminEvents)
}

// Keeps a monitor's verdict, one a source, over the last.
func (self *FakeDnsRestoreStore) PutCanaryVerdict(ctx context.Context, root string, verdict dnsservice.DnsCanaryVerdict) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.rootVerdicts[root] == nil {
		self.rootVerdicts[root] = map[string]dnsservice.DnsCanaryVerdict{}
	}
	self.rootVerdicts[root][verdict.Source] = verdict
	return nil
}

func (self *FakeDnsRestoreStore) CanaryVerdicts(ctx context.Context, root string) ([]dnsservice.DnsCanaryVerdict, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	verdicts := []dnsservice.DnsCanaryVerdict{}
	for _, source := range []string{dnsservice.DnsCanarySourceSite, dnsservice.DnsCanarySourceOutside} {
		if verdict, ok := self.rootVerdicts[root][source]; ok {
			verdicts = append(verdicts, verdict)
		}
	}
	return verdicts, nil
}
