// T2's dnsservice.DnsCustomHostMapStore (§13.4; DNS-M6-03): the custom-host map's versions, each lb
// interface's report, and the custom hosts' readiness, in memory. A test sets the versions and the hosts'
// map versions as the model's raise would; polls, reports and route probes go through the same pure functions
// the real store applies (dnsservice.ApplyDnsMapPoll, ApplyDnsMapReport, ApplyDnsRouteProbes), so the fake and
// dnshost.CustomHostMaps differ only in where they keep the rows. Safe for concurrent use.

package sidecartest

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/dnsservice"
)

// T2's store. See the file header. It is also the restore step's map half (dnsservice.DnsRestoreMapStore), keeping
// each incident's raised version and its listed hosts as the model does.
type FakeDnsCustomHostMapStore struct {
	stateLock sync.Mutex
	versions  []dnsservice.DnsMapVersion
	// the newest version's hosts
	hosts      []string
	interfaces map[string]*dnsservice.DnsMapInterface
	// each active custom host's map version
	hostVersions map[string]uint64
	// each host's ready time, unset while not ready
	hostReadyTimes map[string]time.Time
	// each incident's raised version, and the hosts it listed
	incidentVersions map[sidecar.Id]uint64
	incidentEntries  map[sidecar.Id][]dnsservice.DnsRestoreEntry
	// each host's network, as a row or a verified domain names it, for a listing
	hostNetworkIds map[string]sidecar.Id
	// the networks each incident wrote an admin event for, in order
	incidentEventNetworkIds map[sidecar.Id][]sidecar.Id
	// called with the version once a restore's raise has made it, as lbmap would then load it
	restoreRaiseHook func(version uint64)
	// reads of the state, which a test waits on to know a reader has reached its wait
	stateReads *sidecar.MonitorValue[int]
}

// How many times the state was read, and a channel that closes at the next read.
func (self *FakeDnsCustomHostMapStore) StateReads() (int, chan struct{}) {
	return self.stateReads.Get()
}

// Calls hook with the version once a restore's raise has made it, outside the store's lock, before the raise
// returns: where a test reports lbmap's load of the restored map.
func (self *FakeDnsCustomHostMapStore) SetRestoreRaiseHook(hook func(version uint64)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.restoreRaiseHook = hook
}

var (
	_ dnsservice.DnsCustomHostMapStore = (*FakeDnsCustomHostMapStore)(nil)
	_ dnsservice.DnsRestoreMapStore    = (*FakeDnsCustomHostMapStore)(nil)
)

// An empty store: no version, no interface, no host.
func NewFakeDnsCustomHostMapStore() *FakeDnsCustomHostMapStore {
	return &FakeDnsCustomHostMapStore{
		interfaces:              map[string]*dnsservice.DnsMapInterface{},
		hostVersions:            map[string]uint64{},
		hostReadyTimes:          map[string]time.Time{},
		incidentVersions:        map[sidecar.Id]uint64{},
		incidentEntries:         map[sidecar.Id][]dnsservice.DnsRestoreEntry{},
		hostNetworkIds:          map[string]sidecar.Id{},
		incidentEventNetworkIds: map[sidecar.Id][]sidecar.Id{},
		stateReads:              sidecar.NewMonitorValue(0),
	}
}

// Says which network host is under, as its row or a verified domain does, for a restore's listing.
func (self *FakeDnsCustomHostMapStore) SetHostNetwork(host string, networkId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.hostNetworkIds[host] = networkId
}

// Each host's map version, and the networks an incident wrote an admin event for.
func (self *FakeDnsCustomHostMapStore) HostVersion(host string) uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.hostVersions[host]
}

// The networks the incident wrote an admin event for, in the order it wrote them.
func (self *FakeDnsCustomHostMapStore) IncidentEventNetworks(incidentId sidecar.Id) []sidecar.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.incidentEventNetworkIds[incidentId])
}

// Raises the map 2^24 above the newest of the counter, every host's map version and every reported version, as
// the model does, once an incident.
func (self *FakeDnsCustomHostMapStore) RaiseCustomHostMapForRestore(ctx context.Context, root string, incidentId sidecar.Id) (uint64, error) {
	version, raised, hook := self.raiseForRestore(incidentId)
	if raised && hook != nil {
		hook(version)
	}
	return version, nil
}

// The raise's work under the lock: the version, whether this call made it, and the hook to call.
func (self *FakeDnsCustomHostMapStore) raiseForRestore(incidentId sidecar.Id) (uint64, bool, func(version uint64)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if version, ok := self.incidentVersions[incidentId]; ok {
		return version, false, nil
	}
	base := uint64(0)
	for _, version := range self.versions {
		base = max(base, version.Version)
	}
	for _, version := range self.hostVersions {
		base = max(base, version)
	}
	for _, lbInterface := range self.interfaces {
		base = max(base, lbInterface.ReportedVersion)
	}
	version := base + dnsservice.DnsRestoreSerialJump
	self.versions = append(self.versions, dnsservice.DnsMapVersion{Version: version, Digest: dnsservice.DnsCustomHostMapDigest(self.hosts), CreateTime: time.Now()})
	for host := range self.hostVersions {
		self.hostVersions[host] = version
		delete(self.hostReadyTimes, host)
	}
	self.incidentVersions[incidentId] = version
	return version, true, self.restoreRaiseHook
}

// Lists each host not yet listed under the incident, with one admin event a network the incident lists first.
func (self *FakeDnsCustomHostMapStore) ListRestoreCustomHosts(ctx context.Context, root string, incidentId sidecar.Id, added []string, dropped []string) (*dnsservice.DnsRestoreListing, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entries := self.incidentEntries[incidentId]
	listed := func(host string, change string) bool {
		return slices.ContainsFunc(entries, func(entry dnsservice.DnsRestoreEntry) bool {
			return entry.CustomHost == host && entry.CustomHostChange == change
		})
	}
	list := func(hosts []string, change string) {
		for _, host := range hosts {
			if listed(host, change) {
				continue
			}
			entry := dnsservice.DnsRestoreEntry{CustomHost: host, CustomHostChange: change, ListTime: time.Now()}
			if networkId, ok := self.hostNetworkIds[host]; ok {
				entry.NetworkId = &networkId
				if !slices.Contains(self.incidentEventNetworkIds[incidentId], networkId) {
					self.incidentEventNetworkIds[incidentId] = append(self.incidentEventNetworkIds[incidentId], networkId)
				}
			}
			entries = append(entries, entry)
		}
	}
	list(added, dnsservice.DnsRestoreCustomHostAdded)
	list(dropped, dnsservice.DnsRestoreCustomHostDropped)
	self.incidentEntries[incidentId] = entries
	return &dnsservice.DnsRestoreListing{Root: root, IncidentId: incidentId, Entries: slices.Clone(entries)}, nil
}

// Adds version, the newest, with hosts, created at createTime, as the model's raise does: each host not in
// the map yet enters with this version as its map version and no ready time, and a host the map drops leaves.
func (self *FakeDnsCustomHostMapStore) Raise(version uint64, hosts []string, createTime time.Time) string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	digest := dnsservice.DnsCustomHostMapDigest(hosts)
	self.versions = append(self.versions, dnsservice.DnsMapVersion{Version: version, Digest: digest, CreateTime: createTime})
	self.hosts = slices.Sorted(slices.Values(hosts))
	for _, host := range hosts {
		if _, ok := self.hostVersions[host]; !ok {
			self.hostVersions[host] = version
		}
	}
	for host := range self.hostVersions {
		if !slices.Contains(hosts, host) {
			delete(self.hostVersions, host)
			delete(self.hostReadyTimes, host)
		}
	}
	return digest
}

// Whether host is ready, and since when.
func (self *FakeDnsCustomHostMapStore) Ready(host string) (time.Time, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	readyTime, ok := self.hostReadyTimes[host]
	return readyTime, ok
}

// The interface's row as it stands, nil for none.
func (self *FakeDnsCustomHostMapStore) Interface(name string) *dnsservice.DnsMapInterface {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	lbInterface, ok := self.interfaces[name]
	if !ok {
		return nil
	}
	return lbInterface.Clone()
}

// The newest version with its hosts, nil before any.
func (self *FakeDnsCustomHostMapStore) CustomHostMap(ctx context.Context, root string) (*dnsservice.DnsCustomHostMap, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if len(self.versions) == 0 {
		return nil, nil
	}
	newest := self.versions[len(self.versions)-1]
	return &dnsservice.DnsCustomHostMap{Format: dnsservice.DnsFormat, Version: newest.Version, Digest: newest.Digest, Hosts: slices.Clone(self.hosts)}, nil
}

// Every version, every interface row in name order, and the hosts' distinct versions.
func (self *FakeDnsCustomHostMapStore) CustomHostMapState(ctx context.Context, root string) (*dnsservice.DnsMapState, error) {
	defer self.stateReads.Update(func(count int) int { return count + 1 })
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	state := &dnsservice.DnsMapState{Versions: slices.Clone(self.versions)}
	names := []string{}
	for name := range self.interfaces {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		state.Interfaces = append(state.Interfaces, self.interfaces[name].Clone())
	}
	for _, version := range self.hostVersions {
		if version != 0 && !slices.Contains(state.HostVersions, version) {
			state.HostVersions = append(state.HostVersions, version)
		}
	}
	slices.Sort(state.HostVersions)
	return state, nil
}

// The interface's row, added where there is none. Called with the lock held.
func (self *FakeDnsCustomHostMapStore) interfaceWithLock(name string) *dnsservice.DnsMapInterface {
	lbInterface, ok := self.interfaces[name]
	if !ok {
		lbInterface = &dnsservice.DnsMapInterface{Name: name, HostProbes: map[string]bool{}}
		self.interfaces[name] = lbInterface
	}
	return lbInterface
}

// dnsservice.ApplyDnsMapPoll on the interface's row, added where there is none.
func (self *FakeDnsCustomHostMapStore) RecordMapPoll(ctx context.Context, root string, poll *dnsservice.DnsMapPoll) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	dnsservice.ApplyDnsMapPoll(self.interfaceWithLock(poll.Interface), poll)
	return nil
}

// dnsservice.ApplyDnsMapReport on the interface's row, added where there is none.
func (self *FakeDnsCustomHostMapStore) RecordMapReport(ctx context.Context, root string, report *dnsservice.DnsCustomHostMapReport, now time.Time, routeHostCount int, droppedMaxCount int) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	dnsservice.ApplyDnsMapReport(self.interfaceWithLock(report.Interface), report, now, routeHostCount, droppedMaxCount)
	return nil
}

// dnsservice.ApplyDnsRouteProbes on each named interface's row there is.
func (self *FakeDnsCustomHostMapStore) RecordRouteProbes(ctx context.Context, root string, report *dnsservice.DnsRouteProbeReport, now time.Time) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for index := range report.Interfaces {
		result := &report.Interfaces[index]
		if lbInterface, ok := self.interfaces[result.Name]; ok {
			dnsservice.ApplyDnsRouteProbes(lbInterface, result, now)
		}
	}
	return nil
}

// One row for each of names, and none for any other.
func (self *FakeDnsCustomHostMapStore) SyncMapInterfaces(ctx context.Context, root string, names []string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, name := range names {
		self.interfaceWithLock(name)
	}
	for name := range self.interfaces {
		if !slices.Contains(names, name) {
			delete(self.interfaces, name)
		}
	}
	return nil
}

// Sets each judged version's hosts ready from now, or not ready.
func (self *FakeDnsCustomHostMapStore) SetCustomHostReadiness(ctx context.Context, root string, ready map[uint64]bool, now time.Time) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for host, version := range self.hostVersions {
		isReady, judged := ready[version]
		switch {
		case !judged:
		case isReady:
			if _, ok := self.hostReadyTimes[host]; !ok {
				self.hostReadyTimes[host] = now
			}
		default:
			delete(self.hostReadyTimes, host)
		}
	}
	return nil
}

// One fake a root, for the suite, which makes a root a case: interface rows are each root's fake's alone here,
// as each case names its own.
type fakeDnsMapStoreByRoot struct {
	stores map[string]*FakeDnsCustomHostMapStore
}

// The root's fake's.
func (self *fakeDnsMapStoreByRoot) CustomHostMap(ctx context.Context, root string) (*dnsservice.DnsCustomHostMap, error) {
	return self.stores[root].CustomHostMap(ctx, root)
}

// The root's fake's.
func (self *fakeDnsMapStoreByRoot) CustomHostMapState(ctx context.Context, root string) (*dnsservice.DnsMapState, error) {
	return self.stores[root].CustomHostMapState(ctx, root)
}

// The root's fake's.
func (self *fakeDnsMapStoreByRoot) RecordMapPoll(ctx context.Context, root string, poll *dnsservice.DnsMapPoll) error {
	return self.stores[root].RecordMapPoll(ctx, root, poll)
}

// The root's fake's.
func (self *fakeDnsMapStoreByRoot) RecordMapReport(ctx context.Context, root string, report *dnsservice.DnsCustomHostMapReport, now time.Time, routeHostCount int, droppedMaxCount int) error {
	return self.stores[root].RecordMapReport(ctx, root, report, now, routeHostCount, droppedMaxCount)
}

// The root's fake's.
func (self *fakeDnsMapStoreByRoot) RecordRouteProbes(ctx context.Context, root string, report *dnsservice.DnsRouteProbeReport, now time.Time) error {
	return self.stores[root].RecordRouteProbes(ctx, root, report, now)
}

// The root's fake's.
func (self *fakeDnsMapStoreByRoot) SyncMapInterfaces(ctx context.Context, root string, names []string) error {
	return self.stores[root].SyncMapInterfaces(ctx, root, names)
}

// The root's fake's.
func (self *fakeDnsMapStoreByRoot) SetCustomHostReadiness(ctx context.Context, root string, ready map[uint64]bool, now time.Time) error {
	return self.stores[root].SetCustomHostReadiness(ctx, root, ready, now)
}
