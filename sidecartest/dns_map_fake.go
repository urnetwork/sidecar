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

	"github.com/urnetwork/sidecar/dnsservice"
)

// T2's store. See the file header.
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
}

var _ dnsservice.DnsCustomHostMapStore = (*FakeDnsCustomHostMapStore)(nil)

func NewFakeDnsCustomHostMapStore() *FakeDnsCustomHostMapStore {
	return &FakeDnsCustomHostMapStore{
		interfaces:     map[string]*dnsservice.DnsMapInterface{},
		hostVersions:   map[string]uint64{},
		hostReadyTimes: map[string]time.Time{},
	}
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

func (self *FakeDnsCustomHostMapStore) CustomHostMap(ctx context.Context, root string) (*dnsservice.DnsCustomHostMap, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if len(self.versions) == 0 {
		return nil, nil
	}
	newest := self.versions[len(self.versions)-1]
	return &dnsservice.DnsCustomHostMap{Format: dnsservice.DnsFormat, Version: newest.Version, Digest: newest.Digest, Hosts: slices.Clone(self.hosts)}, nil
}

func (self *FakeDnsCustomHostMapStore) CustomHostMapState(ctx context.Context, root string) (*dnsservice.DnsMapState, error) {
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

func (self *FakeDnsCustomHostMapStore) RecordMapPoll(ctx context.Context, root string, poll *dnsservice.DnsMapPoll) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	dnsservice.ApplyDnsMapPoll(self.interfaceWithLock(poll.Interface), poll)
	return nil
}

func (self *FakeDnsCustomHostMapStore) RecordMapReport(ctx context.Context, root string, report *dnsservice.DnsCustomHostMapReport, now time.Time, routeHostCount int, droppedMaxCount int) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	dnsservice.ApplyDnsMapReport(self.interfaceWithLock(report.Interface), report, now, routeHostCount, droppedMaxCount)
	return nil
}

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

func (self *fakeDnsMapStoreByRoot) CustomHostMap(ctx context.Context, root string) (*dnsservice.DnsCustomHostMap, error) {
	return self.stores[root].CustomHostMap(ctx, root)
}

func (self *fakeDnsMapStoreByRoot) CustomHostMapState(ctx context.Context, root string) (*dnsservice.DnsMapState, error) {
	return self.stores[root].CustomHostMapState(ctx, root)
}

func (self *fakeDnsMapStoreByRoot) RecordMapPoll(ctx context.Context, root string, poll *dnsservice.DnsMapPoll) error {
	return self.stores[root].RecordMapPoll(ctx, root, poll)
}

func (self *fakeDnsMapStoreByRoot) RecordMapReport(ctx context.Context, root string, report *dnsservice.DnsCustomHostMapReport, now time.Time, routeHostCount int, droppedMaxCount int) error {
	return self.stores[root].RecordMapReport(ctx, root, report, now, routeHostCount, droppedMaxCount)
}

func (self *fakeDnsMapStoreByRoot) RecordRouteProbes(ctx context.Context, root string, report *dnsservice.DnsRouteProbeReport, now time.Time) error {
	return self.stores[root].RecordRouteProbes(ctx, root, report, now)
}

func (self *fakeDnsMapStoreByRoot) SyncMapInterfaces(ctx context.Context, root string, names []string) error {
	return self.stores[root].SyncMapInterfaces(ctx, root, names)
}

func (self *fakeDnsMapStoreByRoot) SetCustomHostReadiness(ctx context.Context, root string, ready map[uint64]bool, now time.Time) error {
	return self.stores[root].SetCustomHostReadiness(ctx, root, ready, now)
}
