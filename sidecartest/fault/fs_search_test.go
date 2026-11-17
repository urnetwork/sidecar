//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind

package fault

// What FS-77, FS-109 and FS-110 share (SEARCH-M10-38): §18.4's hosts as their search settings and conditions, the
// search world each schedule writes and syncs (the root's SearchTestWorld, under sidecar_testhooks), and the oracle its
// results are held to.
//
//	desktop  background all, the core's 64 MiB of decoded state and four searches at once; a daemon host reports no
//	         conditions and reads unmetered
//	ios32    the iOS app (sdk's ios host class): wifi_charging, one search's 4 MiB working set beside the 256 KiB of
//	         version-table pages, one search at once, all capped at 256 MiB, one sync round at once
//	android  the Android app, whose search matches iOS's (owner decision 197)
//	worker   the page Worker: wifi_charging, 8 MiB a search beside the pages, all capped at 128 MiB a network, one search
//	         at once; its conditions come from the key-origin frame
//
// The phones' and the Worker's rows mirror sdk's host classes (sdk/sidecar_host_class.go) and §18.4, which the sdk's
// T4 cells hold on the surrogates; here they run on T2, one process, the heap sampled as §22.8's FS-109 says.

import (
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// One host's search, as §18.4's rows set it.
type searchHost struct {
	name string
	// §18.4's working set of one search alone, which the heap less its start stays within.
	workingSetByteCount int64
	// The page's arrival bound after a shard lands (§16.10's cold contract).
	arrival  time.Duration
	settings func() *sidecar.SidecarSearchSettings
	// The host's conditions when it reports them, else unreported.
	conditions sidecar.SearchConditions
}

// The phones' settings over the core's defaults (sdk's phone host class).
func searchPhoneSettings() *sidecar.SidecarSearchSettings {
	settings := sidecar.DefaultSidecarSettings().Search
	settings.AllPolicy = sidecar.SearchPolicyWifiCharging
	settings.MemoryByteCount = 4*1024*1024 + 256*1024
	settings.DaemonSearchCount = 1
	settings.AllCacheByteCount = 256 * 1024 * 1024
	settings.UnusedAllAge = 30 * 24 * time.Hour
	settings.DirectoryBuckets = false
	settings.SyncRoundCount = 1
	settings.RemoteServe = false
	settings.RemoteAsk = true
	return settings
}

// The page Worker's settings (§18.4's caps and targets rows).
func searchWorkerSettings() *sidecar.SidecarSearchSettings {
	settings := searchPhoneSettings()
	settings.MemoryByteCount = 8*1024*1024 + 256*1024
	settings.AllCacheByteCount = 128 * 1024 * 1024
	settings.RemoteAsk = false
	return settings
}

// §18.4's hosts. A phone on Wi-Fi while charging, the Worker's tab the same, which a case changes where it says.
func searchHosts() []*searchHost {
	desktopSettings := func() *sidecar.SidecarSearchSettings { return sidecar.DefaultSidecarSettings().Search }
	wifiCharging := sidecar.SearchConditions{Unmetered: true, Charging: true, Reported: true, Foreground: true}
	return []*searchHost{
		{name: "desktop", workingSetByteCount: 64 * 1024 * 1024, arrival: 100 * time.Millisecond, settings: desktopSettings,
			conditions: sidecar.SearchConditions{DaemonHost: true}},
		{name: "ios32", workingSetByteCount: 4 * 1024 * 1024, arrival: 300 * time.Millisecond, settings: searchPhoneSettings, conditions: wifiCharging},
		{name: "android", workingSetByteCount: 4 * 1024 * 1024, arrival: 300 * time.Millisecond, settings: searchPhoneSettings, conditions: wifiCharging},
		{name: "worker", workingSetByteCount: 8 * 1024 * 1024, arrival: 300 * time.Millisecond, settings: searchWorkerSettings, conditions: wifiCharging},
	}
}

// The host named name.
func searchHostNamed(name string) *searchHost {
	for _, host := range searchHosts() {
		if host.name == name {
			return host
		}
	}
	panic("no search host " + name)
}

// A schedule's world: the index, the oracle's ledger beside it, and the devices made on it.
type searchWorld struct {
	net    *Net
	index  *sidecar.SearchTestWorld
	ledger *sidecartest.SearchLedger
	oracle *sidecartest.SearchOracle
	// the reader every device searches as, and the network it reads
	readerId  sidecar.Id
	networkId sidecar.Id
	writerId  sidecar.Id
	// the next ref version the ledger records at
	refVersion uint64
	devices    []*sidecar.SearchTestDevice
	// the most a device's read asks for: §11.9's 32 MiB, which FS-110 narrows to a shard
	readByteCount int64
}

// A world on net's clock, the oracle's ledger holding the repo.
func newSearchWorld(net *Net, label string) (*searchWorld, error) {
	repoId := searchId("fs search repo " + label)
	refId := searchId("fs search ref " + label)
	index, err := sidecar.NewSearchTestWorld(&sidecar.SearchTestWorldArgs{RepoId: repoId, RefId: refId, Clock: net.Clock()})
	if err != nil {
		return nil, err
	}
	world := &searchWorld{
		net: net, index: index, ledger: sidecartest.NewSearchLedger(), readByteCount: 32 * 1024 * 1024,
		readerId: searchId("fs search reader " + label), networkId: searchId("fs search network " + label),
		writerId: searchId("fs search writer " + label),
	}
	err = world.ledger.AddRepo(&sidecartest.SearchLedgerRepo{
		RepoId: repoId, NetworkId: world.networkId, Kind: protocol.RepoKind_REPO_KIND_GENERAL, DefaultRefId: refId,
		Key: index.RepoKey(), ReaderIds: []sidecar.Id{world.readerId},
	})
	if err != nil {
		return nil, err
	}
	world.oracle = sidecartest.NewSearchOracle(world.ledger)
	return world, nil
}

// Records documents in the ledger as one indexed commit at at: what the oracle judges.
func (self *searchWorld) record(at time.Time, documents ...*sidecar.SearchTestDocument) error {
	self.refVersion += 1
	commit := &sidecartest.SearchCommit{
		RepoId: self.index.RepoId(), RefId: self.index.RefId(), RefVersion: self.refVersion, Time: at, WriterId: self.writerId,
		Indexed: true,
	}
	for _, document := range documents {
		commit.Changes = append(commit.Changes, &sidecartest.SearchChange{
			Path: document.Path, Version: document.Version, Content: []byte(document.Title + "\n" + document.Text),
		})
	}
	return self.ledger.Commit(commit)
}

// The oracle's matches for query over the buckets and all, as paths at versions.
func (self *searchWorld) oracleMatches(query string) []string {
	scope := &sidecartest.SearchScope{
		Partitions: sidecartest.SearchScopeAll, Breadth: sidecartest.SearchBreadthNetwork,
		NetworkIds: []sidecar.Id{self.networkId}, ReaderId: self.readerId,
	}
	matches := []string{}
	for _, key := range self.oracle.Matches(query, scope) {
		matches = append(matches, fmt.Sprintf("%s@%d", key.Name, key.Version))
	}
	slices.Sort(matches)
	return matches
}

// A search's hits as paths at versions, sorted.
func searchHitNames(hits []sidecar.SearchHit) []string {
	names := []string{}
	for _, hit := range hits {
		names = append(names, fmt.Sprintf("%s@%d", hit.Path, hit.Version))
	}
	slices.Sort(names)
	return names
}

// A fresh device of host on the world, its cache in memory standing for its disk (a heap sampler leaves the cache's
// bytes out, as CacheByteCount counts them): conditions nil reads the host's; reads at rate; onRecord at each record a
// search opens.
func (self *searchWorld) device(ctx context.Context, host *searchHost, settings *sidecar.SidecarSearchSettings, conditions func() sidecar.SearchConditions, rate int64, onRecord func()) (*sidecar.SearchTestDevice, error) {
	if settings == nil {
		settings = host.settings()
	}
	if conditions == nil {
		reported := host.conditions
		conditions = func() sidecar.SearchConditions { return reported }
	}
	device, err := self.index.NewDevice(ctx, &sidecar.SearchTestDeviceArgs{
		Settings: settings, Conditions: conditions, ReadByteRate: rate, ReadByteCount: self.readByteCount, OnRecord: onRecord,
	})
	if err != nil {
		return nil, err
	}
	self.devices = append(self.devices, device)
	return device, nil
}

// A 16 B id from a label.
func searchId(label string) sidecar.Id {
	digest := sha256.Sum256([]byte("fs search id " + label))
	return sidecar.Id(digest[:16])
}

// Ends device, which the world made, and lets its cache go.
func (self *searchWorld) done(device *sidecar.SearchTestDevice) {
	device.Close()
	self.devices = slices.DeleteFunc(self.devices, func(other *sidecar.SearchTestDevice) bool { return other == device })
}

// Ends every device the world made.
func (self *searchWorld) close() {
	for _, device := range self.devices {
		device.Close()
	}
	self.devices = nil
}

// A fetch trace as text, for comparing two and reading a failure.
func searchTraceOf(fetches []sidecar.SearchTestFetch) []string {
	trace := []string{}
	for _, fetch := range fetches {
		trace = append(trace, fmt.Sprintf("%s@%d:%d", fetch.Path, fetch.Version, fetch.ByteCount))
	}
	return trace
}

// The all shards of a trace, in order.
func searchAllShardsOf(trace []string) []string {
	shards := []string{}
	for _, line := range trace {
		path, _, _ := strings.Cut(line, "@")
		if strings.Contains(path, "/a/") && !strings.HasSuffix(path, "/a/m") {
			shards = append(shards, line)
		}
	}
	return shards
}
