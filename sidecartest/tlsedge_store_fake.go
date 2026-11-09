// T2's TlsEdgeStore: §12's label map, network_tls_suspension and tls_connection_record in memory, until
// TLS-M5-11's model.NewTlsEdgeStore. The map keeps DNS-M5-10's rules: every change takes the root's next
// serial, a change to a network's suspensions moves every name of that network (DNS-M5-14), names are
// never deleted, only tombstoned, and a restore moves the root's restore serial. Calls go through
// hostCall, so a plan under FaultOpHost with the key "tlsedge.<Method>" reaches them, and each is
// counted, so a test can show a connection's path made none (§22.5). Safe for concurrent use.

package sidecartest

import (
	"context"
	"crypto/rand"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/tlsedgeservice"
)

var _ tlsedgeservice.TlsEdgeStore = (*FakeTlsEdgeStore)(nil)

// A label map row as the fake keeps it.
type fakeTlsEdgeName struct {
	root         string
	name         string
	networkId    sidecar.Id
	kind         tlsedgeservice.TlsEdgeNameKind
	state        tlsedgeservice.TlsEdgeNameState
	changeSerial uint64
}

// One network's §12.9 suspensions.
type fakeTlsEdgeZone struct {
	suspended     bool
	suspendUntil  time.Time
	withheldHosts map[string]bool
}

// The label map and kill rows of one test, in memory.
type FakeTlsEdgeStore struct {
	faults *FaultQueue

	stateLock sync.Mutex
	// by root, then name
	rootNames map[string]map[string]*fakeTlsEdgeName
	// by root
	rootSerials        map[string]uint64
	rootRestoreSerials map[string]uint64
	networkZones       map[sidecar.Id]*fakeTlsEdgeZone
	suspensions        []*sidecar.TlsSuspendArgs
	records            []*tlsedgeservice.TlsConnectionRecord
	opCounts           map[string]int
}

// A nil faults takes a fresh queue.
func NewFakeTlsEdgeStore(faults *FaultQueue) *FakeTlsEdgeStore {
	if faults == nil {
		faults = NewFaultQueue()
	}
	return &FakeTlsEdgeStore{
		faults:             faults,
		rootNames:          map[string]map[string]*fakeTlsEdgeName{},
		rootSerials:        map[string]uint64{},
		rootRestoreSerials: map[string]uint64{},
		networkZones:       map[sidecar.Id]*fakeTlsEdgeZone{},
		opCounts:           map[string]int{},
	}
}

// One call through the fake's fault and count, under its lock.
func (self *FakeTlsEdgeStore) call(ctx context.Context, method string, serve func() error) error {
	return hostCall(ctx, self.faults, "tlsedge."+method, func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.opCounts[method] += 1
		return serve()
	})
}

// How often each method ran, by name.
func (self *FakeTlsEdgeStore) OpCounts() map[string]int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return maps.Clone(self.opCounts)
}

// The root's next change serial.
func (self *FakeTlsEdgeStore) nextSerialWithLock(root string) uint64 {
	self.rootSerials[root] += 1
	return self.rootSerials[root]
}

// Writes a name, taking the root's next serial. A name another network holds, in any state, is refused,
// as dns_label's key refuses it.
func (self *FakeTlsEdgeStore) putNameWithLock(root string, name string, networkId sidecar.Id, kind tlsedgeservice.TlsEdgeNameKind, state tlsedgeservice.TlsEdgeNameState) error {
	names, ok := self.rootNames[root]
	if !ok {
		names = map[string]*fakeTlsEdgeName{}
		self.rootNames[root] = names
	}
	if existing, ok := names[name]; ok && existing.networkId != networkId {
		return errors.New("the name is held")
	}
	names[name] = &fakeTlsEdgeName{
		root:         root,
		name:         name,
		networkId:    networkId,
		kind:         kind,
		state:        state,
		changeSerial: self.nextSerialWithLock(root),
	}
	return nil
}

// Moves every name of networkId in every root to the root's next serial, as a change to its
// suspensions does (DNS-M5-14).
func (self *FakeTlsEdgeStore) touchNetworkWithLock(networkId sidecar.Id) {
	for root, names := range self.rootNames {
		for _, row := range names {
			if row.networkId == networkId {
				row.changeSerial = self.nextSerialWithLock(root)
			}
		}
	}
}

// Gives networkId a live label in root, drawn as §12.5 draws one, and returns it. A network with a label
// already keeps it.
func (self *FakeTlsEdgeStore) AddLabel(root string, networkId sidecar.Id) (string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, row := range self.rootNames[root] {
		if row.networkId == networkId && row.kind == tlsedgeservice.TlsEdgeNameKindLabel {
			return row.name, nil
		}
	}
	for {
		label, err := sidecar.NewDnsLabel(rand.Reader)
		if err != nil {
			return "", err
		}
		if _, held := self.rootNames[root][label]; held {
			continue
		}
		return label, self.putNameWithLock(root, label, networkId, tlsedgeservice.TlsEdgeNameKindLabel, tlsedgeservice.TlsEdgeNameStateLive)
	}
}

// Gives networkId a label of the test's choosing, for tables that need fixed names.
func (self *FakeTlsEdgeStore) SetLabel(root string, networkId sidecar.Id, label string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.putNameWithLock(root, label, networkId, tlsedgeservice.TlsEdgeNameKindLabel, tlsedgeservice.TlsEdgeNameStateLive)
}

// Gives networkId a live alias in root (§12.5, M6).
func (self *FakeTlsEdgeStore) AddAlias(root string, networkId sidecar.Id, alias string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.putNameWithLock(root, alias, networkId, tlsedgeservice.TlsEdgeNameKindAlias, tlsedgeservice.TlsEdgeNameStateLive)
}

// Moves one name to state, as an alias retiring does (D-DNS-10).
func (self *FakeTlsEdgeStore) SetNameState(root string, name string, state tlsedgeservice.TlsEdgeNameState) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	row, ok := self.rootNames[root][name]
	if !ok {
		return errors.New("no such name")
	}
	row.state = state
	row.changeSerial = self.nextSerialWithLock(root)
	return nil
}

// Tombstones every name of networkId, as deleting the network does (DnsWithdrawNetworkInTx).
func (self *FakeTlsEdgeStore) WithdrawNetwork(networkId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for root, names := range self.rootNames {
		for _, row := range names {
			if row.networkId == networkId && row.state != tlsedgeservice.TlsEdgeNameStateTombstoned {
				row.state = tlsedgeservice.TlsEdgeNameStateTombstoned
				row.changeSerial = self.nextSerialWithLock(root)
			}
		}
	}
}

func (self *FakeTlsEdgeStore) zoneWithLock(networkId sidecar.Id) *fakeTlsEdgeZone {
	zone, ok := self.networkZones[networkId]
	if !ok {
		zone = &fakeTlsEdgeZone{withheldHosts: map[string]bool{}}
		self.networkZones[networkId] = zone
	}
	return zone
}

// §12.9's SuspendZone: none of the network's names routes until Restore or until. A zero until holds
// until a lift.
func (self *FakeTlsEdgeStore) SuspendZone(networkId sidecar.Id, until time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	zone := self.zoneWithLock(networkId)
	zone.suspended = true
	zone.suspendUntil = until
	self.touchNetworkWithLock(networkId)
}

// §12.9's SuspendHost: host, relative to the network's zones, and everything below it.
func (self *FakeTlsEdgeStore) SuspendHost(networkId sidecar.Id, host string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.zoneWithLock(networkId).withheldHosts[host] = true
	self.touchNetworkWithLock(networkId)
}

// §12.9's Restore: host empty lifts the zone suspension, otherwise that host's.
func (self *FakeTlsEdgeStore) Restore(networkId sidecar.Id, host string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	zone := self.zoneWithLock(networkId)
	if host == "" {
		zone.suspended = false
		zone.suspendUntil = time.Time{}
	} else {
		delete(zone.withheldHosts, host)
	}
	self.touchNetworkWithLock(networkId)
}

// A Postgres restore of root (§12.6): its restore serial moves, which tells a reader to take a new
// snapshot. The rows stay as they are.
func (self *FakeTlsEdgeStore) RestoreRoot(root string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.rootRestoreSerials[root] = self.nextSerialWithLock(root)
}

// Writes a row of network_tls_suspension, replacing the network's row for the same host.
func (self *FakeTlsEdgeStore) SetSuspension(row *sidecar.TlsSuspendArgs) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.suspensions = slices.DeleteFunc(self.suspensions, func(existing *sidecar.TlsSuspendArgs) bool {
		return existing.NetworkId == row.NetworkId && existing.Host == row.Host
	})
	kept := *row
	self.suspensions = append(self.suspensions, &kept)
}

// Deletes the network's row for host, as the case's lift does.
func (self *FakeTlsEdgeStore) LiftSuspension(networkId sidecar.Id, host string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.suspensions = slices.DeleteFunc(self.suspensions, func(existing *sidecar.TlsSuspendArgs) bool {
		return existing.NetworkId == networkId && existing.Host == host
	})
}

// Every record written, oldest first, as copies.
func (self *FakeTlsEdgeStore) Records() []*tlsedgeservice.TlsConnectionRecord {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	records := make([]*tlsedgeservice.TlsConnectionRecord, 0, len(self.records))
	for _, record := range self.records {
		records = append(records, fakeTlsEdgeRecordCopy(record))
	}
	return records
}

func fakeTlsEdgeRecordCopy(record *tlsedgeservice.TlsConnectionRecord) *tlsedgeservice.TlsConnectionRecord {
	kept := *record
	kept.VisitorHash = slices.Clone(record.VisitorHash)
	return &kept
}

// The entry a row reads as, with its network's suspensions as they stand.
func (self *FakeTlsEdgeStore) entryWithLock(row *fakeTlsEdgeName) *tlsedgeservice.TlsEdgeNameEntry {
	entry := &tlsedgeservice.TlsEdgeNameEntry{
		Name:          row.name,
		NetworkId:     row.networkId,
		Kind:          row.kind,
		State:         row.state,
		WithheldHosts: []string{},
	}
	if zone, ok := self.networkZones[row.networkId]; ok {
		entry.ZoneSuspended = zone.suspended
		entry.ZoneSuspendUntil = zone.suspendUntil
		for host := range zone.withheldHosts {
			entry.WithheldHosts = append(entry.WithheldHosts, host)
		}
		slices.Sort(entry.WithheldHosts)
	}
	return entry
}

// The rows of root above after, in change serial order.
func (self *FakeTlsEdgeStore) mapWithLock(root string, after uint64) *tlsedgeservice.TlsEdgeNameMap {
	nameMap := &tlsedgeservice.TlsEdgeNameMap{
		Serial:        after,
		RestoreSerial: self.rootRestoreSerials[root],
		Entries:       []*tlsedgeservice.TlsEdgeNameEntry{},
	}
	rows := []*fakeTlsEdgeName{}
	for _, row := range self.rootNames[root] {
		if after < row.changeSerial {
			rows = append(rows, row)
		}
	}
	slices.SortFunc(rows, func(a *fakeTlsEdgeName, b *fakeTlsEdgeName) int {
		if a.changeSerial != b.changeSerial {
			if a.changeSerial < b.changeSerial {
				return -1
			}
			return 1
		}
		return strings.Compare(a.name, b.name)
	})
	for _, row := range rows {
		nameMap.Serial = max(nameMap.Serial, row.changeSerial)
		nameMap.Entries = append(nameMap.Entries, self.entryWithLock(row))
	}
	return nameMap
}

// See tlsedgeservice.TlsEdgeStore.
func (self *FakeTlsEdgeStore) NameSnapshot(ctx context.Context, root string) (*tlsedgeservice.TlsEdgeNameMap, error) {
	var nameMap *tlsedgeservice.TlsEdgeNameMap
	err := self.call(ctx, "NameSnapshot", func() error {
		nameMap = self.mapWithLock(root, 0)
		return nil
	})
	return nameMap, err
}

// See tlsedgeservice.TlsEdgeStore.
func (self *FakeTlsEdgeStore) NamesSince(ctx context.Context, root string, after uint64) (*tlsedgeservice.TlsEdgeNameMap, error) {
	var nameMap *tlsedgeservice.TlsEdgeNameMap
	err := self.call(ctx, "NamesSince", func() error {
		nameMap = self.mapWithLock(root, after)
		return nil
	})
	return nameMap, err
}

// See tlsedgeservice.TlsEdgeStore.
func (self *FakeTlsEdgeStore) Suspensions(ctx context.Context) ([]*sidecar.TlsSuspendArgs, error) {
	rows := []*sidecar.TlsSuspendArgs{}
	err := self.call(ctx, "Suspensions", func() error {
		for _, row := range self.suspensions {
			kept := *row
			rows = append(rows, &kept)
		}
		return nil
	})
	return rows, err
}

// See tlsedgeservice.TlsEdgeStore. Keeps a copy of each row, so a caller reusing its batch changes
// nothing here.
func (self *FakeTlsEdgeStore) InsertConnectionRecords(ctx context.Context, records []*tlsedgeservice.TlsConnectionRecord) error {
	return self.call(ctx, "InsertConnectionRecords", func() error {
		for _, record := range records {
			self.records = append(self.records, fakeTlsEdgeRecordCopy(record))
		}
		return nil
	})
}
