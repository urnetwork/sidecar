// T2's dnsservice.DnsStore and DnsFeed (§12.6, §12.14): the root's rows, journal and serial in memory,
// and a feed answering from any DnsStore as the API block does. RunDnsStoreSuite holds the store to
// the promises dnshost.Store keeps, so a test on it sees what an engine would see:
//
//   - one lock stands for dns_root's row lock, so writers in a root serialize with consecutive serials;
//   - a row's serial comes from the same commit as its rows, and {dns}serial:<root> rises after it, so
//     a fault plan can land between the two;
//   - journal rows carry the injected clock's commit time, which PurgeJournal reads;
//   - TakeDump and LoadDump stand in for §19.6's dump and §19.10's load, the one way a serial lowers.
//
// A call goes through hostCall, so a schedule reaches it by FaultOpHost and the keys below. The store
// holds a write to the rules every store does and no more: DNS-M5-02's lint and copy planning and
// DNS-M5-14's suspensions are model code the real store runs and this one does not. Safe for
// concurrent use.

package sidecartest

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/dnsservice"
)

// The FaultOpHost keys of the fake store and feed, the methods' names under dns. and dns.feed.
const (
	// The commit a Write ends in. CrashAfterApply is a crash between the commit and the raise.
	FaultDnsWrite = "dns.Write"
	// {dns}serial:<root>'s raise after a commit. FailBeforeApply loses it, as a Redis failure does.
	FaultDnsRaise = "dns.Raise"
	// One feed poll, before its hold.
	FaultDnsFeedJournal = "dns.feed.Journal"
	// One feed snapshot.
	FaultDnsFeedSnapshot = "dns.feed.Snapshot"
	// One feed diff.
	FaultDnsFeedReloadDiff = "dns.feed.ReloadDiff"
)

// One committed row and when it committed.
type fakeDnsJournalEntry struct {
	row        *dnsservice.DnsJournalRow
	commitTime time.Time
}

// One root's dns_root row and everything hanging off it.
type fakeDnsRoot struct {
	serial            uint64
	restoreSerial     uint64
	restoring         bool
	restoreIncidentId *sidecar.Id
	rows              map[dnsservice.DnsRecordKey]dnsservice.DnsRecordSet
	// oldest first, so serials ascend
	journal      []fakeDnsJournalEntry
	zoneVersions map[sidecar.Id]uint64
	reloadDiffs  []*dnsservice.DnsReloadDiff
}

// A copy of the row with nothing shared.
func cloneDnsJournalRow(row *dnsservice.DnsJournalRow) *dnsservice.DnsJournalRow {
	clone := *row
	clone.Upserts = make([]dnsservice.DnsRecordSet, 0, len(row.Upserts))
	for index := range row.Upserts {
		clone.Upserts = append(clone.Upserts, row.Upserts[index].Clone())
	}
	clone.Deletes = slices.Clone(row.Deletes)
	return &clone
}

// T2's store. See the file header.
type FakeDnsStore struct {
	clock  Clock
	faults *FaultQueue

	stateLock sync.Mutex
	roots     map[string]*fakeDnsRoot
	// by root, kept apart from the rows since Redis outlives a Postgres restore. Filled on first use.
	raised map[string]*sidecar.MonitorValue[uint64]
}

// clock may be nil, for a fresh clock. faults may be nil, for a queue of its own.
func NewFakeDnsStore(clock Clock, faults *FaultQueue) *FakeDnsStore {
	if clock == nil {
		clock = NewFakeClock(DefaultClockStart())
	}
	if faults == nil {
		faults = NewFaultQueue()
	}
	return &FakeDnsStore{
		clock:  clock,
		faults: faults,
		roots:  map[string]*fakeDnsRoot{},
		raised: map[string]*sidecar.MonitorValue[uint64]{},
	}
}

// The queue plans reach this store through.
func (self *FakeDnsStore) Faults() *FaultQueue {
	return self.faults
}

// The root's row, or ErrDnsRootUnknown.
func (self *FakeDnsStore) rootWithLock(root string) (*fakeDnsRoot, error) {
	state, ok := self.roots[root]
	if !ok {
		return nil, fmt.Errorf("%w: %s", dnsservice.ErrDnsRootUnknown, root)
	}
	return state, nil
}

// The root's raised value, made on first use.
func (self *FakeDnsStore) raisedOf(root string) *sidecar.MonitorValue[uint64] {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.raisedWithLock(root)
}

// The root's raised value, made on first use.
func (self *FakeDnsStore) raisedWithLock(root string) *sidecar.MonitorValue[uint64] {
	raised, ok := self.raised[root]
	if !ok {
		raised = sidecar.NewMonitorValue[uint64](0)
		self.raised[root] = raised
	}
	return raised
}

// Adds root at serial zero.
func (self *FakeDnsStore) EnsureRoot(ctx context.Context, root string) error {
	return hostCall(ctx, self.faults, "dns.EnsureRoot", func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if _, ok := self.roots[root]; !ok {
			self.roots[root] = &fakeDnsRoot{
				rows:         map[dnsservice.DnsRecordKey]dnsservice.DnsRecordSet{},
				zoneVersions: map[sidecar.Id]uint64{},
			}
		}
		return nil
	})
}

// One read of the root's row.
func (self *FakeDnsStore) RootState(ctx context.Context, root string) (*dnsservice.DnsRootState, error) {
	var rootState *dnsservice.DnsRootState
	err := hostCall(ctx, self.faults, "dns.RootState", func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		state, err := self.rootWithLock(root)
		if err != nil {
			return err
		}
		rootState = &dnsservice.DnsRootState{
			Root:          root,
			Serial:        state.serial,
			RestoreSerial: state.restoreSerial,
			Restoring:     state.restoring,
		}
		if state.restoreIncidentId != nil {
			incidentId := *state.restoreIncidentId
			rootState.RestoreIncidentId = &incidentId
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rootState, nil
}

// Rows above after, stopping at limit or the first hole.
func (self *FakeDnsStore) Journal(ctx context.Context, root string, after uint64, limit int) (*dnsservice.DnsJournalRead, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("journal limit %d is not positive", limit)
	}
	var read *dnsservice.DnsJournalRead
	err := hostCall(ctx, self.faults, "dns.Journal", func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		state, err := self.rootWithLock(root)
		if err != nil {
			return err
		}
		read = &dnsservice.DnsJournalRead{Serial: state.serial}
		next, _ := slices.BinarySearchFunc(state.journal, after+1, func(entry fakeDnsJournalEntry, serial uint64) int {
			return cmp.Compare(entry.row.Serial, serial)
		})
		for serial := after + 1; next < len(state.journal) && len(read.Rows) < limit; serial += 1 {
			row := state.journal[next].row
			if row.Serial != serial {
				break
			}
			read.Rows = append(read.Rows, *cloneDnsJournalRow(row))
			next += 1
		}
		read.Gap = after < state.serial && len(read.Rows) == 0
		return nil
	})
	if err != nil {
		return nil, err
	}
	return read, nil
}

// A frozen copy of the rows, in owner then type order.
func (self *FakeDnsStore) Snapshot(ctx context.Context, root string) (dnsservice.DnsSnapshotRows, error) {
	var rows dnsservice.DnsSnapshotRows
	err := hostCall(ctx, self.faults, "dns.Snapshot", func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		state, err := self.rootWithLock(root)
		if err != nil {
			return err
		}
		sets := make([]dnsservice.DnsRecordSet, 0, len(state.rows))
		for _, key := range slices.SortedFunc(maps.Keys(state.rows), compareDnsRecordKeys) {
			set := state.rows[key]
			sets = append(sets, set.Clone())
		}
		rows = dnsservice.NewDnsSnapshotRows(dnsservice.DnsSnapshot{
			Format:        dnsservice.DnsFormat,
			Root:          root,
			Serial:        state.serial,
			RestoreSerial: state.restoreSerial,
		}, sets)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// Owner, then type.
func compareDnsRecordKeys(a dnsservice.DnsRecordKey, b dnsservice.DnsRecordKey) int {
	return cmp.Or(cmp.Compare(a.Owner, b.Owner), cmp.Compare(a.Type, b.Type))
}

// The commit, then the raise. A plan ending the call at the commit leaves the key behind it.
func (self *FakeDnsStore) Write(ctx context.Context, write *dnsservice.DnsZoneWrite) (uint64, error) {
	if err := write.Validate(); err != nil {
		return 0, err
	}
	var serial uint64
	err := hostCall(ctx, self.faults, FaultDnsWrite, func() error {
		var err error
		serial, err = self.commit(write)
		return err
	})
	if err != nil {
		return 0, err
	}
	// nothing is lost if this fails, because the feed rereads the journal at the end of each hold
	hostCall(ctx, self.faults, FaultDnsRaise, func() error {
		self.raise(write.Root, serial)
		return nil
	})
	return serial, nil
}

// §12.6's transaction: all of it, or none.
func (self *FakeDnsStore) commit(write *dnsservice.DnsZoneWrite) (uint64, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	state, err := self.rootWithLock(write.Root)
	if err != nil {
		return 0, err
	}
	if state.restoring {
		return 0, fmt.Errorf("%w: %s", dnsservice.ErrDnsRestoring, write.Root)
	}
	if write.ExpectVersion != nil && *write.ExpectVersion != state.zoneVersions[write.NetworkId] {
		return 0, fmt.Errorf("%w: %d is not %d", dnsservice.ErrDnsVersionConflict, *write.ExpectVersion, state.zoneVersions[write.NetworkId])
	}
	state.serial += 1
	row := cloneDnsJournalRow(write.Row(state.serial))
	for index := range row.Upserts {
		set := &row.Upserts[index]
		state.rows[set.Key()] = set.Clone()
	}
	for _, key := range row.Deletes {
		delete(state.rows, key)
	}
	state.journal = append(state.journal, fakeDnsJournalEntry{row: row, commitTime: self.clock.Now()})
	state.zoneVersions[write.NetworkId] = state.serial
	return state.serial, nil
}

// Raises the key, never lowering it.
func (self *FakeDnsStore) raise(root string, serial uint64) {
	self.raisedOf(root).Update(func(raised uint64) uint64 {
		return max(raised, serial)
	})
}

// The serial of the zone's last write.
func (self *FakeDnsStore) ZoneVersion(ctx context.Context, root string, networkId sidecar.Id) (uint64, error) {
	var version uint64
	err := hostCall(ctx, self.faults, "dns.ZoneVersion", func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		state, err := self.rootWithLock(root)
		if err != nil {
			return err
		}
		version = state.zoneVersions[networkId]
		return nil
	})
	if err != nil {
		return 0, err
	}
	return version, nil
}

// Drops rows committed before before.
func (self *FakeDnsStore) PurgeJournal(ctx context.Context, root string, before time.Time) (int, error) {
	purgedCount := 0
	err := hostCall(ctx, self.faults, "dns.PurgeJournal", func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		state, err := self.rootWithLock(root)
		if err != nil {
			return err
		}
		purgedCount = 0
		for purgedCount < len(state.journal) && state.journal[purgedCount].commitTime.Before(before) {
			purgedCount += 1
		}
		state.journal = slices.Delete(state.journal, 0, purgedCount)
		return nil
	})
	if err != nil {
		return 0, err
	}
	return purgedCount, nil
}

// Sets or clears restoring, forgetting an earlier restore's incident when it sets.
func (self *FakeDnsStore) SetRestoring(ctx context.Context, root string, restoring bool) error {
	return hostCall(ctx, self.faults, "dns.SetRestoring", func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		state, err := self.rootWithLock(root)
		if err != nil {
			return err
		}
		if restoring && !state.restoring {
			state.restoreIncidentId = nil
		}
		state.restoring = restoring
		return nil
	})
}

// §12.6's restore transaction, idempotent by incident.
func (self *FakeDnsStore) CommitRestore(ctx context.Context, root string, incidentId sidecar.Id, observedSerial uint64) (uint64, error) {
	var restoreSerial uint64
	err := hostCall(ctx, self.faults, "dns.CommitRestore", func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		state, err := self.rootWithLock(root)
		if err != nil {
			return err
		}
		if !state.restoring {
			return fmt.Errorf("%w: %s", dnsservice.ErrDnsNotRestoring, root)
		}
		if state.restoreIncidentId != nil {
			if *state.restoreIncidentId != incidentId {
				return fmt.Errorf("%w: %s", dnsservice.ErrDnsRestoreIncident, root)
			}
			restoreSerial = state.restoreSerial
			return nil
		}
		restoreSerial = max(state.serial, observedSerial, self.raisedWithLock(root).Value()) + dnsservice.DnsRestoreSerialJump
		state.serial = restoreSerial
		state.restoreSerial = restoreSerial
		state.restoreIncidentId = &incidentId
		return nil
	})
	if err != nil {
		return 0, err
	}
	self.raise(root, restoreSerial)
	return restoreSerial, nil
}

// Keeps diff.
func (self *FakeDnsStore) RecordReloadDiff(ctx context.Context, diff *dnsservice.DnsReloadDiff) error {
	return hostCall(ctx, self.faults, "dns.RecordReloadDiff", func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		state, err := self.rootWithLock(diff.Root)
		if err != nil {
			return err
		}
		kept := *diff
		kept.Rrsets = slices.Clone(diff.Rrsets)
		state.reloadDiffs = append(state.reloadDiffs, &kept)
		return nil
	})
}

// Every diff kept.
func (self *FakeDnsStore) ReloadDiffs(ctx context.Context, root string) ([]*dnsservice.DnsReloadDiff, error) {
	var diffs []*dnsservice.DnsReloadDiff
	err := hostCall(ctx, self.faults, "dns.ReloadDiffs", func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		state, err := self.rootWithLock(root)
		if err != nil {
			return err
		}
		diffs = make([]*dnsservice.DnsReloadDiff, 0, len(state.reloadDiffs))
		for _, diff := range state.reloadDiffs {
			kept := *diff
			kept.Rrsets = slices.Clone(diff.Rrsets)
			diffs = append(diffs, &kept)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return diffs, nil
}

// What the key holds.
func (self *FakeDnsStore) RaisedSerial(ctx context.Context, root string) (uint64, error) {
	var serial uint64
	err := hostCall(ctx, self.faults, "dns.RaisedSerial", func() error {
		serial = self.raisedOf(root).Value()
		return nil
	})
	if err != nil {
		return 0, err
	}
	return serial, nil
}

// Closes at the next raise.
func (self *FakeDnsStore) SerialRaised(root string) <-chan struct{} {
	_, changed := self.raisedOf(root).Get()
	return changed
}

// A root's rows as a dump holds them: dns_zone_journal is in no dump (§19.6).
type FakeDnsDump struct {
	root *fakeDnsRoot
}

// What §19.6's dump would hold of root now.
func (self *FakeDnsStore) TakeDump(root string) (*FakeDnsDump, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	state, err := self.rootWithLock(root)
	if err != nil {
		return nil, err
	}
	return &FakeDnsDump{root: &fakeDnsRoot{
		serial:        state.serial,
		restoreSerial: state.restoreSerial,
		rows:          maps.Clone(state.rows),
		zoneVersions:  maps.Clone(state.zoneVersions),
	}}, nil
}

// §19.10's load: root comes back at the dump's serial with an empty journal and no restore running,
// while {dns}serial:<root> stays, since Redis is not restored. Writes are what SetRestoring holds off,
// so a test sets it first, as §19.10 does.
func (self *FakeDnsStore) LoadDump(root string, dump *FakeDnsDump) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	restoring := false
	if state, ok := self.roots[root]; ok {
		restoring = state.restoring
	}
	self.roots[root] = &fakeDnsRoot{
		serial:        dump.root.serial,
		restoreSerial: dump.root.restoreSerial,
		restoring:     restoring,
		rows:          maps.Clone(dump.root.rows),
		zoneVersions:  maps.Clone(dump.root.zoneVersions),
	}
}

// What a feed answer holds beyond the journal, and how long a poll waits.
type FakeDnsFeedSettings struct {
	// How long a poll holds with nothing new, on the injected clock: §12.8's 25 s.
	HoldTimeout time.Duration
	// The most rows one answer carries.
	RowLimit int
}

func DefaultFakeDnsFeedSettings() *FakeDnsFeedSettings {
	return &FakeDnsFeedSettings{
		HoldTimeout: 25 * time.Second,
		RowLimit:    256,
	}
}

// T2's feed over any DnsStore, so a test drives an edge with no API block. It decides as the block does
// (plan reading 8): hold at or ahead of the serial, reload for a gap below it, and while restoring
// only once the restore transaction has run. Safe for concurrent use.
type FakeDnsFeed struct {
	store    dnsservice.DnsStore
	clock    Clock
	faults   *FaultQueue
	settings *FakeDnsFeedSettings

	stateLock  sync.Mutex
	interfaces []dnsservice.DnsLbInterface
	keyWindow  *dnsservice.DnsKeyWindow
}

// clock may be nil, for a fresh clock. faults may be nil, for a queue of its own. settings may be nil,
// for the defaults.
func NewFakeDnsFeed(store dnsservice.DnsStore, clock Clock, faults *FaultQueue, settings *FakeDnsFeedSettings) *FakeDnsFeed {
	if clock == nil {
		clock = NewFakeClock(DefaultClockStart())
	}
	if faults == nil {
		faults = NewFaultQueue()
	}
	if settings == nil {
		settings = DefaultFakeDnsFeedSettings()
	}
	return &FakeDnsFeed{store: store, clock: clock, faults: faults, settings: settings}
}

// What every answer names from now on.
func (self *FakeDnsFeed) SetInterfaces(interfaces []dnsservice.DnsLbInterface) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.interfaces = slices.Clone(interfaces)
}

// The window every answer names from now on. nil names none.
func (self *FakeDnsFeed) SetKeyWindow(keyWindow *dnsservice.DnsKeyWindow) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.keyWindow = keyWindow
}

// One read of the store, as the block makes on each wake.
func (self *FakeDnsFeed) answer(ctx context.Context, root string, after uint64) (*dnsservice.DnsFeedAnswer, error) {
	state, err := self.store.RootState(ctx, root)
	if err != nil {
		return nil, err
	}
	read, err := self.store.Journal(ctx, root, after, self.settings.RowLimit)
	if err != nil {
		return nil, err
	}
	answer := &dnsservice.DnsFeedAnswer{
		Format:        dnsservice.DnsFormat,
		Root:          root,
		Serial:        read.Serial,
		RestoreSerial: state.RestoreSerial,
		Reload:        read.Gap && (!state.Restoring || state.RestoreIncidentId != nil),
		Rows:          read.Rows,
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		answer.Interfaces = slices.Clone(self.interfaces)
		answer.KeyWindow = self.keyWindow
	}()
	return answer, nil
}

// Answers at once with what is there, or holds until a raise, the hold's end or ctx. The hold's end
// rereads, which is what catches a lost raise.
func (self *FakeDnsFeed) hold(ctx context.Context, root string, after uint64) (*dnsservice.DnsFeedAnswer, error) {
	holdEnded := self.clock.After(self.settings.HoldTimeout)
	for {
		raised := self.store.SerialRaised(root)
		answer, err := self.answer(ctx, root, after)
		if err != nil || answer.Reload || len(answer.Rows) != 0 {
			return answer, err
		}
		select {
		case <-raised:
		case <-holdEnded:
			return self.answer(ctx, root, after)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// One poll.
func (self *FakeDnsFeed) Journal(ctx context.Context, root string, after uint64) (*dnsservice.DnsFeedAnswer, error) {
	var answer *dnsservice.DnsFeedAnswer
	err := hostCall(ctx, self.faults, FaultDnsFeedJournal, func() error {
		var err error
		answer, err = self.hold(ctx, root, after)
		return err
	})
	if err != nil {
		return nil, err
	}
	return answer, nil
}

// The store's snapshot.
func (self *FakeDnsFeed) Snapshot(ctx context.Context, root string) (dnsservice.DnsSnapshotRows, error) {
	var rows dnsservice.DnsSnapshotRows
	err := hostCall(ctx, self.faults, FaultDnsFeedSnapshot, func() error {
		var err error
		rows, err = self.store.Snapshot(ctx, root)
		return err
	})
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// Hands diff to the store.
func (self *FakeDnsFeed) ReloadDiff(ctx context.Context, diff *dnsservice.DnsReloadDiff) error {
	return hostCall(ctx, self.faults, FaultDnsFeedReloadDiff, func() error {
		return self.store.RecordReloadDiff(ctx, diff)
	})
}
