package dnsservice_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/miekg/dns"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/dnsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The NS as a restore test makes them answer: each at a serial it is set to, or silent; once the restore
// transaction has run, one set to follow reloads at restore_serial, as an edge does at its next poll,
// and posts the diff it is given. Safe for concurrent use.
type restoreTestNs struct {
	store *sidecartest.FakeDnsStore
	// SOA reads answered, counted as each returns.
	readCount *sidecar.MonitorValue[int]

	stateLock sync.Mutex
	serials   map[string]uint32
	silent    map[string]bool
	follows   map[string]bool
	diffs     map[string][]dnsservice.DnsRecordKey
	kinds     map[string][]dnsservice.DnsRecordKind
	posted    map[string]bool
}

func newRestoreTestNs(store *sidecartest.FakeDnsStore) *restoreTestNs {
	return &restoreTestNs{
		store:     store,
		readCount: sidecar.NewMonitorValue(0),
		serials:   map[string]uint32{},
		silent:    map[string]bool{},
		follows:   map[string]bool{},
		diffs:     map[string][]dnsservice.DnsRecordKey{},
		kinds:     map[string][]dnsservice.DnsRecordKind{},
		posted:    map[string]bool{},
	}
}

// ns answers serial, until it follows a restore.
func (self *restoreTestNs) serve(ns string, serial uint32) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.serials[ns] = serial
	self.silent[ns] = false
}

// ns answers nothing.
func (self *restoreTestNs) silence(ns string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.silent[ns] = true
}

// ns reloads at restore_serial once the transaction has run, posting a diff of keys with their kinds.
func (self *restoreTestNs) follow(ns string, keys []dnsservice.DnsRecordKey, kinds []dnsservice.DnsRecordKind) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.follows[ns] = true
	self.diffs[ns] = keys
	self.kinds[ns] = kinds
}

// Waits until count SOA reads have returned.
func (self *restoreTestNs) awaitReads(t testing.TB, count int) {
	t.Helper()
	for {
		current, changed := self.readCount.Get()
		if count <= current {
			return
		}
		select {
		case <-changed:
		case <-t.Context().Done():
			t.Fatalf("%d reads", current)
		}
	}
}

func (self *restoreTestNs) ReadSoa(ctx context.Context, root string, ns string) (uint32, error) {
	defer self.readCount.Update(func(count int) int { return count + 1 })
	var serial uint32
	var silent bool
	var follows bool
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		serial = self.serials[ns]
		silent = self.silent[ns]
		follows = self.follows[ns]
	}()
	if silent {
		return 0, errors.New("no answer")
	}
	if !follows {
		return serial, nil
	}
	state, err := self.store.RootState(ctx, root)
	if err != nil {
		return 0, err
	}
	if state.RestoreIncidentId == nil {
		return serial, nil
	}
	var diff *dnsservice.DnsReloadDiff
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if !self.posted[ns] {
			self.posted[ns] = true
			diff = &dnsservice.DnsReloadDiff{Root: root, ReplacedSerial: uint64(serial), Serial: state.RestoreSerial, Rrsets: self.diffs[ns], Kinds: self.kinds[ns]}
		}
	}()
	if diff != nil {
		if err := self.store.RecordReloadDiff(ctx, diff); err != nil {
			return 0, err
		}
	}
	return uint32(state.RestoreSerial), nil
}

// A store holding a zone written to some serial, a dump of it, the NS, the step and its fakes.
type restoreTest struct {
	clock    *sidecartest.FakeClock
	store    *sidecartest.FakeDnsStore
	restore  *sidecartest.FakeDnsRestoreStore
	ns       *restoreTestNs
	settings *dnsservice.DnsSettings
	step     *dnsservice.RestoreStep
	dump     *sidecartest.FakeDnsDump
}

func newRestoreTest(t testing.TB) *restoreTest {
	t.Helper()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	store := sidecartest.NewFakeDnsStore(clock, nil)
	settings := edgeTestSettings(t)
	self := &restoreTest{
		clock:    clock,
		store:    store,
		restore:  sidecartest.NewFakeDnsRestoreStore(clock),
		ns:       newRestoreTestNs(store),
		settings: settings,
	}
	if err := store.EnsureRoot(t.Context(), edgeTestRoot); err != nil {
		t.Fatal(err)
	}
	self.step = self.newStep(t)
	return self
}

// A step of its own over the same stores, as a rerun after a crash makes.
func (self *restoreTest) newStep(t testing.TB) *dnsservice.RestoreStep {
	t.Helper()
	step, err := dnsservice.NewRestoreStep(self.settings, &dnsservice.RestoreStepDeps{
		Store:     self.store,
		Restore:   self.restore,
		SoaReader: self.ns,
		Clock:     self.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return step
}

// Writes a TXT at owner, returning the serial.
func (self *restoreTest) write(t testing.TB, owner string) uint64 {
	t.Helper()
	serial, err := self.store.Write(t.Context(), &dnsservice.DnsZoneWrite{
		Root:    edgeTestRoot,
		Upserts: []dnsservice.DnsRecordSet{{Owner: owner, Type: dns.TypeTXT, Ttl: 300, Kind: dnsservice.DnsRecordKindUser, Rdata: []string{`"x"`}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return serial
}

// Writes count rows, the last at the serial returned.
func (self *restoreTest) writeMany(t testing.TB, count int) uint64 {
	t.Helper()
	serial := uint64(0)
	for index := range count {
		serial = self.write(t, "w"+string(rune('a'+index%26))+"."+edgeTestRoot)
	}
	return serial
}

// Takes the dump.
func (self *restoreTest) takeDump(t testing.TB) {
	t.Helper()
	dump, err := self.store.TakeDump(edgeTestRoot)
	if err != nil {
		t.Fatal(err)
	}
	self.dump = dump
}

// §19.10's load: restoring set as the dump comes back.
func (self *restoreTest) loseAndLoad(t testing.TB) {
	t.Helper()
	if err := self.step.SetRestoring(t.Context(), edgeTestRoot, true); err != nil {
		t.Fatal(err)
	}
	self.store.LoadDump(edgeTestRoot, self.dump)
}

// The root's state now.
func (self *restoreTest) state(t testing.TB) *dnsservice.DnsRootState {
	t.Helper()
	state, err := self.store.RootState(t.Context(), edgeTestRoot)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

// Runs the step to its end.
func (self *restoreTest) run(t testing.TB, incidentId sidecar.Id) *dnsservice.DnsRestoreProgress {
	t.Helper()
	progress, err := self.step.Run(t.Context(), edgeTestRoot, incidentId)
	if err != nil {
		t.Fatal(err)
	}
	return progress
}

// restore_serial lands 2^24 above the highest of the restored serial, the SOAs read and the key: here the
// lost primary's raises failed, so the key is below what the NS serve.
func TestRestoreStepLandsAboveSoasTheKeyMissed(t *testing.T) {
	test := newRestoreTest(t)
	dumped := test.writeMany(t, 3)
	test.takeDump(t)
	test.loseAndLoad(t)
	// the NS served writes the dump lacks, whose raises a failover lost
	test.ns.serve("ns1", uint32(dumped+22))
	test.ns.serve("ns2", uint32(dumped+20))
	test.ns.follow("ns1", nil, nil)
	test.ns.follow("ns2", nil, nil)
	incidentId := sidecar.NewId()
	progress := test.run(t, incidentId)
	want := dumped + 22 + dnsservice.DnsRestoreSerialJump
	if progress.RestoreSerial != want || !progress.Done {
		t.Errorf("progress %+v, want serial %d", progress, want)
	}
	state := test.state(t)
	if state.Restoring || state.RestoreSerial != want || state.Serial != want || *state.RestoreIncidentId != incidentId {
		t.Errorf("state %+v", state)
	}
	raised, err := test.store.RaisedSerial(t.Context(), edgeTestRoot)
	if err != nil || raised != want {
		t.Errorf("the key %d %v", raised, err)
	}
	// a write after the step commits above restore_serial
	if serial := test.write(t, "after."+edgeTestRoot); serial != want+1 {
		t.Errorf("a write after the step took %d", serial)
	}
}

// Here the key held the lost primary's last serial and the NS lag behind it: the key decides.
func TestRestoreStepLandsAboveTheKeyWhenTheNsLag(t *testing.T) {
	test := newRestoreTest(t)
	dumped := test.writeMany(t, 3)
	test.takeDump(t)
	lost := test.writeMany(t, 6)
	test.loseAndLoad(t)
	test.ns.serve("ns1", uint32(dumped+2))
	test.ns.serve("ns2", uint32(dumped+1))
	test.ns.follow("ns1", nil, nil)
	test.ns.follow("ns2", nil, nil)
	progress := test.run(t, sidecar.NewId())
	if want := lost + dnsservice.DnsRestoreSerialJump; progress.RestoreSerial != want {
		t.Errorf("restore serial %d, want %d", progress.RestoreSerial, want)
	}
}

// Every RRset a diff names is listed once across both NS's diffs, but challenges' and canaries'; by
// network through the labels, with no network for the root's own; the network with an open case
// flagged; one admin event a network. A rerun lists nothing twice, and a diff posted later adds only
// what it brings.
func TestRestoreStepListsEachChangedRrsetOnce(t *testing.T) {
	test := newRestoreTest(t)
	test.writeMany(t, 2)
	test.takeDump(t)
	test.loseAndLoad(t)
	flaggedNetworkId := sidecar.NewId()
	otherNetworkId := sidecar.NewId()
	test.restore.SetLabel(edgeTestRoot, "netone", flaggedNetworkId)
	test.restore.SetLabel(edgeTestRoot, "nettwo", otherNetworkId)
	test.restore.SetOpenCase(flaggedNetworkId, true)
	key := func(owner string, rrType uint16) dnsservice.DnsRecordKey {
		return dnsservice.DnsRecordKey{Owner: owner + edgeTestRoot, Type: rrType}
	}
	user := dnsservice.DnsRecordKindUser
	test.ns.serve("ns1", 9)
	test.ns.serve("ns2", 9)
	test.ns.follow("ns1",
		[]dnsservice.DnsRecordKey{key("www.netone.", dns.TypeA), key("_acme-challenge.netone.", dns.TypeTXT), key("nettwo.", dns.TypeMX), key("", dns.TypeTXT)},
		[]dnsservice.DnsRecordKind{user, dnsservice.DnsRecordKindChallenge, dnsservice.DnsRecordKindSystem, dnsservice.DnsRecordKindSystem})
	test.ns.follow("ns2",
		[]dnsservice.DnsRecordKey{key("www.netone.", dns.TypeA), key("canary.", dns.TypeTXT), key("api.nettwo.", dns.TypeAAAA)},
		[]dnsservice.DnsRecordKind{user, dnsservice.DnsRecordKindCanary, user})
	incidentId := sidecar.NewId()
	progress := test.run(t, incidentId)
	if progress.DiffCount != 2 || progress.Listing == nil {
		t.Fatalf("progress %+v", progress)
	}
	listed := map[dnsservice.DnsRecordKey]dnsservice.DnsRestoreEntry{}
	for _, entry := range progress.Listing.Entries {
		entryKey := dnsservice.DnsRecordKey{Owner: entry.Owner, Type: entry.Type}
		if _, twice := listed[entryKey]; twice {
			t.Errorf("%v listed twice", entryKey)
		}
		listed[entryKey] = entry
	}
	if len(listed) != 4 {
		t.Errorf("listed %v", listed)
	}
	for _, left := range []dnsservice.DnsRecordKey{key("_acme-challenge.netone.", dns.TypeTXT), key("canary.", dns.TypeTXT)} {
		if _, ok := listed[left]; ok {
			t.Errorf("%v listed", left)
		}
	}
	if entry := listed[key("www.netone.", dns.TypeA)]; entry.NetworkId == nil || *entry.NetworkId != flaggedNetworkId || !entry.Flagged {
		t.Errorf("the flagged network's entry %+v", entry)
	}
	if entry := listed[key("api.nettwo.", dns.TypeAAAA)]; entry.NetworkId == nil || *entry.NetworkId != otherNetworkId || entry.Flagged {
		t.Errorf("the other network's entry %+v", entry)
	}
	if entry := listed[key("", dns.TypeTXT)]; entry.NetworkId != nil || entry.Flagged {
		t.Errorf("the root's own entry %+v", entry)
	}
	if events := test.restore.AdminEvents(); len(events) != 2 {
		t.Errorf("admin events %+v", events)
	}

	// a rerun after the end lists nothing again
	again := test.run(t, incidentId)
	if len(again.Listing.Entries) != len(progress.Listing.Entries) || len(test.restore.AdminEvents()) != 2 {
		t.Errorf("a rerun listed %d, events %d", len(again.Listing.Entries), len(test.restore.AdminEvents()))
	}
	// an NS that reloaded late posts a diff; a rerun lists only what it brings
	late := &dnsservice.DnsReloadDiff{
		Root: edgeTestRoot, ReplacedSerial: 9, Serial: progress.RestoreSerial + 3,
		Rrsets: []dnsservice.DnsRecordKey{key("www.netone.", dns.TypeA), key("mail.nettwo.", dns.TypeMX)},
		Kinds:  []dnsservice.DnsRecordKind{user, user},
	}
	if err := test.store.RecordReloadDiff(t.Context(), late); err != nil {
		t.Fatal(err)
	}
	lateRun := test.run(t, incidentId)
	if len(lateRun.Listing.Entries) != 5 || len(test.restore.AdminEvents()) != 2 {
		t.Errorf("after a late diff listed %d, events %d", len(lateRun.Listing.Entries), len(test.restore.AdminEvents()))
	}
}

// An NS that misses the SOA read is stopped and left out of the count, so the step ends once the
// running NS serve restore_serial, and GET ready does not wait for it; once it serves restore_serial it
// runs again.
func TestRestoreStepStopsAnNsThatMissesItsSoaRead(t *testing.T) {
	test := newRestoreTest(t)
	test.writeMany(t, 2)
	test.takeDump(t)
	test.loseAndLoad(t)
	test.ns.serve("ns1", 7)
	test.ns.follow("ns1", nil, nil)
	test.ns.silence("ns2")
	incidentId := sidecar.NewId()
	progress := test.run(t, incidentId)
	if !slices.Equal(progress.StoppedNs, []string{"ns2"}) || !progress.Done {
		t.Fatalf("progress %+v", progress)
	}
	stopped, err := test.restore.StoppedNs(t.Context(), edgeTestRoot)
	if err != nil || !slices.Equal(stopped, []string{"ns2"}) {
		t.Errorf("stopped %v %v", stopped, err)
	}

	// it reloads from its local snapshot, posting its diff, and serves restore_serial: the next run
	// starts it
	test.ns.serve("ns2", 5)
	test.ns.follow("ns2", nil, nil)
	again := test.run(t, incidentId)
	if len(again.StoppedNs) != 0 {
		t.Errorf("still stopped %v", again.StoppedNs)
	}
	if stopped, _ := test.restore.StoppedNs(t.Context(), edgeTestRoot); len(stopped) != 0 {
		t.Errorf("dns_ns still holds %v", stopped)
	}
}

// Where no NS state can be kept (dns_ns before its §2.8 row), an NS that misses its SOA read is counted
// still, so restoring holds until it serves restore_serial: plan-DNS-running-ns's interim.
func TestRestoreStepWaitsForEveryNsWhenNoneCanBeStopped(t *testing.T) {
	test := newRestoreTest(t)
	test.restore.SetNsStateUnavailable(true)
	test.writeMany(t, 2)
	test.takeDump(t)
	test.loseAndLoad(t)
	test.ns.serve("ns1", 7)
	test.ns.follow("ns1", nil, nil)
	test.ns.silence("ns2")
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	var progress *dnsservice.DnsRestoreProgress
	var runErr error
	go func() {
		defer close(done)
		progress, runErr = test.step.Run(ctx, edgeTestRoot, sidecar.NewId())
	}()
	// both NS read before the transaction and once after it: what the step waits on is then fixed
	test.ns.awaitReads(t, 4)
	cancel()
	<-done
	if !errors.Is(runErr, context.Canceled) || progress == nil || !slices.Equal(progress.WaitingNs, []string{"ns2"}) || !slices.Equal(progress.CountedNs, []string{"ns2"}) || progress.Done {
		t.Fatalf("progress %+v %v", progress, runErr)
	}
	if !test.state(t).Restoring {
		t.Error("restoring cleared while ns2 is behind")
	}
}

// The step runs only inside the restoring it is for: not after restoring was cleared for no restore, and
// not for a second incident once one has committed.
func TestRestoreStepRunsOnlyInItsOwnRestoring(t *testing.T) {
	test := newRestoreTest(t)
	test.writeMany(t, 2)
	if _, err := test.step.Run(t.Context(), edgeTestRoot, sidecar.NewId()); !errors.Is(err, dnsservice.ErrDnsNotRestoring) {
		t.Errorf("not restoring: %v", err)
	}
	test.takeDump(t)
	test.loseAndLoad(t)
	test.ns.serve("ns1", 3)
	test.ns.serve("ns2", 3)
	test.ns.follow("ns1", nil, nil)
	test.ns.follow("ns2", nil, nil)
	first := sidecar.NewId()
	if _, err := test.store.CommitRestore(t.Context(), edgeTestRoot, first, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := test.step.Run(t.Context(), edgeTestRoot, sidecar.NewId()); !errors.Is(err, dnsservice.ErrDnsRestoreIncident) {
		t.Errorf("a second incident: %v", err)
	}
	if _, err := test.step.Run(t.Context(), "other.example.", first); !errors.Is(err, dnsservice.ErrDnsRootUnknown) {
		t.Errorf("another root: %v", err)
	}
}

// After the step, GET ready answers stale for every challenge committed before the loss, whatever its
// serial: one the dump holds, and one the NS never served whose raise was lost, above every SOA read and
// the key, since restore_serial lands 2^24 above them all. A challenge written after the step reads
// ready once both NS serve it.
func TestRestoreStepLeavesEveryEarlierChallengeStale(t *testing.T) {
	api := newTestApi(t, nil)
	api.cleanCanary()
	test := &restoreTest{clock: api.clock, store: api.store, restore: sidecartest.NewFakeDnsRestoreStore(api.clock), settings: api.settings}
	test.ns = newRestoreTestNs(api.store)
	test.step = test.newStep(t)
	dumpedChallenge := test.writeMany(t, 2)
	test.takeDump(t)
	lost := test.writeMany(t, 4)
	test.loseAndLoad(t)
	test.ns.serve("ns1", uint32(lost))
	test.ns.serve("ns2", uint32(lost-1))
	test.ns.follow("ns1", nil, nil)
	test.ns.follow("ns2", nil, nil)
	progress := test.run(t, sidecar.NewId())
	unservedChallenge := lost + 1000
	for _, serial := range []uint64{dumpedChallenge, unservedChallenge} {
		if answer := api.awaitAnswer(t, api.askReady(t, serial)); answer.Answer != dnsservice.DnsReadyStale || answer.RestoreSerial != progress.RestoreSerial {
			t.Errorf("serial %d: %+v", serial, answer)
		}
	}
	after := test.write(t, "_acme-challenge.after."+edgeTestRoot)
	api.soa.set("ns1", uint32(after))
	api.soa.set("ns2", uint32(after))
	if answer := api.awaitAnswer(t, api.askReady(t, after)); answer.Answer != dnsservice.DnsReadyReady {
		t.Errorf("a challenge after the step: %+v", answer)
	}
}
