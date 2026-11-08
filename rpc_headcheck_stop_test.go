// HeadStopState's stops on a fake clock: proof of withholding and forks stop at once and clear as §6.4
// says, the witness bound stops shared groups only, the bound's values and refusals, ReportFork, the
// evidence alarms carry, and what survives a restart. Time is a clock the test moves, and the run loop
// wakes only when the test moves it past a wait.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A SidecarStore in memory, flat: every directory is the one store.
type testHeadStopStore struct {
	stateLock sync.Mutex
	files     map[string][]byte
}

// No files.
func newTestHeadStopStore() *testHeadStopStore {
	return &testHeadStopStore{files: map[string][]byte{}}
}

// A copy of the file.
func (self *testHeadStopStore) Open(name string) (io.ReadCloser, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	content, ok := self.files[name]
	if !ok {
		return nil, ErrSidecarStoreAbsent
	}
	return io.NopCloser(bytes.NewReader(bytes.Clone(content))), nil
}

// A writer that swaps the file in at Commit.
func (self *testHeadStopStore) Create(name string) (SidecarStoreWriter, error) {
	return &testHeadStopWriter{store: self, name: name}, nil
}

// Drops the file.
func (self *testHeadStopStore) Remove(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.files, name)
	return nil
}

// The files under prefix, by name.
func (self *testHeadStopStore) List(prefix string) ([]SidecarStoreEntry, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entries := []SidecarStoreEntry{}
	for name, content := range self.files {
		if strings.HasPrefix(name, prefix) {
			entries = append(entries, SidecarStoreEntry{Name: name, ByteCount: int64(len(content))})
		}
	}
	slices.SortFunc(entries, func(a SidecarStoreEntry, b SidecarStoreEntry) int {
		return strings.Compare(a.Name, b.Name)
	})
	return entries, nil
}

// This store.
func (self *testHeadStopStore) Directory(name string, class string) (SidecarStore, error) {
	return self, nil
}

// Replaces a file's bytes, as a corrupted disk would.
func (self *testHeadStopStore) put(name string, content []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.files[name] = bytes.Clone(content)
}

// One file on its way into a testHeadStopStore.
type testHeadStopWriter struct {
	store  *testHeadStopStore
	name   string
	buffer bytes.Buffer
}

// Buffers p.
func (self *testHeadStopWriter) Write(p []byte) (int, error) {
	return self.buffer.Write(p)
}

// Swaps the file in.
func (self *testHeadStopWriter) Commit() error {
	self.store.put(self.name, self.buffer.Bytes())
	return nil
}

// Nothing to drop.
func (self *testHeadStopWriter) Close() error {
	return nil
}

// One wait on a testHeadStopClock.
type testHeadStopWait struct {
	at   time.Time
	fire chan time.Time
}

// A Clock the test moves. Advance fires every wait it reaches; the state's loop mark is how a test
// learns the run loop has armed its next wait, with no sleep.
type testHeadStopClock struct {
	stateLock sync.Mutex
	now       time.Time
	waits     []testHeadStopWait
}

// At testHeadStart.
func newTestHeadStopClock() *testHeadStopClock {
	return &testHeadStopClock{now: testHeadStart}
}

// The time the test moved to.
func (self *testHeadStopClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

// Fires once the test moves the clock past timeout from now.
func (self *testHeadStopClock) After(timeout time.Duration) <-chan time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	fire := make(chan time.Time, 1)
	if timeout <= 0 {
		fire <- self.now
	} else {
		self.waits = append(self.waits, testHeadStopWait{at: self.now.Add(timeout), fire: fire})
	}
	return fire
}

// Calls function once the clock reaches now plus timeout.
func (self *testHeadStopClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	fire := self.After(timeout)
	stopped := make(chan struct{})
	go func() {
		select {
		case <-fire:
			function()
		case <-stopped:
		}
	}()
	var once sync.Once
	return func() bool {
		stoppedNow := false
		once.Do(func() {
			close(stopped)
			stoppedNow = true
		})
		return stoppedNow
	}
}

// Moves the clock and fires every wait it reaches.
func (self *testHeadStopClock) Advance(by time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.now = self.now.Add(by)
	self.waits = slices.DeleteFunc(self.waits, func(wait testHeadStopWait) bool {
		if self.now.Before(wait.at) {
			return false
		}
		wait.fire <- self.now
		return true
	})
}

// A HeadStopState on a fake device, store and clock, with what it raises and asks for collected.
type testHeadStop struct {
	t      *testing.T
	stop   *HeadStopState
	device *testHeadCheckDevice
	store  *testHeadStopStore
	clock  *testHeadStopClock

	stateLock  sync.Mutex
	shared     map[Id]bool
	boundHours uint32
	boundKnown bool

	alarms chan SidecarEvent
	rounds chan struct{}
}

var (
	testHeadSharedGroup = Id{0x5a, 1}
	testHeadOwnGroup    = Id{0x5a, 2}
)

// A state on a fresh store, its run loop parked on its first wait. testHeadSharedGroup holds another
// member's devices and testHeadOwnGroup does not.
func newTestHeadStop(t *testing.T) *testHeadStop {
	fixture := &testHeadStop{
		t:          t,
		device:     newTestHeadCheckWorld(),
		store:      newTestHeadStopStore(),
		clock:      newTestHeadStopClock(),
		shared:     map[Id]bool{testHeadSharedGroup: true},
		boundKnown: true,
		alarms:     make(chan SidecarEvent, 64),
		rounds:     make(chan struct{}, 64),
	}
	fixture.open()
	return fixture
}

// Starts a state on the fixture's store and clock, as a restart does, and waits for its run loop to
// park.
func (self *testHeadStop) open() {
	self.t.Helper()
	stop, err := NewHeadStopState(context.Background(), self.env())
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(stop.Close)
	self.stop = stop
	self.quiesce()
}

// Waits until the run loop has parked having seen every change, so its wait is armed from the clock
// as it stands.
func (self *testHeadStop) quiesce() {
	for {
		mark, notify := self.stop.loopMark.Get()
		if mark.passes != 0 && mark.seen == self.stop.changed.Value() {
			return
		}
		<-notify
	}
}

// Moves the clock by by once the run loop is parked. With wake set the move reaches the loop's wait,
// and this returns once the loop has run its pass and parked again.
func (self *testHeadStop) advance(by time.Duration, wake bool) {
	self.quiesce()
	passes := self.stop.loopMark.Value().passes
	self.clock.Advance(by)
	if !wake {
		return
	}
	for {
		mark, notify := self.stop.loopMark.Get()
		if passes < mark.passes {
			return
		}
		<-notify
	}
}

// What NewHeadStopState takes on this fixture.
func (self *testHeadStop) env() *HeadStopStateEnv {
	device := self.device
	return &HeadStopStateEnv{
		SidecarId: device.sidecarId,
		NetworkId: device.networkId,
		Sources:   &HeadCheckSources{Auth: device, Gens: device, Groups: device, Refs: device, Peers: device},
		Store:     self.store,
		Settings:  DefaultSidecarProtocolSettings(),
		Clock:     self.clock,
		Log:       NewNoopLogger(),
		WitnessBoundHours: func() (uint32, bool) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.boundHours, self.boundKnown
		},
		SharedGroup: func(groupId Id) bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.shared[groupId]
		},
		Alarm: func(event SidecarEvent) {
			self.alarms <- event
		},
		RequestRound: func() {
			self.rounds <- struct{}{}
		},
	}
}

// Sets witness_bound_hours as the state reads it.
func (self *testHeadStop) bound(hours uint32, known bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.boundHours = hours
	self.boundKnown = known
}

// The next alarm, waiting for it.
func (self *testHeadStop) alarm() SidecarEvent {
	return <-self.alarms
}

// Fails if an alarm is waiting.
func (self *testHeadStop) noAlarm() {
	self.t.Helper()
	select {
	case alarm := <-self.alarms:
		self.t.Fatalf("alarm %s %+v", alarm.HeadAlarm, alarm)
	default:
	}
}

// The stop's cause in group, empty for none.
func (self *testHeadStop) cause(groupId Id) HeadStopCause {
	self.t.Helper()
	err := self.stop.SealAllowed(groupId)
	if err == nil {
		return ""
	}
	stopErr := &HeadStopError{}
	if !errors.As(err, &stopErr) || !errors.Is(err, ErrHeadStop) || stopErr.GroupId != groupId {
		self.t.Fatalf("err %v", err)
	}
	return stopErr.Cause
}

// Drives a withheld tip at main 14 from testHeadPeer through the engine: fetched, unserved, proved.
func (self *testHeadStop) withhold() *bridge.AuthPin {
	self.t.Helper()
	tip := testMainChain.pin(14)
	if _, err := self.stop.reconcile(testHeadPeer, self.device.message(tip)); err != nil {
		self.t.Fatal(err)
	}
	// the clock moves short of the run loop's first deadline, so it stays parked
	self.advance(10*time.Minute, false)
	if asks := testActs(self.stop.fetched(), headCheckActAskProof); len(asks) != 1 {
		self.t.Fatalf("asks %+v", asks)
	}
	if step := self.stop.proved(tip, testHeadPeer, [][]byte{[]byte("entry")}, true); step.withheld == nil {
		self.t.Fatal("no withholding")
	}
	return tip
}

func TestHeadStopWithheldStopsSharedGroupsAtOnceUntilServed(t *testing.T) {
	fixture := newTestHeadStop(t)
	if fixture.cause(testHeadSharedGroup) != "" {
		t.Fatal("stopped before anything")
	}
	tip := fixture.withhold()
	alarm := fixture.alarm()
	if alarm.HeadAlarm != SidecarHeadAlarmWithheld || *alarm.SidecarId != testHeadPeer {
		t.Fatalf("alarm %+v", alarm)
	}
	// both pins as evidence: this device's and the withheld tip
	if !bytes.Equal(alarm.Evidence[0], headCheckEvidence(testMainChain.pin(10))) || !bytes.Equal(alarm.Evidence[1], headCheckEvidence(tip)) {
		t.Error("evidence is not the two pins")
	}
	if cause := fixture.cause(testHeadSharedGroup); cause != HeadStopWithheld {
		t.Fatalf("shared group: %q", cause)
	}
	if cause := fixture.cause(testHeadOwnGroup); cause != "" {
		t.Fatalf("own group: %q", cause)
	}
	// served while it holds the tip: the proof it verified
	if proof := fixture.stop.servedProof(); len(proof) != 1 {
		t.Fatalf("served %d", len(proof))
	}
	// once api serves the entries the stop clears, with no alarm
	fixture.device.follow(testMainChain, 1, 15)
	if step := fixture.stop.fetched(); !step.served {
		t.Fatal("not served")
	}
	if cause := fixture.cause(testHeadSharedGroup); cause != "" {
		t.Fatalf("still %q", cause)
	}
	fixture.noAlarm()
}

func TestHeadStopForksStopAtOnce(t *testing.T) {
	fixture := newTestHeadStop(t)
	forkPin := testForkChain(6).pin(10)
	if _, err := fixture.stop.reconcile(testHeadPeer, fixture.device.message(forkPin)); err != nil {
		t.Fatal(err)
	}
	alarm := fixture.alarm()
	if alarm.HeadAlarm != SidecarHeadAlarmFork || *alarm.SidecarId != testHeadPeer ||
		!bytes.Equal(alarm.Evidence[0], headCheckEvidence(testMainChain.pin(10))) || !bytes.Equal(alarm.Evidence[1], headCheckEvidence(forkPin)) {
		t.Fatalf("alarm %+v", alarm)
	}
	// an auth fork stops every shared group, and alarms only in an own one
	if cause := fixture.cause(testHeadSharedGroup); cause != HeadStopFork {
		t.Fatalf("shared group: %q", cause)
	}
	if cause := fixture.cause(testHeadOwnGroup); cause != "" {
		t.Fatalf("own group: %q", cause)
	}
	// the same fork again alarms nothing more
	if _, err := fixture.stop.reconcile(testHeadPeer, fixture.device.message(forkPin)); err != nil {
		t.Fatal(err)
	}
	fixture.noAlarm()
	// the peer's revocation ends the denial, at the next round
	fixture.device.peers[testHeadPeer] = HeadCheckPeer{Admitted: true, Revoked: true}
	fixture.stop.round()
	if cause := fixture.cause(testHeadSharedGroup); cause != "" {
		t.Fatalf("after the revocation: %q", cause)
	}
}

func TestHeadStopReportedForksStopTheirGroup(t *testing.T) {
	fixture := newTestHeadStop(t)
	local := headCheckEvidence(&bridge.AuthPin{Version: 7, Chain: testHeadDigest("main", 7)})
	remote := headCheckEvidence(&bridge.AuthPin{Version: 7, Chain: testHeadDigest("other", 7)})
	// a gen fork in an own group stops that group, as the FORK row says of the affected repo
	fixture.stop.ReportFork(HeadFork{Kind: HeadForkGen, GroupId: testHeadOwnGroup, Local: local, Remote: remote})
	alarm := fixture.alarm()
	if alarm.HeadAlarm != SidecarHeadAlarmFork || alarm.SidecarId != nil || !bytes.Equal(alarm.Evidence[0], local) || !bytes.Equal(alarm.Evidence[1], remote) {
		t.Fatalf("alarm %+v", alarm)
	}
	if cause := fixture.cause(testHeadOwnGroup); cause != HeadStopFork {
		t.Fatalf("its group: %q", cause)
	}
	if cause := fixture.cause(testHeadSharedGroup); cause != "" {
		t.Fatalf("another group: %q", cause)
	}
	// ConfigLog's own fork is an auth fork with no peer, which no revocation clears
	fixture.stop.ReportFork(HeadFork{Kind: HeadForkAuth, Local: local, Remote: remote})
	fixture.alarm()
	fixture.stop.round()
	if cause := fixture.cause(testHeadSharedGroup); cause != HeadStopFork {
		t.Fatalf("shared group: %q", cause)
	}
	// a kind this build does not know stops as widely as an auth fork
	fresh := newTestHeadStop(t)
	fresh.stop.ReportFork(HeadFork{Kind: HeadForkKind(9), Local: local, Remote: remote})
	fresh.alarm()
	if cause := fresh.cause(testHeadSharedGroup); cause != HeadStopFork {
		t.Fatalf("unknown kind: %q", cause)
	}
}

func TestHeadStopUnwitnessedStopsSharedGroupsAtTheBound(t *testing.T) {
	fixture := newTestHeadStop(t)
	// a fresh device runs its clock from this state's start: no stop before the default 72 h; the 24 h
	// alarm comes on the way
	fixture.advance(72*time.Hour-time.Second, true)
	if cause := fixture.cause(testHeadSharedGroup); cause != "" {
		t.Fatalf("early: %q", cause)
	}
	fixture.advance(time.Second, false)
	if cause := fixture.cause(testHeadSharedGroup); cause != HeadStopUnwitnessed {
		t.Fatalf("at the bound: %q", cause)
	}
	// own groups only alarm
	if cause := fixture.cause(testHeadOwnGroup); cause != "" {
		t.Fatalf("own group: %q", cause)
	}
	// a consistent witness ends it
	message := fixture.device.message(testMainChain.pin(10))
	if _, err := fixture.stop.reconcile(testHeadPeer, message); err != nil {
		t.Fatal(err)
	}
	if fixture.stop.witness(testHeadPeer, message, false) == nil {
		t.Fatal("no witness")
	}
	if cause := fixture.cause(testHeadSharedGroup); cause != "" {
		t.Fatalf("after a witness: %q", cause)
	}
}

func TestHeadStopBoundValues(t *testing.T) {
	cases := []struct {
		name  string
		hours uint32
		known bool
		stop  time.Duration
	}{
		{name: "unset", hours: 0, known: true, stop: 72 * time.Hour},
		{name: "least", hours: 24, known: true, stop: 24 * time.Hour},
		{name: "greatest", hours: 168, known: true, stop: 168 * time.Hour},
		{name: "below, refused", hours: 23, known: true, stop: 24 * time.Hour},
		{name: "above, refused", hours: 169, known: true, stop: 24 * time.Hour},
		{name: "unreadable, refused", hours: 168, known: false, stop: 24 * time.Hour},
	}
	for _, c := range cases {
		fixture := newTestHeadStop(t)
		fixture.bound(c.hours, c.known)
		fixture.advance(c.stop-time.Second, c.stop-time.Second >= 24*time.Hour)
		if cause := fixture.cause(testHeadSharedGroup); cause != "" {
			t.Errorf("%s: stopped before %v", c.name, c.stop)
		}
		fixture.advance(time.Second, c.stop == 24*time.Hour)
		if cause := fixture.cause(testHeadSharedGroup); cause != HeadStopUnwitnessed {
			t.Errorf("%s: not stopped at %v", c.name, c.stop)
		}
	}
}

func TestHeadStopPersonalNetworkNeverStops(t *testing.T) {
	fixture := newTestHeadStop(t)
	// a personal network: no group holds another member's devices
	fixture.stateLock.Lock()
	fixture.shared = map[Id]bool{}
	fixture.stateLock.Unlock()
	fixture.withhold()
	fixture.alarm()
	if _, err := fixture.stop.reconcile(testHeadPeerB, fixture.device.message(testForkChain(3).pin(10))); err != nil {
		t.Fatal(err)
	}
	fixture.alarm()
	fixture.advance(169*time.Hour, true)
	for _, groupId := range []Id{testHeadSharedGroup, testHeadOwnGroup} {
		if cause := fixture.cause(groupId); cause != "" {
			t.Errorf("%s: %q", groupId, cause)
		}
	}
}

func TestHeadStopUnverifiedAlarmsAndShowsInStatus(t *testing.T) {
	fixture := newTestHeadStop(t)
	pin := testMainChain.pin(14)
	if _, err := fixture.stop.reconcile(testHeadPeer, fixture.device.message(pin)); err != nil {
		t.Fatal(err)
	}
	fixture.advance(10*time.Minute, false)
	fixture.stop.fetched()
	fixture.stop.proved(pin, testHeadPeer, nil, false)
	alarm := fixture.alarm()
	if alarm.HeadAlarm != SidecarHeadAlarmUnverified || *alarm.SidecarId != testHeadPeer || !bytes.Equal(alarm.Evidence[1], headCheckEvidence(pin)) {
		t.Fatalf("alarm %+v", alarm)
	}
	if unverified := fixture.stop.Unverified(); len(unverified) != 1 || !bytes.Equal(unverified[0], headCheckEvidence(pin)) {
		t.Fatalf("status %x", unverified)
	}
	// it rides on to the next peer
	if _, relayed := fixture.stop.relayed(testHeadPeerB); len(relayed) != 1 {
		t.Fatalf("relayed %+v", relayed)
	}
	// and while it is held, no peer counts, so the bound runs
	message := fixture.device.message(testMainChain.pin(10))
	if _, err := fixture.stop.reconcile(testHeadPeerB, message); err != nil {
		t.Fatal(err)
	}
	if fixture.stop.witness(testHeadPeerB, message, false) != nil || !fixture.stop.WitnessedAt().IsZero() {
		t.Fatal("witnessed while holding an UNVERIFIED pin")
	}
}

func TestHeadStopStateSurvivesARestart(t *testing.T) {
	fixture := newTestHeadStop(t)
	// a witness, a fork, a withheld tip and a revocation, then a restart
	message := fixture.device.message(testMainChain.pin(10))
	if _, err := fixture.stop.reconcile(testHeadPeerB, message); err != nil {
		t.Fatal(err)
	}
	fixture.stop.witness(testHeadPeerB, message, false)
	witnessedAt := fixture.stop.WitnessedAt()
	fixture.stop.ReportFork(HeadFork{Kind: HeadForkRef, GroupId: testHeadOwnGroup, Local: []byte{1}, Remote: []byte{2}, PeerId: &testHeadPeerC})
	fixture.alarm()
	fixture.withhold()
	fixture.alarm()
	fixture.stop.TrackRevocation(9)
	<-fixture.rounds
	before := struct {
		shared, own HeadStopCause
		unverified  [][]byte
		positions   []uint64
		proof       [][]byte
	}{
		shared:     fixture.cause(testHeadSharedGroup),
		own:        fixture.cause(testHeadOwnGroup),
		unverified: fixture.stop.Unverified(),
		positions:  fixture.stop.UnwitnessedRevocations(),
		proof:      fixture.stop.servedProof(),
	}
	fixture.stop.Close()

	fixture.open()
	if !fixture.stop.WitnessedAt().Equal(witnessedAt) || witnessedAt.IsZero() {
		t.Errorf("witnessed_at %v, want %v", fixture.stop.WitnessedAt(), witnessedAt)
	}
	if cause := fixture.cause(testHeadSharedGroup); cause != before.shared || cause != HeadStopWithheld {
		t.Errorf("shared group %q, want %q", cause, before.shared)
	}
	if cause := fixture.cause(testHeadOwnGroup); cause != before.own || cause != HeadStopFork {
		t.Errorf("own group %q, want %q", cause, before.own)
	}
	if !slices.Equal(fixture.stop.UnwitnessedRevocations(), before.positions) || len(before.positions) != 1 {
		t.Errorf("revocations %v", fixture.stop.UnwitnessedRevocations())
	}
	if proof := fixture.stop.servedProof(); len(proof) != 1 || !bytes.Equal(proof[0], before.proof[0]) {
		t.Errorf("proof %q", proof)
	}
	// the revoker asks for its round at the start, and nothing alarms again
	<-fixture.rounds
	fixture.noAlarm()
}

func TestHeadStopRefusesAStateThatDoesNotDecode(t *testing.T) {
	fixture := newTestHeadStop(t)
	fixture.stop.Close()
	for _, content := range []string{"", "{", `{"version":2,"unwitnessed_since_ms":1}`, `{"version":1}`, `{"version":1,"unwitnessed_since_ms":1,"extra":true}`,
		`{"version":1,"unwitnessed_since_ms":1,"forks":[{"kind":7,"group_id":"00000000000000000000000000","local":"","remote":"","at_ms":1}]}`} {
		fixture.store.put(headStopFileName, []byte(content))
		if _, err := NewHeadStopState(context.Background(), fixture.env()); !errors.Is(err, errHeadStopDocument) {
			t.Errorf("%q: %v", content, err)
		}
	}
}

func TestHeadStopEnvIsRequiredWhole(t *testing.T) {
	fixture := newTestHeadStop(t)
	cases := []func(env *HeadStopStateEnv){
		func(env *HeadStopStateEnv) { env.Store = nil },
		func(env *HeadStopStateEnv) { env.Clock = nil },
		func(env *HeadStopStateEnv) { env.WitnessBoundHours = nil },
		func(env *HeadStopStateEnv) { env.SharedGroup = nil },
		func(env *HeadStopStateEnv) { env.Alarm = nil },
		func(env *HeadStopStateEnv) { env.RequestRound = nil },
		func(env *HeadStopStateEnv) { env.Sources.Refs = nil },
	}
	for i, adjust := range cases {
		env := fixture.env()
		adjust(env)
		if _, err := NewHeadStopState(context.Background(), env); err == nil {
			t.Errorf("case %d: built", i)
		}
	}
}
