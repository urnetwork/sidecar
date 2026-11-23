// QD-817's join on the test network: a device whose keychain holds no generation of the config repo, so it opens no
// config head, follows the log past base 1 rows-only, handing each state it so reaches to its key client unconfirmed
// and nothing else; once the key client takes its Welcome the full pass re-reads every base from the genesis, each head
// judged, and only then does the client answer WaitFor; a forged head at a base the rows-only pass applied withholds
// that pass's confirmation; and a device that holds the key, from the start or at a restart, keeps the full check from
// base 1, never running the rows-only pass. The key client and the head reader over evs are fakes that share whether
// the keychain holds the config key, since a head reader over evs opens a head only with it.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// How long, in real time, a join step waits before it fails: a guard only, since every wait is on a monitor.
const testConfigJoinTimeout = 30 * time.Second

// A key client's config join as a ConfigClient meets it (GkmConfigJoiner): whether the keychain holds the config key,
// the channel the next key taken closes, and each unconfirmed state handed over.
type testConfigJoiner struct {
	stateLock sync.Mutex
	held      bool
	changed   chan struct{}
	// the unconfirmed states handed over, and the config repo each named
	unconfirmed   []*ConfigState
	configRepoIds []Id
	// the newest version handed over, which a test waits on
	handed *MonitorValue[uint64]
}

var _ GkmConfigJoiner = (*testConfigJoiner)(nil)

func newTestConfigJoiner(held bool) *testConfigJoiner {
	return &testConfigJoiner{held: held, changed: make(chan struct{}), handed: NewMonitorValue[uint64](0)}
}

func (self *testConfigJoiner) RepoKeyHeld(repoId Id) (bool, <-chan struct{}) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.held, self.changed
}

func (self *testConfigJoiner) AuthUnconfirmed(state GkmAuthView, configRepoId Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	configState, _ := state.(*ConfigState)
	self.unconfirmed = append(self.unconfirmed, configState)
	self.configRepoIds = append(self.configRepoIds, configRepoId)
	self.handed.Set(state.Pin().GetVersion())
}

// The keychain takes the config key, as a Welcome's join keeps it: every waiter looks again.
func (self *testConfigJoiner) hold() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.held {
		return
	}
	self.held = true
	close(self.changed)
	self.changed = make(chan struct{})
}

// The unconfirmed states handed over so far, and the config repos they named.
func (self *testConfigJoiner) handedStates() ([]*ConfigState, []Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.unconfirmed), slices.Clone(self.configRepoIds)
}

// Waits until a state at n or past it was handed over.
func (self *testConfigJoiner) waitHanded(t *testing.T, n uint64) {
	t.Helper()
	guard := time.After(testConfigJoinTimeout)
	for {
		version, changed := self.handed.Get()
		if n <= version {
			return
		}
		select {
		case <-changed:
		case <-guard:
			t.Fatalf("the key client was handed %d, not %d", version, n)
		}
	}
}

// The config repo's heads as a device reads them over evs: none opens until the key client holds the config key, every
// read is recorded, and a forger's head answers for the versions forged names.
type testConfigKeyedHeads struct {
	next   ConfigHeadReader
	joiner *testConfigJoiner
	forged map[uint64]*ConfigHead

	stateLock sync.Mutex
	// the versions read with the key held, and those withheld for want of it
	opened   []uint64
	withheld []uint64
}

func newTestConfigKeyedHeads(next ConfigHeadReader, joiner *testConfigJoiner) *testConfigKeyedHeads {
	return &testConfigKeyedHeads{next: next, joiner: joiner, forged: map[uint64]*ConfigHead{}}
}

func (self *testConfigKeyedHeads) ReadConfigHead(ctx context.Context, configVersion uint64, configHeadSha256 []byte) (*ConfigHead, error) {
	held, _ := self.joiner.RepoKeyHeld(Id{})
	forged := func() *ConfigHead {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if !held {
			self.withheld = append(self.withheld, configVersion)
			return nil
		}
		self.opened = append(self.opened, configVersion)
		return self.forged[configVersion]
	}()
	switch {
	case !held:
		return nil, fmt.Errorf("%w: no generation of the config repo is held", ErrConfigHeadUnavailable)
	case forged != nil:
		return forged, nil
	}
	return self.next.ReadConfigHead(ctx, configVersion, configHeadSha256)
}

// The versions read so far, opened and withheld.
func (self *testConfigKeyedHeads) reads() ([]uint64, []uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.opened), slices.Clone(self.withheld)
}

// A client on the world reading heads through heads and joining through joiner, closed at the test's end. settings nil
// is the defaults.
func (self *testConfigClientWorld) joiningClient(heads ConfigHeadReader, joiner GkmConfigJoiner, settings *ConfigClientSettings) *ConfigClient {
	self.t.Helper()
	if settings == nil {
		settings = DefaultConfigClientSettings()
	}
	settings.LogSettings = testConfigLogSettings()
	settings.Log = NewNoopLogger()
	client, err := NewConfigClient(context.Background(), &ConfigClientArgs{
		NetworkId:    self.net.networkId,
		GenesisChain: bridge.GenesisChain(self.net.signedGenesis),
		Projection:   self.projection,
		Heads:        heads,
		Store:        self.store,
		Gkm:          self.gkm,
		Joiner:       joiner,
		Emit: func(event SidecarEvent) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.events = append(self.events, event)
		},
		ReportFork: func(fork HeadFork) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.forks = append(self.forks, fork)
		},
		Clock:    self.clock,
		Settings: settings,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(client.Close)
	return client
}

// The positions KEYS's AuthAdvanced saw.
func (self *testConfigGkm) advancedPositions() []uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.positions)
}

// A network past base 1, base 2 folding a member's admission, then the device that joins admitted by the member's
// first device: what a member device that is not the network's first meets. Answers the joining device.
func (self *testConfigClientWorld) joinedNetwork() testConfigDevice {
	self.t.Helper()
	net := self.net
	member, first := net.consentedMember("m")
	net.fold(net.owner, net.n, 2)
	joining := net.device("m joining", member)
	net.admitDevice(first, joining, 0)
	self.publish()
	return joining
}

// Whether a client answers WaitFor for n now, with a context already done: false while nothing confirms n.
func testConfigWaitAnswers(client *ConfigClient, n uint64) bool {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	state, err := client.WaitFor(ctx, n)
	return err == nil && state != nil
}

// A device with no config key follows the log past base 1 rows-only: the key client alone hears of it, unconfirmed and
// naming the genesis's config repo, its pin is kept as the floor, the full pass's first head is withheld for want of the
// key, and nothing answers State, VerifiedState or WaitFor, no AuthAdvanced and no entry callback. Once the key client
// takes its Welcome the full pass re-reads every base from the genesis, each head judged, and the client stands on the
// network's state, the rows-only log gone, and follows on as any reader does.
func TestConfigClientJoinsRowsOnlyThenStandsOnTheFullReread(t *testing.T) {
	world := newTestConfigClientWorld(t)
	net := world.net
	joining := world.joinedNetwork()
	joiner := newTestConfigJoiner(false)
	heads := newTestConfigKeyedHeads(world.heads, joiner)
	client := world.joiningClient(heads, joiner, nil)
	callbacks := []uint64{}
	var callbacksLock sync.Mutex
	defer client.AddEntryCallback(func(entry *SidecarAuthorityEntry) {
		callbacksLock.Lock()
		defer callbacksLock.Unlock()
		callbacks = append(callbacks, entry.Pin.GetVersion())
	})()

	joiner.waitHanded(t, net.n)
	states, configRepoIds := joiner.handedStates()
	last := states[len(states)-1]
	if last == nil || !proto.Equal(last.Pin(), net.log.Pin()) || last.SidecarRow(joining.sidecarId) == nil {
		t.Fatalf("the key client was handed %v, not the tip admitting the joining device", last.Pin())
	}
	for _, configRepoId := range configRepoIds {
		if configRepoId != testConfigId("config repo") {
			t.Fatalf("an unconfirmed state named repo %s, not the genesis's config repo", configRepoId)
		}
	}
	if pin := client.UnconfirmedPin(); !proto.Equal(pin, net.log.Pin()) {
		t.Fatalf("the rows-only pass stands at %v", pin)
	}
	if client.State() != nil || client.VerifiedState() != nil || client.Log() != nil || client.Pin() != nil {
		t.Fatal("a rows-only state answers as verified")
	}
	if testConfigWaitAnswers(client, 1) {
		t.Fatal("WaitFor answered a position only the rows-only pass applied")
	}
	if positions := world.gkm.advancedPositions(); len(positions) != 0 {
		t.Fatalf("AuthAdvanced saw %v before any base was confirmed", positions)
	}
	if opened, withheld := heads.reads(); len(opened) != 0 || !slices.Contains(withheld, 1) {
		t.Fatalf("heads opened %v, withheld %v, before the key", opened, withheld)
	}
	if _, pin := world.store.keptEntries(t); pin != net.n {
		t.Fatalf("authlog/ keeps pin %d, not the rows-only pass's %d", pin, net.n)
	}
	if world.headAlarms(SidecarHeadAlarmFork) != 0 || world.headAlarms(SidecarHeadAlarmWithheld) != 0 {
		t.Fatal("the rows-only pass raised a head_alarm")
	}
	handedBefore := len(states)

	// the key client takes its Welcome: the follower wakes for the full pass
	joiner.hold()
	state := world.caughtUp(client)
	testConfigStatesEqual(t, state, net.log.State())
	if opened, _ := heads.reads(); !slices.Contains(opened, 1) || !slices.Contains(opened, 2) {
		t.Errorf("the full re-read opened heads %v, not every base's", opened)
	}
	if client.UnconfirmedPin() != nil {
		t.Error("the rows-only log outlived the confirmation")
	}
	if positions := world.gkm.advancedPositions(); len(positions) == 0 || positions[len(positions)-1] != net.n {
		t.Errorf("AuthAdvanced saw %v", positions)
	}
	if states, _ := joiner.handedStates(); len(states) != handedBefore {
		t.Errorf("%d unconfirmed states were handed over after the key was held", len(states)-handedBefore)
	}
	callbacksLock.Lock()
	if len(callbacks) != 0 {
		t.Errorf("entry callbacks heard %v of the history the confirmation published", callbacks)
	}
	callbacksLock.Unlock()

	// on as any reader: a new entry reaches its callback once, and the key client's AuthAdvanced
	net.admitMember(net.owner, testConfigId("after the join"), bridge.MemberRole_MEMBER_ROLE_MEMBER)
	world.publish()
	client.ReceiveNotice(PushNotice{Topic: PushTopicTeam, Version: net.n})
	testConfigStatesEqual(t, world.caughtUp(client), net.log.State())
	callbacksLock.Lock()
	if len(callbacks) != 1 || callbacks[0] != net.n {
		t.Errorf("entry callbacks heard %v after the join", callbacks)
	}
	callbacksLock.Unlock()
}

// A forged head at a base the rows-only pass applied: once the key is held the full pass meets it, a fork its start
// meets, which the client holds and stops at as at a held log's fork (QD-1209), with head_alarm fork once. Nothing is
// confirmed, a wait answers the fork, a follow after it opens no head again, and the rows-only log itself is not
// forked: the device never stands on what that pass applied. Before QD-1209 the full pass was refused and ran again
// at every follow, the client unforked, and the wait answered nothing.
func TestConfigClientRereadHoldsTheForkAtAForgedHead(t *testing.T) {
	world := newTestConfigClientWorld(t)
	net := world.net
	world.joinedNetwork()
	joiner := newTestConfigJoiner(false)
	heads := newTestConfigKeyedHeads(world.heads, joiner)
	// base 2's head as a forger answers it: base 1's, which holds none of the records base 2 folds
	forged, err := world.heads.ReadConfigHead(context.Background(), 1, testConfigHeadSha256(1))
	if err != nil {
		t.Fatal(err)
	}
	heads.forged[2] = forged
	client := world.joiningClient(heads, joiner, nil)
	joiner.waitHanded(t, net.n)

	joiner.hold()
	ctx, cancel := context.WithTimeout(context.Background(), testConfigJoinTimeout)
	defer cancel()
	err = client.CatchUp(ctx)
	fork := &ConfigForkError{}
	if !errors.As(err, &fork) {
		t.Fatalf("the full pass over a forged head: %v", err)
	}
	opened, _ := heads.reads()
	if !slices.Contains(opened, 2) {
		t.Fatalf("the full pass did not reach the forged head: %v", opened)
	}
	if client.State() != nil || client.VerifiedState() != nil || testConfigWaitAnswers(client, 1) {
		t.Fatal("a log whose re-read met a forged head was confirmed")
	}
	if pin := client.UnconfirmedPin(); !proto.Equal(pin, net.log.Pin()) {
		t.Errorf("the rows-only pass stands at %v", pin)
	}
	if client.Fork() != fork || client.unconfirmed.Load().Fork() != nil {
		t.Errorf("the client holds %v, its rows-only log forked %v: want the full pass's fork held, the rows-only log unforked", client.Fork(), client.unconfirmed.Load().Fork())
	}
	waitCtx, waitCancel := context.WithCancel(context.Background())
	waitCancel()
	if _, err := client.WaitFor(waitCtx, net.n); err != fork {
		t.Errorf("a wait answered %v, want the held fork", err)
	}
	if err := client.CatchUp(ctx); err != fork {
		t.Errorf("a follow after the fork answered %v, want the held fork", err)
	}
	if again, _ := heads.reads(); len(again) != len(opened) {
		t.Errorf("a follow after the fork opened heads %v again", again[len(opened):])
	}
	if alarms := world.headAlarms(SidecarHeadAlarmFork); alarms != 1 {
		t.Errorf("head_alarm fork raised %d times for the forged head, want once", alarms)
	}
	if positions := world.gkm.advancedPositions(); len(positions) != 0 {
		t.Errorf("AuthAdvanced saw %v", positions)
	}
}

// A device that holds the config key keeps the full check from base 1: one holding it from the start never runs the
// rows-only pass and reads every base's head; so does its restart; and a device that joined rows-only and restarted
// once its keychain took the key judges its kept entries in full from base 1, handing nothing more unconfirmed.
func TestConfigClientWithTheConfigKeyChecksEveryHeadFromBaseOne(t *testing.T) {
	world := newTestConfigClientWorld(t)
	net := world.net
	world.joinedNetwork()
	desktop := func() *ConfigClientSettings {
		settings := DefaultConfigClientSettings()
		settings.RetainFullTail = true
		return settings
	}

	keyed := newTestConfigJoiner(true)
	heads := newTestConfigKeyedHeads(world.heads, keyed)
	client := world.joiningClient(heads, keyed, desktop())
	testConfigStatesEqual(t, world.caughtUp(client), net.log.State())
	if states, _ := keyed.handedStates(); len(states) != 0 {
		t.Errorf("a device holding the key handed %d states over unconfirmed", len(states))
	}
	if opened, withheld := heads.reads(); !slices.Equal(opened, []uint64{1, 2}) || len(withheld) != 0 {
		t.Errorf("heads opened %v, withheld %v", opened, withheld)
	}
	client.Close()

	restartHeads := newTestConfigKeyedHeads(world.heads, keyed)
	restarted := world.joiningClient(restartHeads, keyed, desktop())
	testConfigStatesEqual(t, world.caughtUp(restarted), net.log.State())
	if opened, _ := restartHeads.reads(); !slices.Equal(opened, []uint64{1, 2}) {
		t.Errorf("the restart opened heads %v, not every base's from base 1", opened)
	}
	if states, _ := keyed.handedStates(); len(states) != 0 {
		t.Errorf("the restart handed %d states over unconfirmed", len(states))
	}
	restarted.Close()

	// joined rows-only, then down while the keychain took the key
	world.store = newTestConfigClientStore()
	joiner := newTestConfigJoiner(false)
	joining := world.joiningClient(newTestConfigKeyedHeads(world.heads, joiner), joiner, desktop())
	joiner.waitHanded(t, net.n)
	joining.Close()
	if _, pin := world.store.keptEntries(t); pin != net.n {
		t.Fatalf("authlog/ keeps pin %d, not the rows-only pass's %d", pin, net.n)
	}
	joiner.hold()
	handedBefore, _ := joiner.handedStates()
	keyedHeads := newTestConfigKeyedHeads(world.heads, joiner)
	afterJoin := world.joiningClient(keyedHeads, joiner, desktop())
	testConfigStatesEqual(t, world.caughtUp(afterJoin), net.log.State())
	if opened, _ := keyedHeads.reads(); len(opened) < 2 || opened[0] != 1 || !slices.Contains(opened, 2) {
		t.Errorf("the restart with the key opened heads %v, not every base's from base 1", opened)
	}
	if states, _ := joiner.handedStates(); len(states) != len(handedBefore) {
		t.Errorf("the restart with the key handed %d states over unconfirmed", len(states)-len(handedBefore))
	}
}
