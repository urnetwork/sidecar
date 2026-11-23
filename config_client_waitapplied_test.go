//go:build !sidecar_http && !js

// ConfigClient's waits for a position, WaitFor's and WaitForPin's, end at a fork the client's own follow records
// (config-client-waitapplied-fork). A fork stops the log where it was, so the position the waits watch never moves,
// and a wait that watched the position alone slept until its ctx ended: a writer whose base forked its own follower
// waited so in ConfigWriter.publish, in the fold loop for PublishTimeout's 60 s, after which the loop logged that the
// base did not land. The log's fork, which its follower records, is read under the log's lock, so a wait and every
// other reader of ConfigClient.Fork may ask for it from their own goroutines.
//
// On T2's fake api with real ConfigClients, ConfigWriters and ConfigLogs, each wait is held to the order that lost the
// fork: the follower's read of the entries that fork it answers only once the wait has looked at the log and parks,
// which the wait's ctx tells the test at its first Done once armed (testWaitAppliedCtx), so the fork lands after every
// look the wait took. Each wait's ctx ends after 30 s, so a wait the fork does not end fails the test rather than
// hanging it, and a wait that answers the fork took it as the follow recorded it.

package sidecar_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A wait's ctx, ending after 30 s, that tells the test when the wait has looked at the log and parks: its first Done
// once armed closes parked. ConfigClient's wait calls Done as it enters its select, after it read the position and the
// fork, so nothing the follow records once parked closes was there for that look to see.
type testWaitAppliedCtx struct {
	context.Context
	parked chan struct{}

	stateLock sync.Mutex
	armed     bool
	closed    bool
}

// A wait's ctx under parent, armed from the start when armed is set, else by arm.
func newTestWaitAppliedCtx(t *testing.T, parent context.Context, armed bool) *testWaitAppliedCtx {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	t.Cleanup(cancel)
	return &testWaitAppliedCtx{Context: ctx, parked: make(chan struct{}), armed: armed}
}

// Makes the next Done close parked.
func (self *testWaitAppliedCtx) arm() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.armed = true
}

// The wrapped ctx's, closing parked first when armed.
func (self *testWaitAppliedCtx) Done() <-chan struct{} {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.armed && !self.closed {
			self.closed = true
			close(self.parked)
		}
		self.armed = false
	}()
	return self.Context.Done()
}

// api's projection as one follower reads it. While held, a read finding entries answers only once let, or once its ctx
// ends, so no follow applies them before the test lets it; a read finding none answers at once. A forged entry, once
// set, is served after api's last, as a server forking this follower would serve it.
type testWaitAppliedProjection struct {
	reader sidecar.ConfigProjectionReader

	stateLock sync.Mutex
	// closed by let, nil while nothing is held
	release   chan struct{}
	forged    []byte
	forgedPin *bridge.AuthPin
}

// Holds every read that finds entries until let.
func (self *testWaitAppliedProjection) hold() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.release = make(chan struct{})
}

// Lets the held reads answer, and holds no more.
func (self *testWaitAppliedProjection) let() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.release != nil {
		close(self.release)
		self.release = nil
	}
}

// Serves entryBytes, at pin, after api's last entry.
func (self *testWaitAppliedProjection) forge(entryBytes []byte, pin *bridge.AuthPin) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.forged, self.forgedPin = entryBytes, pin
}

// api's read, the forged entry after its last, held while the test holds reads.
func (self *testWaitAppliedProjection) ReadConfigProjection(ctx context.Context, after uint64) (*sidecar.ConfigProjection, error) {
	projection, err := self.reader.ReadConfigProjection(ctx, after)
	if err != nil {
		return nil, err
	}
	release, forged, forgedPin := func() (chan struct{}, []byte, *bridge.AuthPin) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.release, self.forged, self.forgedPin
	}()
	if forged != nil && after < forgedPin.GetVersion() && !projection.More {
		projection.Entries = append(projection.Entries, forged)
		projection.Tip = forgedPin
	}
	if release != nil && len(projection.Entries) != 0 {
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return projection, nil
}

// An entry at the position after pin, chaining onto it, of a base whose body is no Signed ProjectionHeader: a run
// carrying it chains, and every reader's apply forks there (§7.9's base row), a rows-only reader's included. Its pin
// with it.
func testWaitAppliedForgedBase(world *testWriterWorld, pin *bridge.AuthPin) ([]byte, *bridge.AuthPin) {
	world.t.Helper()
	entry := &bridge.AuthEntry{
		NetworkId: world.networkId.Bytes(),
		N:         pin.GetVersion() + 1,
		PrevChain: pin.GetChain(),
		Kind:      bridge.AuthEntryKindBase,
		TimeMs:    world.clock.Now().UnixMilli(),
		Body:      []byte{0xff},
	}
	entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
	if err != nil {
		world.t.Fatal(err)
	}
	chain, err := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
	if err != nil {
		world.t.Fatal(err)
	}
	return entryBytes, &bridge.AuthPin{Version: entry.GetN(), Chain: chain[:]}
}

// A follower of the world's network over projection and heads, a joining device's when joiner is not nil, on the
// world's clock and closed at the test's end.
func testWaitAppliedClient(world *testWriterWorld, projection sidecar.ConfigProjectionReader, heads sidecar.ConfigHeadReader, joiner sidecar.GkmConfigJoiner) *sidecar.ConfigClient {
	world.t.Helper()
	settings := sidecar.DefaultConfigClientSettings()
	settings.Log = sidecar.NewNoopLogger()
	logSettings := sidecar.DefaultConfigLogSettings()
	logSettings.Log = sidecar.NewNoopLogger()
	settings.LogSettings = logSettings
	client, err := sidecar.NewConfigClient(world.ctx, &sidecar.ConfigClientArgs{
		NetworkId:    world.networkId,
		GenesisChain: world.genesis.GenesisChain,
		Projection:   projection,
		Heads:        heads,
		Joiner:       joiner,
		Clock:        world.clock,
		Settings:     settings,
	})
	if err != nil {
		world.t.Fatal(err)
	}
	world.t.Cleanup(client.Close)
	return client
}

// Runs wait on its own goroutine with projection's reads that find entries held until the wait has looked at the log
// and parks (ctx's parked), then lets them, and answers what the wait returned. Fails the test where the wait answers
// before it parks.
func testWaitAppliedRun(t *testing.T, projection *testWaitAppliedProjection, ctx *testWaitAppliedCtx, wait func() error) error {
	t.Helper()
	projection.hold()
	defer projection.let()
	answered := make(chan error, 1)
	go func() {
		answered <- wait()
	}()
	select {
	case <-ctx.parked:
	case err := <-answered:
		t.Fatalf("the wait answered before it parked: %v", err)
	}
	projection.let()
	return <-answered
}

// api's append for a writer, calling landed once api lands a base.
type testWaitAppliedPublisher struct {
	publisher sidecar.ConfigBasePublisher
	landed    func()
}

// api's append; a base that lands calls landed.
func (self *testWaitAppliedPublisher) PublishConfigBase(ctx context.Context, base *sidecar.ConfigBasePublish) (*bridge.AuthPin, error) {
	pin, err := self.publisher.PublishConfigBase(ctx, base)
	if err == nil {
		self.landed()
	}
	return pin, err
}

// A joining device's key client whose keychain takes no generation of the config repo (QD-817): it keeps the newest
// position the rows-only pass handed it.
type testWaitAppliedJoiner struct {
	handed *sidecar.MonitorValue[uint64]
	// never closed: no key arrives
	changed chan struct{}
}

func newTestWaitAppliedJoiner() *testWaitAppliedJoiner {
	return &testWaitAppliedJoiner{handed: sidecar.NewMonitorValue[uint64](0), changed: make(chan struct{})}
}

// None held, and a channel no key closes.
func (self *testWaitAppliedJoiner) RepoKeyHeld(repoId sidecar.Id) (bool, <-chan struct{}) {
	return false, self.changed
}

// Keeps the state's position.
func (self *testWaitAppliedJoiner) AuthUnconfirmed(state sidecar.GkmAuthView, configRepoId sidecar.Id) {
	self.handed.Update(func(handed uint64) uint64 {
		return max(handed, state.Pin().GetVersion())
	})
}

// Fails unless the rows-only pass hands a state at n or past it within 30 s.
func (self *testWaitAppliedJoiner) waitHanded(t *testing.T, n uint64) {
	t.Helper()
	timeout := time.After(30 * time.Second)
	for {
		handed, changed := self.handed.Get()
		if n <= handed {
			return
		}
		select {
		case <-changed:
		case <-timeout:
			t.Fatalf("the rows-only pass handed %d, never %d", handed, n)
		}
	}
}

// The config heads as a device whose keychain holds no generation of the config repo reads them: every head is
// unavailable, which withholds the base naming it (QD-817).
type testWaitAppliedKeylessHeads struct{}

// Unavailable.
func (self testWaitAppliedKeylessHeads) ReadConfigHead(ctx context.Context, configVersion uint64, configHeadSha256 []byte) (*sidecar.ConfigHead, error) {
	return nil, fmt.Errorf("%w: no generation of the config repo held", sidecar.ErrConfigHeadUnavailable)
}

// A config writer's base that forks its own follower: the owner's device saves a head holding a ServiceSettings record
// signed by a device the log never admitted, which api, judging rows alone, appends, and at which the owner's follower,
// judging the head at the state before the base, forks, the record's signer not standing. The save returns that fork
// with the base's pin as soon as the follow records it, though the follow ran only after the save's wait looked at the
// log and parked with 30 s left on its ctx, and the follower stands stopped below the base with that fork.
func TestAWriterWhoseBaseForksItsOwnFollowerReturnsTheFork(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	projection := &testWaitAppliedProjection{reader: world.reader()}
	client := testWaitAppliedClient(world, projection, world.heads, nil)
	before := world.caughtUp(client).Pin()
	ctx := newTestWaitAppliedCtx(t, world.ctx, false)
	// api landing the base arms the ctx, so its next Done is the save's wait's
	writer := world.writer(world.owner, client, &testWaitAppliedPublisher{publisher: world.publisher(), landed: ctx.arm}, 0, nil)
	stranger := testWriterDeviceOf("never admitted", testWriterId("never admitted member"))
	settings := world.statement(stranger, bridge.SignedType_SIGNED_SERVICE_SETTINGS, &protocol.ServiceSettings{MailStrict: true})

	var pin *bridge.AuthPin
	err := testWaitAppliedRun(t, projection, ctx, func() error {
		var err error
		pin, err = writer.SaveHead(ctx, func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error) {
			return head.WithFile(sidecar.ConfigHeadServiceSettingsPath, settings)
		})
		return err
	})
	fork := &sidecar.ConfigForkError{}
	if !errors.As(err, &fork) {
		t.Fatalf("the save answered %v, want its follower's fork", err)
	}
	if pin == nil || pin.GetVersion() != before.GetVersion()+1 || fork.N != pin.GetVersion() ||
		!strings.Contains(fork.Reason, sidecar.ConfigHeadServiceSettingsPath+": its signer") || !strings.Contains(fork.Reason, "is not standing") {
		t.Fatalf("the base landed at %v after %d, and the follower forked at %d: %s", pin, before.GetVersion(), fork.N, fork.Reason)
	}
	if client.Fork() != fork || !proto.Equal(client.Pin(), before) {
		t.Fatalf("the follower stands at %v forked %v", client.Pin(), client.Fork())
	}
}

// A wait for the position past a full reader's pin, WaitFor's and WaitForPin's alike, ends with the fork the follow it
// asks for records there: api serves a base chaining onto the reader's pin whose body is no header, which forks the
// log at that position and leaves the position where it was. The wait returns the fork as the follow records it,
// though the follow ran only after the wait looked at the log and parked with 30 s left on its ctx; the log stays
// stopped, so a wait after it returns the fork at its first look.
func TestAWaitReturnsTheForkItsFollowRecords(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	for _, c := range []struct {
		name string
		wait func(client *sidecar.ConfigClient, ctx context.Context, n uint64) (*sidecar.ConfigState, error)
	}{
		{name: "WaitFor", wait: (*sidecar.ConfigClient).WaitFor},
		{name: "WaitForPin", wait: (*sidecar.ConfigClient).WaitForPin},
	} {
		projection := &testWaitAppliedProjection{reader: world.reader()}
		client := testWaitAppliedClient(world, projection, world.heads, nil)
		pin := world.caughtUp(client).Pin()
		forged, forgedPin := testWaitAppliedForgedBase(world, pin)
		projection.forge(forged, forgedPin)
		ctx := newTestWaitAppliedCtx(t, world.ctx, true)
		err := testWaitAppliedRun(t, projection, ctx, func() error {
			_, err := c.wait(client, ctx, forgedPin.GetVersion())
			return err
		})
		fork := &sidecar.ConfigForkError{}
		if !errors.As(err, &fork) || fork.N != forgedPin.GetVersion() {
			t.Fatalf("%s answered %v, want the fork at %d", c.name, err, forgedPin.GetVersion())
		}
		if client.Fork() != fork || !proto.Equal(client.Pin(), pin) {
			t.Fatalf("%s: the client stands at %v forked %v", c.name, client.Pin(), client.Fork())
		}
		if _, err := c.wait(client, newTestWaitAppliedCtx(t, world.ctx, false), forgedPin.GetVersion()); err != fork {
			t.Fatalf("%s after the fork answered %v", c.name, err)
		}
	}
}

// A joining device's wait ends at its rows-only log's fork (QD-817): with no generation of the config repo in its
// keychain, its full pass withholds at base 1 and its rows-only pass follows api's log, until api serves a base
// chaining onto that log's pin whose body is no header, which forks the rows-only log and moves no position. A wait for
// that position returns the fork as the follow records it, as it returns a confirmed log's, though the follow ran only
// after the wait parked; the device stands joining, its rows-only log stopped below the base.
func TestAJoiningDevicesWaitReturnsItsRowsOnlyFork(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	tip, err := world.api.Tip(world.ctx, world.networkId)
	if err != nil {
		t.Fatal(err)
	}
	projection := &testWaitAppliedProjection{reader: world.reader()}
	joiner := newTestWaitAppliedJoiner()
	client := testWaitAppliedClient(world, projection, testWaitAppliedKeylessHeads{}, joiner)
	joiner.waitHanded(t, tip.GetVersion())
	if client.State() != nil || !proto.Equal(client.UnconfirmedPin(), tip) {
		t.Fatalf("the joining device stands at %v, rows-only at %v", client.Pin(), client.UnconfirmedPin())
	}

	forged, forgedPin := testWaitAppliedForgedBase(world, tip)
	projection.forge(forged, forgedPin)
	ctx := newTestWaitAppliedCtx(t, world.ctx, true)
	err = testWaitAppliedRun(t, projection, ctx, func() error {
		_, err := client.WaitFor(ctx, forgedPin.GetVersion())
		return err
	})
	fork := &sidecar.ConfigForkError{}
	if !errors.As(err, &fork) || fork.N != forgedPin.GetVersion() {
		t.Fatalf("the wait answered %v, want the rows-only fork at %d", err, forgedPin.GetVersion())
	}
	if client.Fork() != fork || client.State() != nil || !proto.Equal(client.UnconfirmedPin(), tip) {
		t.Fatalf("the joining device stands at %v, rows-only at %v, forked %v", client.Pin(), client.UnconfirmedPin(), client.Fork())
	}
}

// The log's fork is read under the log's lock while its follower records it: a reader asks a full reader's log for its
// fork on a goroutine of its own, nothing ordering that read and the follow that forks the log, as a wait, a key
// request or a remote search's authority asks ConfigClient.Fork. Under -race this checks that the read and the
// follower's write are ordered, which they were not; on any leg the reader sees no fork or the follower's.
func TestTheLogsForkIsReadUnderItsLockWhileTheFollowerRecordsIt(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	projection := &testWaitAppliedProjection{reader: world.reader()}
	client := testWaitAppliedClient(world, projection, world.heads, nil)
	pin := world.caughtUp(client).Pin()
	forged, forgedPin := testWaitAppliedForgedBase(world, pin)
	projection.forge(forged, forgedPin)

	log := client.Log()
	seen := make(chan *sidecar.ConfigForkError, 1)
	go func() {
		seen <- log.Fork()
	}()
	ctx, cancel := context.WithTimeout(world.ctx, 30*time.Second)
	defer cancel()
	err := client.CatchUp(ctx)
	fork := &sidecar.ConfigForkError{}
	if !errors.As(err, &fork) || fork.N != forgedPin.GetVersion() || log.Fork() != fork {
		t.Fatalf("the follow answered %v, the log's fork %v, want the fork at %d", err, log.Fork(), forgedPin.GetVersion())
	}
	if read := <-seen; read != nil && read != fork {
		t.Fatalf("the reader saw %v, the follower recorded %v", read, fork)
	}
}
