//go:build !sidecar_http && !js

// QD-1205's class for the two records that ride a config head alone and whose failure forks the base (question
// config-head-records-revoked-signer-carried-records): every head carries the network's ServiceSettings and
// VersioningRules forward unchanged, and CheckConfigBase judges each record's signer, standing and of a role that signs
// it, at S(n-1) of every base whose head holds it. So once the device that signed them stops standing, here the owner's
// first device revoked as lost, or its member loses the role, the next base forks every reader that judges it there,
// whoever publishes it and whatever it changes: the fold loop's own fold is enough.
//
// On T2's fake api, whose verifier is api's rows-only ConfigLog, with sidecartest's in-memory config ref and real
// ConfigClients, ConfigWriters and ConfigLogs, these pin down what each kind of reader does with that base as built:
//
//	warm     a device that followed the log through the revocation forks at the base, raises head_alarm (fork) and
//	         reports it to HeadStopState, once; the writer of every such device then refuses to plan, so no device
//	         that followed can publish another base, whatever it would put in the head
//	genesis  a new device while api still serves the log from 1 judges every base on the state it lands on: it forks
//	         at the same base at every follow and installs no state at all
//	cold     a new device that starts at the base, once api's retention point has passed the entries before it, checks
//	         the base's anchor, which judges no record's signer: it takes the base and holds both records, then judges
//	         the next base on the state it lands on and forks there
//	gate     api's sequencer and every rows-only gate (api's ACL gate, evs, gkm) open no head and take every base
//
// They assert the forks as built, which the question raises: §7.9's Writes judges a record at its parent head and
// D-TEAM-26 has what a revoked device signed stand until revoked, so the forks depart from the design. The track that
// builds the answer turns each fork here into the base taken. Every wait is on the client's log or a call's return;
// api's clock never moves, so no fold loop publishes on its own. A writer's follower holds back the head its fold names
// until the fold returns (testRevokedSignerWriter.fold), since a publish whose base forks its own follower meets two
// faults in ConfigClient's wait for that base.

package sidecar_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The ServiceSettings the records' signer files: head-only fields, so a rows-only gate cannot know them.
func testRevokedSignerSettings() *protocol.ServiceSettings {
	return &protocol.ServiceSettings{MailStrict: true, RecordRequired: true}
}

// The VersioningRules the records' signer files.
func testRevokedSignerRules() *protocol.VersioningRules {
	return &protocol.VersioningRules{Rules: []*protocol.VersioningRule{
		{SizeAboveBytes: 1024 * 1024, Versioning: protocol.VersioningMode_VERSIONING_MODE_OFF},
	}}
}

// A head edit filing settings and rules signed by device, each left out when nil, as ur admin settings and ur admin
// versioning file them through the writer.
func testRevokedSignerRecords(world *testWriterWorld, device testWriterDevice, settings *protocol.ServiceSettings, rules *protocol.VersioningRules) func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error) {
	world.t.Helper()
	var settingsBytes, rulesBytes []byte
	if settings != nil {
		settingsBytes = world.statement(device, bridge.SignedType_SIGNED_SERVICE_SETTINGS, settings)
	}
	if rules != nil {
		rulesBytes = world.statement(device, bridge.SignedType_SIGNED_VERSIONING_RULES, rules)
	}
	return func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error) {
		var err error
		if settingsBytes != nil {
			if head, err = head.WithFile(sidecar.ConfigHeadServiceSettingsPath, settingsBytes); err != nil {
				return nil, err
			}
		}
		if rulesBytes != nil {
			if head, err = head.WithFile(sidecar.ConfigHeadVersioningRulesPath, rulesBytes); err != nil {
				return nil, err
			}
		}
		return head, nil
	}
}

// signer admits device, a member device of device's member, failing the test unless api lands it.
func testRevokedSignerAdmit(world *testWriterWorld, signer testWriterDevice, device testWriterDevice) {
	world.t.Helper()
	if _, err := world.api.AppendStatement(world.ctx, world.networkId, world.statement(signer, bridge.SignedType_SIGNED_SIDECAR_ADMIT, &protocol.SidecarAdmit{
		Header:            world.header(),
		NetworkId:         world.networkId.Bytes(),
		SidecarId:         device.sidecarId.Bytes(),
		IdentityPublicKey: device.key.Public().(ed25519.PublicKey),
		IdentityAlg:       "ed25519",
		MemberId:          device.memberId.Bytes(),
	})); err != nil {
		world.t.Fatalf("admitting %s: %v", device.sidecarId, err)
	}
}

// signer revokes device as lost, failing the test unless api lands it.
func testRevokedSignerRevoke(world *testWriterWorld, signer testWriterDevice, device testWriterDevice) {
	world.t.Helper()
	if _, err := world.api.AppendStatement(world.ctx, world.networkId, world.statement(signer, bridge.SignedType_SIGNED_SIDECAR_REVOKE, &bridge.SidecarRevoke{
		Header: world.header(), SidecarId: device.sidecarId.Bytes(), Reason: bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST,
	})); err != nil {
		world.t.Fatalf("revoking %s: %v", device.sidecarId, err)
	}
}

// Fails unless state holds settings and rules from its base's head, nil for a record the head holds none of.
func testRevokedSignerHolds(t *testing.T, label string, state *sidecar.ConfigState, settings *protocol.ServiceSettings, rules *protocol.VersioningRules) {
	t.Helper()
	heldSettings, settingsKnown := state.HeadSettings()
	if !settingsKnown || !proto.Equal(heldSettings, settings) {
		t.Fatalf("%s at %d holds the settings %v (known %t), want %v", label, state.Pin().GetVersion(), heldSettings, settingsKnown, settings)
	}
	heldRules, rulesKnown := state.VersioningRules()
	if !rulesKnown || !proto.Equal(heldRules, rules) {
		t.Fatalf("%s at %d holds the rules %v (known %t), want %v", label, state.Pin().GetVersion(), heldRules, rulesKnown, rules)
	}
}

// Fails unless fork stopped a log at n, a base whose head's record at path failed for why.
func testRevokedSignerForkedAt(t *testing.T, label string, fork *sidecar.ConfigForkError, n uint64, path string, why string) {
	t.Helper()
	if fork == nil {
		t.Fatalf("%s did not fork", label)
	}
	if fork.N != n || !strings.Contains(fork.Reason, path+": its signer") || !strings.Contains(fork.Reason, why) {
		t.Fatalf("%s forked at %d: %s; want the base at %d, its %s's signer %s", label, fork.N, fork.Reason, n, path, why)
	}
}

// One device's follower of the network over projection, recording the head_alarm events it raises and the forks it
// reports to HeadStopState, reading heads through a reader that can hold them back.
type testRevokedSignerReader struct {
	client *sidecar.ConfigClient
	heads  *testRevokedSignerHeads

	stateLock sync.Mutex
	alarms    []sidecar.SidecarEvent
	forks     []sidecar.HeadFork
}

// A follower on the world's clock, closed at the test's end.
func newTestRevokedSignerReader(world *testWriterWorld, projection sidecar.ConfigProjectionReader) *testRevokedSignerReader {
	world.t.Helper()
	self := &testRevokedSignerReader{heads: &testRevokedSignerHeads{heads: world.heads}}
	settings := sidecar.DefaultConfigClientSettings()
	settings.Log = sidecar.NewNoopLogger()
	logSettings := sidecar.DefaultConfigLogSettings()
	logSettings.Log = sidecar.NewNoopLogger()
	settings.LogSettings = logSettings
	client, err := sidecar.NewConfigClient(world.ctx, &sidecar.ConfigClientArgs{
		NetworkId:    world.networkId,
		GenesisChain: world.genesis.GenesisChain,
		Projection:   projection,
		Heads:        self.heads,
		Emit: func(event sidecar.SidecarEvent) {
			if event.Kind != sidecar.SidecarEventHeadAlarm {
				return
			}
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.alarms = append(self.alarms, event)
		},
		ReportFork: func(fork sidecar.HeadFork) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.forks = append(self.forks, fork)
		},
		Clock:    world.clock,
		Settings: settings,
	})
	if err != nil {
		world.t.Fatal(err)
	}
	world.t.Cleanup(client.Close)
	self.client = client
	return self
}

// How many fork alarms it raised, and how many auth forks it reported.
func (self *testRevokedSignerReader) raised() (int, int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	alarms := 0
	for _, event := range self.alarms {
		if event.HeadAlarm == sidecar.SidecarHeadAlarmFork {
			alarms += 1
		}
	}
	forks := 0
	for _, fork := range self.forks {
		if fork.Kind == sidecar.HeadForkAuth {
			forks += 1
		}
	}
	return alarms, forks
}

// The config repo's heads as one follower reads them: while held, every version past the one held answers
// unavailable, which withholds the base naming it, never a fork.
type testRevokedSignerHeads struct {
	heads *sidecartest.FakeConfigHeads

	stateLock sync.Mutex
	holding   bool
	heldAbove uint64
}

// Holds back every version past version.
func (self *testRevokedSignerHeads) hold(version uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.holding, self.heldAbove = true, version
}

// Holds back nothing.
func (self *testRevokedSignerHeads) release() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.holding = false
}

// The shared ref's head, or unavailable past a held version.
func (self *testRevokedSignerHeads) ReadConfigHead(ctx context.Context, version uint64, configHeadSha256 []byte) (*sidecar.ConfigHead, error) {
	held := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.holding && self.heldAbove < version
	}()
	if held {
		return nil, fmt.Errorf("%w: version %d held back", sidecar.ErrConfigHeadUnavailable, version)
	}
	return self.heads.ReadConfigHead(ctx, version, configHeadSha256)
}

// A config writer's device: its follower and its writer, whose publisher runs landed, when set, once api lands a base.
type testRevokedSignerWriter struct {
	world    *testWriterWorld
	follower *testRevokedSignerReader
	writer   *sidecar.ConfigWriter

	stateLock sync.Mutex
	landed    func()
}

// device's writer standing on follower, closed at the test's end.
func newTestRevokedSignerWriter(world *testWriterWorld, device testWriterDevice, follower *testRevokedSignerReader) *testRevokedSignerWriter {
	world.t.Helper()
	self := &testRevokedSignerWriter{world: world, follower: follower}
	self.writer = world.writer(device, follower.client, self, 0, nil)
	return self
}

// api's append; a base that lands runs landed.
func (self *testRevokedSignerWriter) PublishConfigBase(ctx context.Context, base *sidecar.ConfigBasePublish) (*bridge.AuthPin, error) {
	pin, err := self.world.publisher().PublishConfigBase(ctx, base)
	if err == nil {
		landed := func() func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.landed
		}()
		if landed != nil {
			landed()
		}
	}
	return pin, err
}

// A fold: the base's pin and what the publish answered, the follower holding back the head the fold names until the
// fold returns. A publish waits for its follower to apply the base it landed, and where that base forks the follower
// two things in ConfigClient go wrong: waitApplied looks for a fork before the follow it asks for has run, and that
// follow's fork leaves the position unchanged, so nothing wakes the wait before its ctx ends; and waitApplied reads the
// log's fork with no lock while the follow writes it, a data race. So here the follower withholds that base, and the
// base's landing cancels the wait, which the publish answers; the test's own CatchUp then applies the base.
func (self *testRevokedSignerWriter) fold() (*bridge.AuthPin, error) {
	world := self.world
	self.follower.heads.hold(world.heads.Version())
	defer self.follower.heads.release()
	ctx, cancel := context.WithCancel(world.ctx)
	defer cancel()
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.landed = cancel
	}()
	defer func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.landed = nil
	}()
	return self.writer.PublishBase(ctx, true)
}

// GET /network/config/projection once api's retention point has passed the entries below from (§7.9's retain row): the
// genesis from 0 and the entries from from on, as api serves a device after deleting the older ones.
type testRevokedSignerRetained struct {
	reader *sidecartest.FakeApiConfigReader
	from   uint64
}

// api's read, less the entries below from.
func (self *testRevokedSignerRetained) ReadConfigProjection(ctx context.Context, after uint64) (*sidecar.ConfigProjection, error) {
	projection, err := self.reader.ReadConfigProjection(ctx, after)
	if err != nil {
		return nil, err
	}
	retained := [][]byte{}
	for _, entryBytes := range projection.Entries {
		entry := &bridge.AuthEntry{}
		if err := proto.Unmarshal(entryBytes, entry); err != nil {
			return nil, err
		}
		if self.from <= entry.GetN() {
			retained = append(retained, entryBytes)
		}
	}
	projection.Entries = retained
	return projection, nil
}

// A rows-only verifier of the network, as api's sequencer, its ACL gate, evs and gkm run one: it opens no config head.
type testRevokedSignerGate struct {
	world *testWriterWorld
	log   *sidecar.ConfigLog
}

// A gate at S(0) of the world's genesis.
func newTestRevokedSignerGate(world *testWriterWorld) *testRevokedSignerGate {
	world.t.Helper()
	settings := sidecar.DefaultConfigLogSettings()
	settings.Log = sidecar.NewNoopLogger()
	log, err := sidecar.NewConfigLogRowsOnly(settings, world.genesis.SignedGenesis)
	if err != nil {
		world.t.Fatal(err)
	}
	return &testRevokedSignerGate{world: world, log: log}
}

// Applies every entry api holds past the gate's pin as one run, failing the test unless the gate takes the run whole
// and stands at api's tip.
func (self *testRevokedSignerGate) caughtUp() *sidecar.ConfigState {
	world := self.world
	world.t.Helper()
	read, err := world.api.ReadProjection(world.ctx, world.networkId, self.log.Pin().GetVersion(), true)
	if err != nil {
		world.t.Fatal(err)
	}
	rowsSource := sidecar.ConfigRowsOnlySource(func(networkId sidecar.Id, rowsSha256 []byte) ([]byte, error) {
		if len(rowsSha256) == sha256.Size {
			if rows, found := read.Rows[[sha256.Size]byte(rowsSha256)]; found {
				return rows, nil
			}
		}
		return nil, sidecar.ErrConfigRowsUnavailable
	})
	if _, err := self.log.ApplyRun(read.Entries, rowsSource); err != nil {
		world.t.Fatalf("the gate past %d: %v", self.log.Pin().GetVersion(), err)
	}
	tip, err := world.api.Tip(world.ctx, world.networkId)
	if err != nil {
		world.t.Fatal(err)
	}
	if !proto.Equal(self.log.Pin(), tip) || self.log.Fork() != nil {
		world.t.Fatalf("the gate stands at %d, forked %v, api's tip %d", self.log.Pin().GetVersion(), self.log.Fork(), tip.GetVersion())
	}
	return self.log.State()
}

// The network the tests share, up to the base that forks: the owner's first device signs settings and rules into a
// head, each left out when nil, with its base; it admits the owner's desktop; a device follows from there, as does a
// gate; the desktop revokes the first device as lost; and the desktop's writer folds, a base api takes, which the
// desktop's follower has not applied yet.
type testRevokedSignerNet struct {
	world    *testWriterWorld
	settings *protocol.ServiceSettings
	rules    *protocol.VersioningRules
	desktop  testWriterDevice
	// a device that followed the log from before the revocation, standing at the revocation until the base
	warm *testRevokedSignerReader
	gate *testRevokedSignerGate
	// the desktop's writer, which published the base
	desktopWriter *testRevokedSignerWriter
	// the base after the revocation
	base *bridge.AuthPin
}

// The network up to the desktop's fold, the first device signing settings and rules, each left out when nil.
func newTestRevokedSignerNet(t *testing.T, settings *protocol.ServiceSettings, rules *protocol.VersioningRules) *testRevokedSignerNet {
	t.Helper()
	world := newTestWriterWorld(t)
	world.started()
	ownerClient := world.client()
	world.caughtUp(ownerClient)
	ownerWriter := world.writer(world.owner, ownerClient, nil, 0, nil)
	if _, err := ownerWriter.SaveHead(world.ctx, testRevokedSignerRecords(world, world.owner, settings, rules)); err != nil {
		t.Fatalf("the first device's records: %v", err)
	}
	net := &testRevokedSignerNet{world: world, settings: settings, rules: rules}
	net.desktop = testWriterDeviceOf("owner desktop", world.owner.memberId)
	testRevokedSignerAdmit(world, world.owner, net.desktop)
	net.warm = newTestRevokedSignerReader(world, world.reader())
	testRevokedSignerHolds(t, "a device before the revocation", world.caughtUp(net.warm.client), settings, rules)
	net.gate = newTestRevokedSignerGate(world)
	net.gate.caughtUp()

	testRevokedSignerRevoke(world, net.desktop, world.owner)
	state := world.caughtUp(net.warm.client)
	if state.SidecarRow(world.owner.sidecarId).GetRevokedAt() == 0 || state.IsConfigWriter(world.owner.sidecarId) {
		t.Fatalf("the first device stands at %d", state.Pin().GetVersion())
	}
	// the revocation changes no head: the records the base before it took stand at every reader until the next base
	testRevokedSignerHolds(t, "a device after the revocation", state, settings, rules)
	desktopFollower := newTestRevokedSignerReader(world, world.reader())
	world.caughtUp(desktopFollower.client)
	net.desktopWriter = newTestRevokedSignerWriter(world, net.desktop, desktopFollower)
	base, err := net.desktopWriter.fold()
	if base == nil || base.GetVersion() != state.Pin().GetVersion()+1 || !errors.Is(err, context.Canceled) {
		t.Fatalf("the desktop's fold after %d landed at %v: %v", state.Pin().GetVersion(), base, err)
	}
	net.base = base
	return net
}

// The owner's first device signs the network's ServiceSettings and VersioningRules into a head, and the owner's desktop
// revokes it as lost. The desktop's next fold carries both records unchanged, as every head does. api takes it and a
// rows-only gate takes it, knowing neither record; every reader that judges it on the state it lands on forks there,
// on the ServiceSettings' signer, the first record the check reads: a device that followed the revocation, which
// raises head_alarm and reports the fork once; the desktop's own follower, whose writer, as every writer whose follower
// forked, then refuses to plan another base; and a new device while api serves the log from 1, at every follow, which
// installs no state.
func TestTheNextBaseAfterTheRecordsSignerIsRevokedForksEveryReaderThatJudgesIt(t *testing.T) {
	net := newTestRevokedSignerNet(t, testRevokedSignerSettings(), testRevokedSignerRules())
	world := net.world

	// api took the base, and a gate takes it, opening no head
	tip, err := world.api.Tip(world.ctx, world.networkId)
	if err != nil || !proto.Equal(tip, net.base) {
		t.Fatalf("api's tip %v, the base %v: %v", tip, net.base, err)
	}
	gateState := net.gate.caughtUp()
	if gateState.Base().GetVersion() != net.base.GetVersion() {
		t.Fatalf("the gate's base %d, want %d", gateState.Base().GetVersion(), net.base.GetVersion())
	}
	if _, known := gateState.HeadSettings(); known {
		t.Error("a rows-only gate knows the head's settings")
	}
	if _, known := gateState.VersioningRules(); known {
		t.Error("a rows-only gate knows the head's rules")
	}

	// a device that followed the revocation forks at the base, once
	if err := net.warm.client.CatchUp(world.ctx); !errors.Is(err, sidecar.ErrConfigFork) {
		t.Fatalf("a device that followed the revocation: %v, want a fork", err)
	}
	testRevokedSignerForkedAt(t, "a device that followed the revocation", net.warm.client.Fork(), net.base.GetVersion(), sidecar.ConfigHeadServiceSettingsPath, "is not standing")
	if state := net.warm.client.State(); state.Pin().GetVersion() != net.base.GetVersion()-1 {
		t.Fatalf("the forked device stands at %d", state.Pin().GetVersion())
	}
	if err := net.warm.client.CatchUp(world.ctx); !errors.Is(err, sidecar.ErrConfigFork) {
		t.Fatalf("a forked device's next follow: %v", err)
	}
	if alarms, forks := net.warm.raised(); alarms != 1 || forks != 1 {
		t.Fatalf("a device that followed the revocation raised %d fork alarms and reported %d forks, want one each", alarms, forks)
	}

	// the desktop's own follower forks alike, and its writer, as every writer whose follower forked, publishes nothing
	// more, whatever its head would hold: re-signing the records included
	follower := net.desktopWriter.follower
	if err := follower.client.CatchUp(world.ctx); !errors.Is(err, sidecar.ErrConfigFork) {
		t.Fatalf("the desktop's follower: %v, want a fork", err)
	}
	testRevokedSignerForkedAt(t, "the desktop's follower", follower.client.Fork(), net.base.GetVersion(), sidecar.ConfigHeadServiceSettingsPath, "is not standing")
	if alarms, forks := follower.raised(); alarms != 1 || forks != 1 {
		t.Fatalf("the desktop's follower raised %d fork alarms and reported %d forks, want one each", alarms, forks)
	}
	if _, err := net.desktopWriter.writer.SaveHead(world.ctx, testRevokedSignerRecords(world, net.desktop, net.settings, net.rules)); !errors.Is(err, sidecar.ErrConfigWriterNotWriter) {
		t.Fatalf("the desktop re-signing the records after the fork: %v, want no writer", err)
	}
	if tip, err := world.api.Tip(world.ctx, world.networkId); err != nil || !proto.Equal(tip, net.base) {
		t.Fatalf("api's tip moved to %v: %v", tip, err)
	}

	// a new device reading the log from 1 judges every base where it lands: it forks at the base and holds nothing
	fresh := newTestRevokedSignerReader(world, world.reader())
	if err := fresh.client.CatchUp(world.ctx); !errors.Is(err, sidecar.ErrConfigFork) {
		t.Fatalf("a new device from the genesis: %v, want a fork", err)
	}
	if err := fresh.client.CatchUp(world.ctx); !errors.Is(err, sidecar.ErrConfigFork) {
		t.Fatalf("a new device from the genesis, again: %v, want a fork", err)
	}
	if state := fresh.client.State(); state != nil {
		t.Fatalf("a new device from the genesis stands at %d", state.Pin().GetVersion())
	}
	if alarms, forks := fresh.raised(); alarms < 2 || forks < 2 {
		t.Fatalf("a new device from the genesis raised %d fork alarms and reported %d forks, want one a follow", alarms, forks)
	}
}

// Once api's retention point has passed the entries before the base, a new device starts at it: the base's anchor
// judges no record's signer, so it takes the base and holds both records the revoked device signed. The next base, a
// fold by a writer standing on that device's follower, api and a gate take, and the device judges it on the state it
// lands on and forks there; a device that starts at that base takes it in turn.
func TestAReaderThatStartsAtTheBaseTakesItAndForksAtTheNext(t *testing.T) {
	net := newTestRevokedSignerNet(t, testRevokedSignerSettings(), testRevokedSignerRules())
	world := net.world
	gateState := net.gate.caughtUp()
	point := gateState.RetentionPoint()
	if point <= 1 {
		t.Fatalf("the retention point is %d: a new device would read the log from 1", point)
	}

	cold := newTestRevokedSignerReader(world, &testRevokedSignerRetained{reader: world.reader(), from: point})
	if err := cold.client.CatchUp(world.ctx); err != nil {
		t.Fatalf("a device starting at the base: %v", err)
	}
	state := cold.client.State()
	if state == nil || !proto.Equal(state.Pin(), net.base) || state.Base().GetVersion() != net.base.GetVersion() {
		t.Fatalf("a device starting at the base stands at %v", cold.client.Pin())
	}
	testRevokedSignerHolds(t, "a device starting at the base", state, net.settings, net.rules)

	coldWriter := newTestRevokedSignerWriter(world, net.desktop, cold)
	next, err := coldWriter.fold()
	if next == nil || next.GetVersion() != net.base.GetVersion()+1 || !errors.Is(err, context.Canceled) {
		t.Fatalf("the next base %v: %v, want it landed", next, err)
	}
	if err := cold.client.CatchUp(world.ctx); !errors.Is(err, sidecar.ErrConfigFork) {
		t.Fatalf("the device that started at the base, at the next: %v, want a fork", err)
	}
	testRevokedSignerForkedAt(t, "the device that started at the base", cold.client.Fork(), next.GetVersion(), sidecar.ConfigHeadServiceSettingsPath, "is not standing")
	if alarms, forks := cold.raised(); alarms != 1 || forks != 1 {
		t.Fatalf("the device that started at the base raised %d fork alarms and reported %d forks, want one each", alarms, forks)
	}
	if gateState := net.gate.caughtUp(); gateState.Base().GetVersion() != next.GetVersion() {
		t.Fatalf("the gate's base %d, want %d", gateState.Base().GetVersion(), next.GetVersion())
	}

	colder := newTestRevokedSignerReader(world, &testRevokedSignerRetained{reader: world.reader(), from: net.gate.log.State().RetentionPoint()})
	if err := colder.client.CatchUp(world.ctx); err != nil {
		t.Fatalf("a device starting at the next base: %v", err)
	}
	if state := colder.client.State(); state == nil || !proto.Equal(state.Pin(), next) {
		t.Fatalf("a device starting at the next base stands at %v", colder.client.Pin())
	}
	testRevokedSignerHolds(t, "a device starting at the next base", colder.client.State(), net.settings, net.rules)
}

// Either record alone forks the next base once its signer is revoked: the ServiceSettings' signer must stand as an
// Owner's or Admin's device, the VersioningRules' as an Owner's, Admin's or Network admin's, each at S(n-1) of every
// base; api and a gate take the base.
func TestEachCarriedRecordAloneForksTheNextBase(t *testing.T) {
	for _, c := range []struct {
		name     string
		settings *protocol.ServiceSettings
		rules    *protocol.VersioningRules
		path     string
	}{
		{name: "ServiceSettings alone", settings: testRevokedSignerSettings(), path: sidecar.ConfigHeadServiceSettingsPath},
		{name: "VersioningRules alone", rules: testRevokedSignerRules(), path: sidecar.ConfigHeadVersioningRulesPath},
	} {
		net := newTestRevokedSignerNet(t, c.settings, c.rules)
		if err := net.warm.client.CatchUp(net.world.ctx); !errors.Is(err, sidecar.ErrConfigFork) {
			t.Fatalf("%s: a device that followed the revocation: %v, want a fork", c.name, err)
		}
		testRevokedSignerForkedAt(t, c.name+": a device that followed the revocation", net.warm.client.Fork(), net.base.GetVersion(), c.path, "is not standing")
		if gateState := net.gate.caughtUp(); gateState.Base().GetVersion() != net.base.GetVersion() {
			t.Fatalf("%s: the gate's base %d, want %d", c.name, gateState.Base().GetVersion(), net.base.GetVersion())
		}
	}
}

// The same check reads the signer's role: an Admin's device files the network's ServiceSettings, and the owner, alone
// at k = 1, then sets an AdminSet without that Admin. The device still stands, but the next base, the owner's fold,
// forks every device that followed the demotion, the record's signer no longer of a role that signs it; api and a gate
// take it.
func TestTheNextBaseAfterTheRecordsSignerLosesItsRoleForks(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	adminMemberId := testWriterId("admin member")
	if _, err := world.api.AppendStatement(world.ctx, world.networkId, world.statement(world.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, &protocol.MemberAdmit{
		Header: world.header(), MemberId: adminMemberId.Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_MEMBER,
	})); err != nil {
		t.Fatal(err)
	}
	laptop := testWriterDeviceOf("admin laptop", adminMemberId)
	testRevokedSignerAdmit(world, world.owner, laptop)
	adminSet := func(admins ...sidecar.Id) {
		t.Helper()
		set := &protocol.AdminSet{Header: world.header(), Owners: [][]byte{world.owner.memberId.Bytes()}}
		for _, admin := range admins {
			set.Admins = append(set.Admins, admin.Bytes())
		}
		if _, err := world.api.AppendStatement(world.ctx, world.networkId, world.statement(world.owner, bridge.SignedType_SIGNED_ADMIN_SET, set)); err != nil {
			t.Fatalf("an AdminSet of %d admins: %v", len(admins), err)
		}
	}
	adminSet(adminMemberId)

	laptopClient := world.client()
	if state := world.caughtUp(laptopClient); state.Member(adminMemberId).GetRole() != bridge.MemberRole_MEMBER_ROLE_ADMIN {
		t.Fatalf("the admin's role %v", state.Member(adminMemberId).GetRole())
	}
	laptopWriter := world.writer(laptop, laptopClient, nil, 0, nil)
	settings := testRevokedSignerSettings()
	if _, err := laptopWriter.SaveHead(world.ctx, testRevokedSignerRecords(world, laptop, settings, nil)); err != nil {
		t.Fatalf("the admin's settings: %v", err)
	}

	adminSet()
	warm := newTestRevokedSignerReader(world, world.reader())
	state := world.caughtUp(warm.client)
	if role := state.Member(adminMemberId).GetRole(); role == bridge.MemberRole_MEMBER_ROLE_ADMIN || role == bridge.MemberRole_MEMBER_ROLE_OWNER {
		t.Fatalf("the demoted admin's role %v", role)
	}
	if state.SidecarRow(laptop.sidecarId).GetRevokedAt() != 0 {
		t.Fatal("the demotion revoked the admin's laptop")
	}
	if held, known := state.HeadSettings(); !known || !proto.Equal(held, settings) {
		t.Fatalf("a device after the demotion holds %v (known %t)", held, known)
	}
	gate := newTestRevokedSignerGate(world)
	gate.caughtUp()

	ownerFollower := newTestRevokedSignerReader(world, world.reader())
	world.caughtUp(ownerFollower.client)
	base, err := newTestRevokedSignerWriter(world, world.owner, ownerFollower).fold()
	if base == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("the owner's fold %v: %v, want it landed", base, err)
	}
	if err := ownerFollower.client.CatchUp(world.ctx); !errors.Is(err, sidecar.ErrConfigFork) {
		t.Fatalf("the owner's follower: %v, want a fork", err)
	}
	testRevokedSignerForkedAt(t, "the owner's follower", ownerFollower.client.Fork(), base.GetVersion(), sidecar.ConfigHeadServiceSettingsPath, "holds no role that signs it")
	if err := warm.client.CatchUp(world.ctx); !errors.Is(err, sidecar.ErrConfigFork) {
		t.Fatalf("a device that followed the demotion: %v, want a fork", err)
	}
	testRevokedSignerForkedAt(t, "a device that followed the demotion", warm.client.Fork(), base.GetVersion(), sidecar.ConfigHeadServiceSettingsPath, "holds no role that signs it")
	if gateState := gate.caughtUp(); gateState.Base().GetVersion() != base.GetVersion() {
		t.Fatalf("the gate's base %d, want %d", gateState.Base().GetVersion(), base.GetVersion())
	}
}
