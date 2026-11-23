//go:build !sidecar_http && !js

// QD-1205's class for the two records that ride a config head alone and whose failure forks the base (question
// config-head-records-revoked-signer-carried-records, answered as QD-1207): every head carries the network's
// ServiceSettings and VersioningRules forward unchanged. A reader judges a record's signer, standing and of a role that
// signs it, at S(n-1) of the base whose head first holds it, and keeps a record the previous base's head held byte for
// byte without judging its signer again (§7.9's Writes, a record judged at its parent head; D-TEAM-26). So once the
// device that signed them stops standing, here the owner's first device revoked as lost, or its member loses the role,
// every base after it carries both records, the fold loop's own fold included, and every reader takes it.
//
// On T2's fake api, whose verifier is api's rows-only ConfigLog, with sidecartest's in-memory config ref and real
// ConfigClients, ConfigWriters and ConfigLogs, these pin down what each kind of reader does with those bases:
//
//	warm     a device that followed the log through the revocation takes the base and the ones after it, holding both
//	         records, with no head_alarm raised and no fork reported; its writer publishes the next base
//	genesis  a new device while api still serves the log from 1 judges each record at the base whose head first holds
//	         it, as every device did there, and takes every base after it
//	cold     a new device that starts at the base, once api's retention point has passed the entries before it, checks
//	         the base's anchor, which judges no record's signer: it takes the base holding both records, and takes the
//	         next base, which carries them
//	gate     api's sequencer and every rows-only gate (api's ACL gate, evs, gkm) open no head and take every base
//
// A record a head first holds is still judged where it lands, and forks every reader that judges it there as before:
// one the revoked device files after its revocation, one the demoted Admin's device files after the demotion, and the
// revoked device's record put back after a head removed it. Every wait is on the client's log or a call's return; api's
// clock never moves, so no fold loop publishes on its own. A writer whose base forks its own follower holds that
// follower's read of the head the base names back until the publish returns (testRevokedSignerWriter.withheld), since
// such a publish meets two faults in ConfigClient's wait for the base (config-client-waitapplied-fork's).

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
	"time"

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

// The signer of the record at path in the newest head the config repo holds, failing the test where it holds none.
func testRevokedSignerRecordSigner(world *testWriterWorld, path string) sidecar.Id {
	world.t.Helper()
	head, _, _, err := world.heads.For(world.owner.sidecarId, world.owner.key).CurrentConfigHead(world.ctx)
	if err != nil || head == nil {
		world.t.Fatalf("the newest head: %v", err)
	}
	record := head.File(path)
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(record, signed); err != nil || len(record) == 0 {
		world.t.Fatalf("the newest head's %s: %v", path, err)
	}
	signerId, err := sidecar.IdFromBytes(signed.GetSignerId())
	if err != nil {
		world.t.Fatal(err)
	}
	return signerId
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

// Fails unless a follow takes every base api holds: the follower stands at api's tip holding settings and rules, nil for
// a record the head holds none of, having raised no fork alarm and reported no fork. Its state.
func (self *testRevokedSignerReader) takes(world *testWriterWorld, label string, settings *protocol.ServiceSettings, rules *protocol.VersioningRules) *sidecar.ConfigState {
	world.t.Helper()
	if err := self.client.CatchUp(world.ctx); err != nil {
		world.t.Fatalf("%s: %v", label, err)
	}
	tip, err := world.api.Tip(world.ctx, world.networkId)
	if err != nil {
		world.t.Fatal(err)
	}
	state := self.client.State()
	if state == nil || !proto.Equal(state.Pin(), tip) || self.client.Fork() != nil {
		world.t.Fatalf("%s stands at %v, forked %v, api's tip at %d", label, self.client.Pin(), self.client.Fork(), tip.GetVersion())
	}
	testRevokedSignerHolds(world.t, label, state, settings, rules)
	if alarms, forks := self.raised(); alarms != 0 || forks != 0 {
		world.t.Fatalf("%s raised %d fork alarms and reported %d forks", label, alarms, forks)
	}
	return state
}

// Fails unless a follow forks at the base at n, its head's record at path refused for why, raising one fork alarm and
// reporting one fork.
func (self *testRevokedSignerReader) forksAt(world *testWriterWorld, label string, n uint64, path string, why string) {
	world.t.Helper()
	if err := self.client.CatchUp(world.ctx); !errors.Is(err, sidecar.ErrConfigFork) {
		world.t.Fatalf("%s: %v, want a fork", label, err)
	}
	testRevokedSignerForkedAt(world.t, label, self.client.Fork(), n, path, why)
	if alarms, forks := self.raised(); alarms != 1 || forks != 1 {
		world.t.Fatalf("%s raised %d fork alarms and reported %d forks, want one each", label, alarms, forks)
	}
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

// A fold with the follower live, as the fold loop publishes one: the publish waits for the follower to apply the base it
// landed, so a nil error is this device taking it. Bounded, so a base the follower does not take fails the test.
func (self *testRevokedSignerWriter) fold() (*bridge.AuthPin, error) {
	ctx, cancel := context.WithTimeout(self.world.ctx, 30*time.Second)
	defer cancel()
	return self.writer.PublishBase(ctx, true)
}

// A head edit saved with the follower live, as ur admin settings saves one, its base published as fold's is.
func (self *testRevokedSignerWriter) save(edit func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error)) (*bridge.AuthPin, error) {
	ctx, cancel := context.WithTimeout(self.world.ctx, 30*time.Second)
	defer cancel()
	return self.writer.SaveHead(ctx, edit)
}

// publish's call with the follower's reads of every head past the newest one held back until the call returns, for a
// base whose head forks the follower. A publish waits for its follower to apply the base it landed, and where that base
// forks the follower two things in ConfigClient go wrong: waitApplied looks for a fork before the follow it asks for
// has run, and that follow's fork leaves the position unchanged, so nothing wakes the wait before its ctx ends; and
// waitApplied reads the log's fork with no lock while the follow writes it, a data race. So here the follower withholds
// that base, and the base's landing cancels the wait, which the call answers; the test's own CatchUp then applies it.
func (self *testRevokedSignerWriter) withheld(publish func(ctx context.Context) (*bridge.AuthPin, error)) (*bridge.AuthPin, error) {
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
	return publish(ctx)
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

// Fails unless the gate takes every base api holds, standing on the base at n.
func (self *testRevokedSignerGate) standsOn(label string, n uint64) {
	self.world.t.Helper()
	if gateState := self.caughtUp(); gateState.Base().GetVersion() != n {
		self.world.t.Fatalf("%s: the gate's base %d, want %d", label, gateState.Base().GetVersion(), n)
	}
}

// The network the tests share, up to the base after the revocation: the owner's first device signs settings and rules
// into a head, each left out when nil, with its base; it admits the owner's desktop; a device follows from there, as
// does a gate; the desktop revokes the first device as lost; and the desktop's writer folds, a base api takes and the
// desktop's follower takes.
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
	if err != nil || base == nil || base.GetVersion() != state.Pin().GetVersion()+1 {
		t.Fatalf("the desktop's fold after %d landed at %v: %v", state.Pin().GetVersion(), base, err)
	}
	net.base = base
	return net
}

// The owner's first device signs the network's ServiceSettings and VersioningRules into a head, and the owner's desktop
// revokes it as lost. The desktop's next fold carries both records unchanged, as every head does, still signed by the
// revoked device, and every reader takes it: api and a rows-only gate, knowing neither record; a device that followed
// the revocation; and the desktop's own follower, whose writer then publishes the next base, which they all take as
// well. A new device while api serves the log from 1 judged each record at the base whose head first held it and takes
// every base. And the desktop then files both records again under its own signature, new records judged where they
// land, which every reader takes in their place.
func TestEveryReaderTakesTheBasesAfterTheRecordsSignerIsRevoked(t *testing.T) {
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
	for _, path := range []string{sidecar.ConfigHeadServiceSettingsPath, sidecar.ConfigHeadVersioningRulesPath} {
		if signer := testRevokedSignerRecordSigner(world, path); signer != world.owner.sidecarId {
			t.Fatalf("the base's head carries the %s %s signed", path, signer)
		}
	}

	// a device that followed the revocation takes the base, and the desktop's follower took it in the fold
	net.warm.takes(world, "a device that followed the revocation", net.settings, net.rules)
	follower := net.desktopWriter.follower
	follower.takes(world, "the desktop's follower", net.settings, net.rules)

	// the desktop's writer folds again, the fold loop's next base, and every reader takes it
	next, err := net.desktopWriter.fold()
	if err != nil || next.GetVersion() != net.base.GetVersion()+1 {
		t.Fatalf("the desktop's next fold landed at %v: %v", next, err)
	}
	net.warm.takes(world, "a device that followed the revocation, at the next base", net.settings, net.rules)
	follower.takes(world, "the desktop's follower, at the next base", net.settings, net.rules)
	net.gate.standsOn("the next base", next.GetVersion())

	// a new device reading the log from 1 judges each record where a head first holds it, and takes every base
	fresh := newTestRevokedSignerReader(world, world.reader())
	fresh.takes(world, "a new device from the genesis", net.settings, net.rules)

	// the desktop files both records again under its own signature: new records, judged where they land, and taken
	resigned, err := net.desktopWriter.save(testRevokedSignerRecords(world, net.desktop, net.settings, net.rules))
	if err != nil || resigned.GetVersion() != next.GetVersion()+1 {
		t.Fatalf("the desktop's re-signed records landed at %v: %v", resigned, err)
	}
	for _, path := range []string{sidecar.ConfigHeadServiceSettingsPath, sidecar.ConfigHeadVersioningRulesPath} {
		if signer := testRevokedSignerRecordSigner(world, path); signer != net.desktop.sidecarId {
			t.Fatalf("the re-signed head holds the %s %s signed", path, signer)
		}
	}
	for _, c := range []struct {
		label  string
		reader *testRevokedSignerReader
	}{
		{label: "a device that followed the revocation, at the re-signed records", reader: net.warm},
		{label: "the desktop's follower, at the re-signed records", reader: follower},
		{label: "a new device from the genesis, at the re-signed records", reader: fresh},
	} {
		c.reader.takes(world, c.label, net.settings, net.rules)
	}
	net.gate.standsOn("the re-signed records", resigned.GetVersion())
}

// Once api's retention point has passed the entries before the base, a new device starts at it: the base's anchor
// judges no record's signer, so it takes the base holding both records the revoked device signed. The next base, a fold
// by a writer standing on that device's follower, it takes as well, as do api and a gate; a device that starts at that
// base takes it in turn, and both take the base after it.
func TestAReaderThatStartsAtTheBaseTakesItAndTheNext(t *testing.T) {
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
	if err != nil || next == nil || next.GetVersion() != net.base.GetVersion()+1 {
		t.Fatalf("the next base %v: %v, want it landed and taken", next, err)
	}
	cold.takes(world, "the device that started at the base, at the next", net.settings, net.rules)
	net.gate.standsOn("the next base", next.GetVersion())

	colder := newTestRevokedSignerReader(world, &testRevokedSignerRetained{reader: world.reader(), from: net.gate.log.State().RetentionPoint()})
	if err := colder.client.CatchUp(world.ctx); err != nil {
		t.Fatalf("a device starting at the next base: %v", err)
	}
	if state := colder.client.State(); state == nil || !proto.Equal(state.Pin(), next) {
		t.Fatalf("a device starting at the next base stands at %v", colder.client.Pin())
	}
	testRevokedSignerHolds(t, "a device starting at the next base", colder.client.State(), net.settings, net.rules)

	third, err := coldWriter.fold()
	if err != nil || third.GetVersion() != next.GetVersion()+1 {
		t.Fatalf("the base after the next %v: %v", third, err)
	}
	cold.takes(world, "the device that started at the base, two bases on", net.settings, net.rules)
	colder.takes(world, "the device that started at the next base, at the one after", net.settings, net.rules)
	net.warm.takes(world, "a device that followed the revocation, two bases on", net.settings, net.rules)
	net.gate.standsOn("the base after the next", third.GetVersion())
}

// Either record alone is kept at the next base once its signer is revoked: the ServiceSettings' signer judged as an
// Owner's or Admin's device, the VersioningRules' as an Owner's, Admin's or Network admin's, each at the base whose head
// first held it and never again while heads carry it; api and a gate take the base.
func TestEachCarriedRecordAloneIsKeptAtTheNextBase(t *testing.T) {
	for _, c := range []struct {
		name     string
		settings *protocol.ServiceSettings
		rules    *protocol.VersioningRules
	}{
		{name: "ServiceSettings alone", settings: testRevokedSignerSettings()},
		{name: "VersioningRules alone", rules: testRevokedSignerRules()},
	} {
		net := newTestRevokedSignerNet(t, c.settings, c.rules)
		net.warm.takes(net.world, c.name+": a device that followed the revocation", c.settings, c.rules)
		net.desktopWriter.follower.takes(net.world, c.name+": the desktop's follower", c.settings, c.rules)
		net.gate.standsOn(c.name, net.base.GetVersion())
	}
}

// A record the revoked device files after its revocation is new where a head first holds it, so every reader judges its
// signer there and forks, as before: a new ServiceSettings, and alike new VersioningRules, signed by the first device
// once the desktop revoked it, which the desktop's writer saves. api and a gate take the base; the device that followed
// the revocation, the desktop's own follower and a new device from the genesis each fork at it.
func TestARecordTheRevokedDeviceFilesAfterItsRevocationForks(t *testing.T) {
	for _, c := range []struct {
		name     string
		settings *protocol.ServiceSettings
		rules    *protocol.VersioningRules
		path     string
	}{
		{name: "new ServiceSettings", settings: &protocol.ServiceSettings{MailStrict: true}, path: sidecar.ConfigHeadServiceSettingsPath},
		{name: "new VersioningRules", rules: &protocol.VersioningRules{}, path: sidecar.ConfigHeadVersioningRulesPath},
	} {
		net := newTestRevokedSignerNet(t, testRevokedSignerSettings(), testRevokedSignerRules())
		world := net.world
		net.warm.takes(world, c.name+": a device that followed the revocation", net.settings, net.rules)
		writer := net.desktopWriter
		filed, err := writer.withheld(func(ctx context.Context) (*bridge.AuthPin, error) {
			return writer.writer.SaveHead(ctx, testRevokedSignerRecords(world, world.owner, c.settings, c.rules))
		})
		if filed == nil || filed.GetVersion() != net.base.GetVersion()+1 || !errors.Is(err, context.Canceled) {
			t.Fatalf("%s: the revoked device's record landed at %v: %v", c.name, filed, err)
		}
		net.gate.standsOn(c.name, filed.GetVersion())
		net.warm.forksAt(world, c.name+": a device that followed the revocation", filed.GetVersion(), c.path, "is not standing")
		writer.follower.forksAt(world, c.name+": the desktop's follower", filed.GetVersion(), c.path, "is not standing")
		// a new device's start keeps no log it forked in, so its fork is the follow's answer
		fresh := newTestRevokedSignerReader(world, world.reader())
		var freshFork *sidecar.ConfigForkError
		if err := fresh.client.CatchUp(world.ctx); !errors.Is(err, sidecar.ErrConfigFork) || !errors.As(err, &freshFork) {
			t.Fatalf("%s: a new device from the genesis: %v, want a fork", c.name, err)
		}
		testRevokedSignerForkedAt(t, c.name+": a new device from the genesis", freshFork, filed.GetVersion(), c.path, "is not standing")
	}
}

// A record a head removes and a later head puts back, byte for byte, is new where it lands again: the first device's
// ServiceSettings, which the desktop's head removes, a base every reader takes holding none, and which the desktop's
// next head puts back once it has revoked the first device. Every reader judges the record there and forks, so no
// record returns under a signer who no longer stands; api and a gate take the base.
func TestARecordPutBackAfterAHeadRemovedItForksOnceItsSignerIsRevoked(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	ownerClient := world.client()
	world.caughtUp(ownerClient)
	ownerWriter := world.writer(world.owner, ownerClient, nil, 0, nil)
	settings := testRevokedSignerSettings()
	putBack := testRevokedSignerRecords(world, world.owner, settings, nil)
	if _, err := ownerWriter.SaveHead(world.ctx, putBack); err != nil {
		t.Fatalf("the first device's settings: %v", err)
	}
	desktop := testWriterDeviceOf("owner desktop", world.owner.memberId)
	testRevokedSignerAdmit(world, world.owner, desktop)
	warm := newTestRevokedSignerReader(world, world.reader())
	testRevokedSignerHolds(t, "a device before the removal", world.caughtUp(warm.client), settings, nil)
	gate := newTestRevokedSignerGate(world)
	gate.caughtUp()

	desktopFollower := newTestRevokedSignerReader(world, world.reader())
	world.caughtUp(desktopFollower.client)
	desktopWriter := newTestRevokedSignerWriter(world, desktop, desktopFollower)
	removed, err := desktopWriter.save(func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error) {
		return head.WithFile(sidecar.ConfigHeadServiceSettingsPath, nil)
	})
	if err != nil {
		t.Fatalf("the desktop's head removing the settings: %v", err)
	}
	warm.takes(world, "a device after the removal", nil, nil)
	gate.standsOn("the removal", removed.GetVersion())

	testRevokedSignerRevoke(world, desktop, world.owner)
	world.caughtUp(warm.client)
	world.caughtUp(desktopFollower.client)
	restored, err := desktopWriter.withheld(func(ctx context.Context) (*bridge.AuthPin, error) {
		return desktopWriter.writer.SaveHead(ctx, putBack)
	})
	if restored == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("the desktop's head putting the settings back landed at %v: %v", restored, err)
	}
	if signer := testRevokedSignerRecordSigner(world, sidecar.ConfigHeadServiceSettingsPath); signer != world.owner.sidecarId {
		t.Fatalf("the head put back the settings %s signed", signer)
	}
	gate.standsOn("the settings put back", restored.GetVersion())
	warm.forksAt(world, "a device that followed the revocation", restored.GetVersion(), sidecar.ConfigHeadServiceSettingsPath, "is not standing")
	desktopFollower.forksAt(world, "the desktop's follower", restored.GetVersion(), sidecar.ConfigHeadServiceSettingsPath, "is not standing")
}

// The same rule reads the signer's role: an Admin's device files the network's ServiceSettings, and the owner, alone at
// k = 1, then sets an AdminSet without that Admin. The device still stands, its member no longer of a role that signs
// the record, but the next base, the owner's fold, carries the record and every reader takes it, as do api and a gate.
// A new record the demoted Admin's device files after the demotion is judged where it lands and forks every reader, as
// before.
func TestTheBaseAfterTheRecordsSignerLosesItsRoleIsTaken(t *testing.T) {
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
	ownerWriter := newTestRevokedSignerWriter(world, world.owner, ownerFollower)
	base, err := ownerWriter.fold()
	if err != nil || base == nil {
		t.Fatalf("the owner's fold %v: %v, want it landed and taken", base, err)
	}
	ownerFollower.takes(world, "the owner's follower", settings, nil)
	warm.takes(world, "a device that followed the demotion", settings, nil)
	gate.standsOn("the owner's fold", base.GetVersion())
	if signer := testRevokedSignerRecordSigner(world, sidecar.ConfigHeadServiceSettingsPath); signer != laptop.sidecarId {
		t.Fatalf("the owner's fold carries the settings %s signed", signer)
	}

	filed, err := ownerWriter.withheld(func(ctx context.Context) (*bridge.AuthPin, error) {
		return ownerWriter.writer.SaveHead(ctx, testRevokedSignerRecords(world, laptop, &protocol.ServiceSettings{MailStrict: true}, nil))
	})
	if filed == nil || filed.GetVersion() != base.GetVersion()+1 || !errors.Is(err, context.Canceled) {
		t.Fatalf("the demoted admin's new settings landed at %v: %v", filed, err)
	}
	gate.standsOn("the demoted admin's new settings", filed.GetVersion())
	ownerFollower.forksAt(world, "the owner's follower", filed.GetVersion(), sidecar.ConfigHeadServiceSettingsPath, "holds no role that signs it")
	warm.forksAt(world, "a device that followed the demotion", filed.GetVersion(), sidecar.ConfigHeadServiceSettingsPath, "holds no role that signs it")
}
