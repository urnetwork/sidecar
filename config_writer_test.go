//go:build !sidecar_http && !js

// TEAM-M2-09's writer on T2's fake api (TEAM-M2-12): BootstrapNetwork and the race of two first devices, a base that
// loses its position to a statement and lands re-signed carrying the tail's verdicts, the fold loop's cadence on a fake
// clock with a second writer's base cancelling the delay, a fold at start after being offline, and a pending head
// published after 10 min. The config repo is sidecartest's in-memory ref and the acl compile a test's (C-05), so each
// base's head and compile check run for real at every reader.

package sidecar_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// One device of a writer test: its sidecar, member and identity key.
type testWriterDevice struct {
	sidecarId sidecar.Id
	memberId  sidecar.Id
	key       ed25519.PrivateKey
}

// A synthetic id from a label.
func testWriterId(label string) sidecar.Id {
	digest := sha256.Sum256([]byte("config writer test " + label))
	return sidecar.Id(digest[:16])
}

// A device of member from a label.
func testWriterDeviceOf(label string, memberId sidecar.Id) testWriterDevice {
	seed := sha256.Sum256([]byte("config writer test key " + label))
	return testWriterDevice{sidecarId: testWriterId(label), memberId: memberId, key: ed25519.NewKeyFromSeed(seed[:])}
}

// Its identity key's signer.
func (self testWriterDevice) sign() sidecar.ConfigSignFunction {
	return func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
		return &bridge.Signed{
			Body:      body,
			SignerId:  self.sidecarId.Bytes(),
			Signature: ed25519.Sign(self.key, bridge.SignedBytes(purpose, signedType, body)),
			Type:      uint32(signedType),
		}, nil
	}
}

// A network on a fake api: its owner, its config repo's ref and the clock.
type testWriterWorld struct {
	t         *testing.T
	ctx       context.Context
	clock     *sidecartest.FakeClock
	api       *sidecartest.FakeApi
	networkId sidecar.Id
	owner     testWriterDevice
	repoId    sidecar.Id
	heads     *sidecartest.FakeConfigHeads
	nonce     uint64
	genesis   *sidecar.ConfigBootstrapResult
}

func newTestWriterWorld(t *testing.T) *testWriterWorld {
	t.Cleanup(sidecar.RegisterConfigAclCompiler(func(head *sidecar.ConfigHead, rows *sidecar.ConfigCompileRows) (*protocol.AclRows, error) {
		return rows.AclStatements, nil
	}))
	ctx := context.Background()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	faults := sidecartest.NewFaultQueue()
	blobs := sidecartest.NewFakeBlobs(clock, faults, nil, sidecartest.DefaultFakeBlobsSettings())
	cluster, err := blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	repoId := testWriterId("config repo")
	return &testWriterWorld{
		t:         t,
		ctx:       ctx,
		clock:     clock,
		api:       sidecartest.NewFakeApi(ctx, clock, faults, nil, cluster, nil),
		networkId: testWriterId("network"),
		owner:     testWriterDeviceOf("owner device", testWriterId("owner member")),
		repoId:    repoId,
		heads:     sidecartest.NewFakeConfigHeads(repoId),
	}
}

// The api's log as a reader reads it, and as a writer publishes to it.
func (self *testWriterWorld) reader() *sidecartest.FakeApiConfigReader {
	return &sidecartest.FakeApiConfigReader{Api: self.api, NetworkId: self.networkId}
}

func (self *testWriterWorld) publisher() *sidecartest.FakeApiConfigPublisher {
	return &sidecartest.FakeApiConfigPublisher{Api: self.api, NetworkId: self.networkId}
}

// device's BootstrapNetwork.
func (self *testWriterWorld) bootstrap(device testWriterDevice) (*sidecar.ConfigBootstrapResult, error) {
	return sidecar.BootstrapNetwork(self.ctx, &sidecar.ConfigBootstrapArgs{
		NetworkId:         self.networkId,
		OwnerMemberId:     device.memberId,
		SidecarId:         device.sidecarId,
		IdentityPublicKey: device.key.Public().(ed25519.PublicKey),
		Sign:              device.sign(),
		ConfigRepoId:      self.repoId,
		Heads:             self.heads.For(device.sidecarId, device.key),
		Publisher:         self.publisher(),
		Projection:        self.reader(),
		Clock:             self.clock,
	})
}

// The owner's network bootstrapped.
func (self *testWriterWorld) started() {
	self.t.Helper()
	result, err := self.bootstrap(self.owner)
	if err != nil || !result.Won {
		self.t.Fatalf("bootstrap: %v", err)
	}
	self.genesis = result
}

// A full reader of the network, on the world's clock.
func (self *testWriterWorld) client() *sidecar.ConfigClient {
	self.t.Helper()
	settings := sidecar.DefaultConfigClientSettings()
	settings.Log = sidecar.NewNoopLogger()
	logSettings := sidecar.DefaultConfigLogSettings()
	logSettings.Log = sidecar.NewNoopLogger()
	settings.LogSettings = logSettings
	client, err := sidecar.NewConfigClient(self.ctx, &sidecar.ConfigClientArgs{
		NetworkId:    self.networkId,
		GenesisChain: self.genesis.GenesisChain,
		Projection:   self.reader(),
		Heads:        self.heads,
		Clock:        self.clock,
		Settings:     settings,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(client.Close)
	return client
}

// A writer of device's over client, its fold loop on clock (the world's when nil), its delays random's fraction.
func (self *testWriterWorld) writer(device testWriterDevice, client *sidecar.ConfigClient, publisher sidecar.ConfigBasePublisher, random float64, clock *sidecartest.FakeClock) *sidecar.ConfigWriter {
	self.t.Helper()
	settings := sidecar.DefaultConfigWriterSettings()
	settings.Clock = self.clock
	if clock != nil {
		settings.Clock = clock
	}
	settings.Random = func() float64 { return random }
	settings.Log = sidecar.NewNoopLogger()
	if publisher == nil {
		publisher = self.publisher()
	}
	writer, err := sidecar.NewConfigWriter(self.ctx, &sidecar.ConfigWriterArgs{
		SidecarId: device.sidecarId,
		Sign:      device.sign(),
		Client:    client,
		Heads:     self.heads.For(device.sidecarId, device.key),
		Publisher: publisher,
		Settings:  settings,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(writer.Close)
	return writer
}

// A statement signed by device at the api's tip.
func (self *testWriterWorld) statement(device testWriterDevice, signedType bridge.SignedType, body proto.Message) []byte {
	self.t.Helper()
	bodyBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(body)
	if err != nil {
		self.t.Fatal(err)
	}
	purpose, _ := sidecar.ConfigStatementPurpose(signedType)
	signed, _ := device.sign()(purpose, signedType, bodyBytes)
	signedBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	if err != nil {
		self.t.Fatal(err)
	}
	return signedBytes
}

// A StatementHeader at the api's tip, a fresh nonce, expiring in a day.
func (self *testWriterWorld) header() *bridge.StatementHeader {
	self.t.Helper()
	tip, err := self.api.Tip(self.ctx, self.networkId)
	if err != nil {
		self.t.Fatal(err)
	}
	self.nonce += 1
	nonce := make([]byte, 16)
	binary.BigEndian.PutUint64(nonce[8:], self.nonce)
	return &bridge.StatementHeader{NetworkId: self.networkId.Bytes(), At: tip, Nonce: nonce, NotAfterMs: self.clock.Now().Add(24 * time.Hour).UnixMilli()}
}

// The owner admits a member; the entry's pin, or the refusal.
func (self *testWriterWorld) admitMember(label string) (*bridge.AuthPin, error) {
	return self.api.AppendStatement(self.ctx, self.networkId, self.statement(self.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, &protocol.MemberAdmit{
		Header: self.header(), MemberId: testWriterId(label).Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_MEMBER,
	}))
}

// Waits for client to stand at the api's tip.
func (self *testWriterWorld) caughtUp(client *sidecar.ConfigClient) *sidecar.ConfigState {
	self.t.Helper()
	tip, err := self.api.Tip(self.ctx, self.networkId)
	if err != nil {
		self.t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(self.ctx, 30*time.Second)
	defer cancel()
	state, err := client.WaitFor(ctx, tip.GetVersion())
	if err != nil {
		self.t.Fatalf("waiting for %d: %v", tip.GetVersion(), err)
	}
	return state
}

// §22.7's race: two first devices of the owner race base 1 at api, and one genesis stands; the loser learns it.
func TestTwoFirstDevicesRaceBaseOneAndOneGenesisStands(t *testing.T) {
	world := newTestWriterWorld(t)
	rival := testWriterDeviceOf("rival device", world.owner.memberId)
	results := make([]*sidecar.ConfigBootstrapResult, 2)
	errs := make([]error, 2)
	var group sync.WaitGroup
	for i, device := range []testWriterDevice{world.owner, rival} {
		group.Add(1)
		go func() {
			defer group.Done()
			results[i], errs[i] = world.bootstrap(device)
		}()
	}
	group.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("device %d: %v", i, err)
		}
	}
	if results[0].Won == results[1].Won {
		t.Fatalf("won: %v and %v", results[0].Won, results[1].Won)
	}
	if !bytes.Equal(results[0].SignedGenesis, results[1].SignedGenesis) {
		t.Error("the two devices hold other genesis")
	}
	read, err := world.api.ReadProjection(world.ctx, world.networkId, 0, false)
	if err != nil || !bytes.Equal(read.SignedGenesis, results[0].SignedGenesis) || len(read.Entries) != 1 {
		t.Fatalf("api holds %d entries: %v", len(read.Entries), err)
	}
	if world.heads.Version() != 1 {
		t.Errorf("the config repo holds %d heads", world.heads.Version())
	}
	// a reader of the winner's genesis follows base 1 and checks its head
	world.genesis = results[0]
	if results[1].Won {
		world.genesis = results[1]
	}
	state := world.caughtUp(world.client())
	if state.Base() == nil || state.Base().GetVersion() != 1 {
		t.Fatalf("the reader stands at %v", state.Pin())
	}
}

// FS-14's writer case: a base planned at tip n loses its position (409) to three entries, a statement, one a malicious
// sequencer landed that every reader refuses, and an AuthorityProposal completing at k = 1; it re-signs at the new tip
// keeping its fold and compile, and lands at n+4 carrying the tail's verdicts 1, 0 and 2; a reader that follows checks
// its head and compile, and the head's fold holds base 1's record.
func TestABaseLosesToAStatementAndLandsReSigned(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	for _, label := range []string{"a", "b"} {
		if _, err := world.admitMember(label); err != nil {
			t.Fatal(err)
		}
	}
	client := world.client()
	world.caughtUp(client)
	planned, err := world.api.Tip(world.ctx, world.networkId)
	if err != nil {
		t.Fatal(err)
	}
	lost := false
	publisher := world.publisher()
	publisher.Before = func(ctx context.Context) {
		if lost {
			return
		}
		lost = true
		// another appender's statement lands first, then what a malicious sequencer lands, then a completion
		if _, err := world.admitMember("late"); err != nil {
			t.Error(err)
		}
		stranger := testWriterDeviceOf("stranger", testWriterId("stranger member"))
		refused := world.statement(stranger, bridge.SignedType_SIGNED_MEMBER_ADMIT, &protocol.MemberAdmit{
			Header: world.header(), MemberId: testWriterId("by a stranger").Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_MEMBER,
		})
		if _, err := world.api.SequenceAnyway(ctx, world.networkId, bridge.AuthEntryKindStatement, refused); err != nil {
			t.Error(err)
		}
		proposed, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.MemberAdmit{
			Header: world.header(), MemberId: testWriterId("by proposal").Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_MEMBER,
		})
		if err != nil {
			t.Error(err)
		}
		proposal := world.statement(world.owner, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, &protocol.AuthorityProposal{
			Header: world.header(), StatementType: uint32(bridge.SignedType_SIGNED_MEMBER_ADMIT), Statement: proposed,
		})
		if _, err := world.api.AppendStatement(ctx, world.networkId, proposal); err != nil {
			t.Error(err)
		}
	}
	writer := world.writer(world.owner, client, publisher, 0, sidecartest.NewFakeClock(world.clock.Now()))
	pin, err := writer.PublishBase(world.ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if pin.GetVersion() != planned.GetVersion()+4 {
		t.Fatalf("the base landed at %d, planned at %d", pin.GetVersion(), planned.GetVersion()+1)
	}
	state := world.caughtUp(client)
	header := state.Base()
	if header.GetFoldedThrough() != planned.GetVersion() || !bytes.Equal(header.GetTailVerdicts(), []byte{0x21}) {
		t.Errorf("the base folds through %d with verdicts %x", header.GetFoldedThrough(), header.GetTailVerdicts())
	}
	if state.Member(testWriterId("late")) == nil || state.Member(testWriterId("by proposal")) == nil || state.Member(testWriterId("by a stranger")) != nil {
		t.Error("the tail did not re-apply by its verdicts")
	}
	head, err := world.heads.ReadConfigHead(world.ctx, header.GetConfigVersion(), header.GetConfigHeadSha256())
	if err != nil {
		t.Fatal(err)
	}
	records, err := head.RecordsIn(0, header.GetFoldedThrough())
	if err != nil || len(records) == 0 || records[0].GetKind() != bridge.AuthEntryKindBase || records[0].GetN() != 1 {
		t.Errorf("the fold's records: %v", err)
	}
	// a second reader started now agrees
	second := world.client()
	if !proto.Equal(world.caughtUp(second).Pin(), state.Pin()) {
		t.Error("a second reader stands elsewhere")
	}
}

// The fold loop on fake clocks, each writer's its own so the test releases every wait: an unfolded statement past 24 h
// makes a fold due, which waits its random delay; a second writer's base landing first cancels the first writer's
// delay, which then finds nothing due and publishes nothing.
func TestTheFoldLoopFoldsByAgeAndAnotherBaseCancelsItsDelay(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	if _, err := world.admitMember("a"); err != nil {
		t.Fatal(err)
	}
	late := world.clock.Now().Add(25 * time.Hour)
	ctx, cancel := context.WithTimeout(world.ctx, 30*time.Second)
	defer cancel()

	// the first writer's delay is 9 min, the second's 1 min
	first := world.client()
	world.caughtUp(first)
	firstClock := sidecartest.NewFakeClock(late)
	world.writer(world.owner, first, nil, 0.9, firstClock)
	if err := firstClock.AwaitTimers(ctx, 1); err != nil {
		t.Fatal(err)
	}
	second := world.client()
	world.caughtUp(second)
	secondClock := sidecartest.NewFakeClock(late)
	world.writer(world.owner, second, nil, 0.1, secondClock)
	if err := secondClock.AwaitTimers(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if pending := firstClock.PendingTimers(); len(pending) != 1 || pending[0] != late.Add(9*time.Minute) {
		t.Fatalf("the first writer waits until %v", pending)
	}

	secondClock.Advance(time.Minute)
	if _, err := second.WaitFor(ctx, 3); err != nil {
		t.Fatal(err)
	}
	// the first writer's reader hears of the base, which cancels its delay
	first.ReceiveNotice(sidecar.PushNotice{Topic: sidecar.PushTopicTeam, Version: 3})
	if _, err := first.WaitFor(ctx, 3); err != nil {
		t.Fatal(err)
	}
	// its loop looks again at its check interval, the cancelled delay's timer left to fire unread
	for {
		pending, added := firstClock.WatchTimers()
		if slices.Contains(pending, late.Add(time.Minute)) {
			break
		}
		select {
		case <-added:
		case <-ctx.Done():
			t.Fatalf("the first writer still waits until %v", pending)
		}
	}
	for range 10 {
		firstClock.Advance(time.Minute)
		if err := firstClock.AwaitTimers(ctx, 1); err != nil {
			t.Fatal(err)
		}
	}
	tip, err := world.api.Tip(world.ctx, world.networkId)
	if err != nil || tip.GetVersion() != 3 {
		t.Fatalf("the log at %d after the first writer's delay: %v", tip.GetVersion(), err)
	}
	state := world.caughtUp(first)
	if base := state.Base(); base.GetVersion() != 3 || base.GetFoldedThrough() != 2 {
		t.Errorf("the base: %v", base)
	}
}

// A writer that starts after being offline past 24 h with an unfolded tail folds at start, after its delay.
func TestAnOfflineWriterFoldsAtStart(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	if _, err := world.admitMember("a"); err != nil {
		t.Fatal(err)
	}
	client := world.client()
	world.caughtUp(client)
	clock := sidecartest.NewFakeClock(world.clock.Now().Add(25 * time.Hour))
	world.writer(world.owner, client, nil, 0.5, clock)
	ctx, cancel := context.WithTimeout(world.ctx, 30*time.Second)
	defer cancel()
	if err := clock.AwaitTimers(ctx, 1); err != nil {
		t.Fatal(err)
	}
	clock.Advance(5 * time.Minute)
	if _, err := client.WaitFor(ctx, 3); err != nil {
		t.Fatal(err)
	}
	if base := client.State().Base(); base.GetVersion() != 3 || base.GetFoldedThrough() != 2 {
		t.Errorf("the base at start: %v", base)
	}
}

// A head saved with no base is pending; past 10 min another config writer publishes its base.
func TestAPendingHeadGetsItsBaseAfterTenMinutes(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	client := world.client()
	world.caughtUp(client)
	// a writer saves a head with a policy and never publishes
	store := world.heads.For(world.owner.sidecarId, world.owner.key)
	head, version, _, err := store.CurrentConfigHead(world.ctx)
	if err != nil {
		t.Fatal(err)
	}
	next, err := head.WithFile(sidecar.ConfigHeadPolicyPath, []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	push, err := store.PrepareConfigHead(world.ctx, next, version)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitConfigHead(world.ctx, push); err != nil {
		t.Fatal(err)
	}
	clock := sidecartest.NewFakeClock(world.clock.Now())
	writer := world.writer(world.owner, client, nil, 0, clock)
	ctx, cancel := context.WithTimeout(world.ctx, 30*time.Second)
	defer cancel()
	if err := clock.AwaitTimers(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if pending, since := writer.PendingHead(); pending != 2 || !since.Equal(clock.Now()) {
		t.Fatalf("pending %d since %v", pending, since)
	}
	if client.State().Base().GetConfigVersion() != 1 {
		t.Fatal("the pending head's base landed before its timeout")
	}
	// each minute the loop looks again; at 10 min it publishes
	for range 10 {
		clock.Advance(time.Minute)
		if err := clock.AwaitTimers(ctx, 1); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := client.WaitFor(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if base := client.State().Base(); base.GetConfigVersion() != 2 || base.GetFoldedThrough() != 0 {
		t.Errorf("the pending head's base: %v", base)
	}
}

// A device that is no config writer publishes nothing.
func TestOnlyAConfigWriterPublishes(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	client := world.client()
	world.caughtUp(client)
	stranger := testWriterDeviceOf("stranger", testWriterId("stranger member"))
	writer := world.writer(stranger, client, nil, 0, sidecartest.NewFakeClock(world.clock.Now()))
	if _, err := writer.PublishBase(world.ctx, true); !errors.Is(err, sidecar.ErrConfigWriterNotWriter) {
		t.Errorf("a stranger's base: %v", err)
	}
}

// A base that would keep both the fold and the head says nothing new, and none is published.
func TestAWriterPublishesNothingNew(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	client := world.client()
	world.caughtUp(client)
	writer := world.writer(world.owner, client, nil, 0, sidecartest.NewFakeClock(world.clock.Now()))
	if _, err := writer.PublishBase(world.ctx, false); !errors.Is(err, sidecar.ErrConfigWriterNothing) {
		t.Errorf("a base with nothing new: %v", err)
	}
	pin, err := writer.SaveHead(world.ctx, func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error) {
		return head.WithFile(sidecar.ConfigHeadPolicyPath, []byte("{\"grants\": []}"))
	})
	if err != nil || pin.GetVersion() != 2 || client.State().Base().GetConfigVersion() != 2 {
		t.Fatalf("a head saved: %v %v", pin, err)
	}
}
