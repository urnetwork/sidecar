// The Forwarder's follow and witness on the root's fakes (BRIDGE-M8-05; DESIGN-DETAILS 4.2.5): a config-client world's
// projection, heads and clock, a sink that holds what it is handed as a posture would, a gkm that serves the test's
// generations and wraps, and a key set the test hands off. No sidecar role runs.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A device role's posture as the Forwarder sees it: it holds the pins it is handed, applies a revocation as a denial
// and wants a compile for every other entry, and records each call.
type testForwarderSink struct {
	events    *testBridgeEvents
	stateLock sync.Mutex
	decision  BridgeSinkDecision
	// run inside SetState before the state is taken; an error refuses it
	onState func(state *bridge.BridgeState) error
}

func (self *testForwarderSink) SetPending(pending *bridge.Pending) error {
	self.stateLock.Lock()
	if self.decision.State == BridgeSinkLegacy {
		self.decision.State = BridgeSinkPending
	}
	self.stateLock.Unlock()
	self.events.add("pending")
	return nil
}

func (self *testForwarderSink) SetState(state *bridge.BridgeState, log *BridgeStateLog) error {
	self.stateLock.Lock()
	onState := self.onState
	self.stateLock.Unlock()
	if onState != nil {
		if err := onState(state); err != nil {
			return err
		}
	}
	n := state.GetAuth().GetVersion()
	dropped := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if n < self.decision.StatePin.GetVersion() {
			return true
		}
		self.decision.State = BridgeSinkEnforcing
		self.decision.StatePin = proto.Clone(state.GetAuth()).(*bridge.AuthPin)
		if self.decision.Pin.GetVersion() <= n {
			self.decision.Pin = proto.Clone(state.GetAuth()).(*bridge.AuthPin)
			self.decision.CompileWanted = false
		}
		return false
	}()
	if dropped {
		self.events.add(fmt.Sprintf("state %d dropped", n))
		return nil
	}
	self.events.add(fmt.Sprintf("state %d of %d entries", n, len(log.Entries)))
	return nil
}

func (self *testForwarderSink) ApplyDeltas(log *BridgeStateLog) error {
	positions := []string{}
	self.stateLock.Lock()
	for _, entryBytes := range log.Entries {
		entry := &bridge.AuthEntry{}
		if err := proto.Unmarshal(entryBytes, entry); err != nil {
			self.stateLock.Unlock()
			return err
		}
		chain, _ := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
		self.decision.Pin = &bridge.AuthPin{Version: entry.GetN(), Chain: chain[:]}
		signed := &bridge.Signed{}
		denial := false
		if entry.GetKind() == bridge.AuthEntryKindStatement && proto.Unmarshal(entry.GetBody(), signed) == nil {
			signedType := bridge.SignedType(signed.GetType())
			denial = signedType == bridge.SignedType_SIGNED_SIDECAR_REVOKE || signedType == bridge.SignedType_SIGNED_DELEGATION_REVOKE
		}
		if !denial {
			self.decision.CompileWanted = true
		}
		positions = append(positions, fmt.Sprint(entry.GetN()))
	}
	self.stateLock.Unlock()
	self.events.add("deltas " + strings.Join(positions, ","))
	return nil
}

func (self *testForwarderSink) SetFork(fork bool) error {
	self.stateLock.Lock()
	self.decision.Fork = fork
	self.stateLock.Unlock()
	self.events.add(fmt.Sprint("fork ", fork))
	return nil
}

func (self *testForwarderSink) Decision() BridgeSinkDecision {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.decision
}

// A forwarding key set as sdk's hand-off holds it: the current slot's Delegation and key, and the reader keys handed
// off so far.
type testForwarderKeys struct {
	stateLock    sync.Mutex
	delegationId [sha256.Size]byte
	key          ed25519.PrivateKey
	readerKeys   []ForwarderReaderKey
}

func (self *testForwarderKeys) Delegation() ([sha256.Size]byte, ed25519.PublicKey, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.key == nil {
		return [sha256.Size]byte{}, nil, false
	}
	return self.delegationId, self.key.Public().(ed25519.PublicKey), true
}

func (self *testForwarderKeys) Sign(message []byte) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return ed25519.Sign(self.key, message), nil
}

func (self *testForwarderKeys) ReaderKeys() ([]ForwarderReaderKey, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.readerKeys), nil
}

// Hands off one more reader key.
func (self *testForwarderKeys) handOff(delegationId []byte, readerKey hpke.PrivateKey) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.readerKeys = append(self.readerKeys, ForwarderReaderKey{DelegationId: [sha256.Size]byte(delegationId), PrivateKey: readerKey})
}

// gkm as the forwarding client reads it: the config group's GenRotates in order, and each generation's wraps by
// recipient.
type testForwarderGkm struct {
	stateLock   sync.Mutex
	generations []*bridge.Signed
	wraps       map[uint64]map[string][]*bridge.Signed
	// how many wraps queries asked late
	lateAskCount int
	// how many reads of the generations it answered
	generationsReadCount int
	// run at each read of the generations before it answers; an error fails the read
	onGenerations func(ctx context.Context) error
}

func (self *testForwarderGkm) Generations(ctx context.Context, repoId Id, groupId Id, since uint64) (*protocol.GkmGenerationsReply, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.onGenerations != nil {
		if err := self.onGenerations(ctx); err != nil {
			return nil, err
		}
	}
	self.generationsReadCount += 1
	reply := &protocol.GkmGenerationsReply{}
	if since < uint64(len(self.generations)) {
		reply.Generations = slices.Clone(self.generations[since:])
	}
	return reply, nil
}

func (self *testForwarderGkm) Wraps(ctx context.Context, repoId Id, groupId Id, generation uint64, query *GkmWrapsQuery) (*protocol.GkmWrapsReply, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if 0 < len(query.Want) {
		self.lateAskCount += 1
	}
	return &protocol.GkmWrapsReply{Wraps: slices.Clone(self.wraps[generation][query.Recipient])}, nil
}

// The heads the net's writer saved, each with the fixture's block, as the forwarding reader key opens them.
type testForwarderHeads struct {
	world *testForwarderWorld
	reads atomic.Int64
	// a head to answer for every version instead, as a server serving another's
	forged atomic.Pointer[ConfigHead]
	// run at each read before it answers; an error fails the read
	onRead func(ctx context.Context) error
}

func (self *testForwarderHeads) ReadConfigHead(ctx context.Context, configVersion uint64, configHeadSha256 []byte) (*ConfigHead, error) {
	self.reads.Add(1)
	if self.onRead != nil {
		if err := self.onRead(ctx); err != nil {
			return nil, err
		}
	}
	if forged := self.forged.Load(); forged != nil {
		return forged, nil
	}
	head := self.world.ledger.heads[configVersion]
	if head == nil || !bytes.Equal(configHeadSha256, testConfigHeadSha256(configVersion)) {
		return nil, ErrConfigHeadUnavailable
	}
	return head.WithFile(ConfigHeadBridgeBlockPath, self.world.blockFile)
}

// The world's store, which refuses to create one record when a test says, as a kill before it would.
type testForwarderStore struct {
	*testConfigClientStore
	onCreate func(name string) error
}

func (self *testForwarderStore) Create(name string) (SidecarStoreWriter, error) {
	if self.onCreate != nil {
		if err := self.onCreate(name); err != nil {
			return nil, err
		}
	}
	return self.testConfigClientStore.Create(name)
}

// The Forwarder's world: a network whose host sidecar S filed a forwarding Delegation with a real reader key, S and a
// peer addressed under generation 1, and the fakes a VPN component would give the Forwarder.
type testForwarderWorld struct {
	*testConfigClientWorld
	// the net's writer: its judge, and the head each base names
	ledger       *testBridgeLedgerNet
	host         testConfigDevice
	peer         testConfigDevice
	groupId      Id
	blockFile    []byte
	delegationId []byte
	readerKey    hpke.PrivateKey
	sink         *testForwarderSink
	keys         *testForwarderKeys
	gkm          *testForwarderGkm
	forwardHeads *testForwarderHeads
	forwardStore *testForwarderStore
	// the world's projection, unreachable while a test says
	api       *testForwarderFailingProjection
	events    *testBridgeEvents
	settings  *ForwarderSettings
	heapInUse atomic.Int64
	lapsed    atomic.Bool
	stateLock sync.Mutex
	// api's signed binding of each sidecar
	bindings map[Id][]byte
}

// An X-Wing reader key from a label, the same on every run.
func testForwarderReaderKey(t testing.TB, label string) hpke.PrivateKey {
	t.Helper()
	privateKey, err := hpke.MLKEM768X25519().NewPrivateKey(gkmTestBytes("forwarder reader "+label, 32))
	if err != nil {
		t.Fatal(err)
	}
	return privateKey
}

func newTestForwarderWorld(t *testing.T) *testForwarderWorld {
	clientWorld := newTestConfigClientWorld(t)
	net := clientWorld.net
	// the net's own reader judges bodies with generation 1's key, as the config's writers do
	ledger := newTestBridgeLedgerNetOver(t, net)
	_, laptop, desktop := testBridgeCast(net)
	self := &testForwarderWorld{
		testConfigClientWorld: clientWorld,
		ledger:                ledger,
		host:                  laptop,
		peer:                  desktop,
		groupId:               testConfigId("config group"),
		blockFile:             net.sign(net.owner, bridge.SignedType_SIGNED_BRIDGE_BLOCK, testBridgeCompileBlock()),
		events:                newTestBridgeEvents(),
		gkm:                   &testForwarderGkm{wraps: map[uint64]map[string][]*bridge.Signed{}},
		keys:                  &testForwarderKeys{},
		settings:              DefaultForwarderSettings(ForwarderHostDesktop),
		bindings:              map[Id][]byte{},
	}
	self.sink = &testForwarderSink{events: self.events, decision: BridgeSinkDecision{State: BridgeSinkLegacy}}
	self.forwardHeads = &testForwarderHeads{world: self}
	self.forwardStore = &testForwarderStore{testConfigClientStore: clientWorld.store}
	self.api = &testForwarderFailingProjection{inner: clientWorld.projection}
	self.settings.CompileDelay = 0
	self.settings.CompileMinInterval = 0
	self.settings.ConfigLog = testConfigLogSettings()

	var forwardKey ed25519.PrivateKey
	self.delegationId, self.readerKey, forwardKey = self.forward("host")
	self.keys.delegationId, self.keys.key = [sha256.Size]byte(self.delegationId), forwardKey
	self.keys.handOff(self.delegationId, self.readerKey)
	net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_ADDRESS, net.bridgeAddress(laptop, testBridgeIpv4(100, 80, 3, 7)))
	net.mustPost(desktop, bridge.SignedType_SIGNED_BRIDGE_ADDRESS, net.bridgeAddress(desktop, testBridgeIpv4(100, 80, 3, 9)))
	clientWorld.publish()
	return self
}

// Files a forwarding Delegation of the host under a real reader key from label: its id, the reader key and the
// forwarding key.
func (self *testForwarderWorld) forward(label string) ([]byte, hpke.PrivateKey, ed25519.PrivateKey) {
	self.t.Helper()
	readerKey := testForwarderReaderKey(self.t, label)
	statement, forwardKey := self.net.forwardingStatement(self.host, label)
	statement.ReaderXwingPublicKey = readerKey.PublicKey().Bytes()
	verdict := self.net.mustPost(self.host, bridge.SignedType_SIGNED_DELEGATION, statement)
	return bytes.Clone(verdict.StatementId[:]), readerKey, forwardKey
}

// api's binding of a device to a client, signed by the device's identity key.
func (self *testForwarderWorld) bind(device testConfigDevice) {
	self.t.Helper()
	clientSeed := sha256.Sum256(append([]byte("forwarder test client "), device.sidecarId.Bytes()...))
	signed, err := NewSidecarIdentityBinding(&SidecarIdentityBinding{
		NetworkId: self.net.networkId, SidecarId: device.sidecarId, ClientId: Id(clientSeed[:len(Id{})]), Generation: 1,
		IssuedAt: time.UnixMilli(testConfigStartMs),
	}, device.key.Seed(), clientSeed[:])
	if err != nil {
		self.t.Fatal(err)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.bindings[device.sidecarId] = signed
}

// The config group's next generation at gkm, rotated by the owner's device, its key the one the net seals that
// generation's bodies under, with a DelegationWrap for each Delegation among recipients.
func (self *testForwarderWorld) rotate(recipients ...testForwarderRecipient) uint64 {
	self.t.Helper()
	self.gkm.stateLock.Lock()
	generation := uint64(len(self.gkm.generations)) + 1
	self.gkm.stateLock.Unlock()
	repoId := self.net.configRepoId()
	repoKey := testConfigSealKey(generation).repoKey
	state := self.net.log.State()
	holders := sha256.Sum256([]byte("forwarder test holders"))
	rotate := &protocol.GenRotate{
		GroupId: self.groupId.Bytes(), RepoId: repoId.Bytes(), Generation: generation,
		Commitment: gkmCommitment(repoId, generation, repoKey), Cause: uint32(GkmCauseSchedule),
		Auth: state.Pin(), TimeMs: state.TimeMs(), HoldersSha256: holders[:],
	}
	if 1 < generation {
		parentKey := testConfigSealKey(generation - 1).repoKey
		linkKey, err := gkmDeriveKey(repoKey, repoId, EvsKeyPurposeLink, generation, nil)
		if err != nil {
			self.t.Fatal(err)
		}
		genLink, err := gkmSeal(linkKey, parentKey, gkmGenLinkAad(repoId, generation, GkmCauseSchedule))
		if err != nil {
			self.t.Fatal(err)
		}
		rotate.ParentCommitment, rotate.Genlink = gkmCommitment(repoId, generation-1, parentKey), genLink
	}
	signed, err := SignGenRotate(rotate, gkmForwardSigner(self.net.owner))
	if err != nil {
		self.t.Fatal(err)
	}
	self.gkm.stateLock.Lock()
	self.gkm.generations = append(self.gkm.generations, signed)
	self.gkm.stateLock.Unlock()
	for _, recipient := range recipients {
		self.wrap(generation, recipient)
	}
	return generation
}

// A Delegation a wrap seals to.
type testForwarderRecipient struct {
	delegationId []byte
	readerKey    hpke.PrivateKey
}

// The host's first forwarding Delegation as a wrap's recipient.
func (self *testForwarderWorld) recipient() testForwarderRecipient {
	return testForwarderRecipient{delegationId: self.delegationId, readerKey: self.readerKey}
}

// A DelegationWrap of a generation gkm holds to one Delegation's reader key, signed by the owner's device.
func (self *testForwarderWorld) wrap(generation uint64, recipient testForwarderRecipient) {
	self.t.Helper()
	self.gkm.stateLock.Lock()
	signedRotate := self.gkm.generations[generation-1]
	self.gkm.stateLock.Unlock()
	parsed, err := ParseGenRotate(testConfigMarshal(self.t, signedRotate), self.groupId, generation, GkmIdentityKeys(self.net.log.State()))
	if err != nil {
		self.t.Fatal(err)
	}
	key, err := OpenEvsRepoKey(parsed, testConfigSealKey(generation).repoKey)
	if err != nil {
		self.t.Fatal(err)
	}
	delivery, err := SealGkmDelivery(key, &GkmDeliveryArgs{
		GroupId: self.groupId, Type: GkmWrapTypeDelegation, Recipient: recipient.delegationId,
		RecipientPublicKey: recipient.readerKey.PublicKey().Bytes(), Kind: GkmDeliveryStaged,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	signed, err := SignGkmDelivery(delivery, GkmWrapTypeDelegation, gkmForwardSigner(self.net.owner))
	if err != nil {
		self.t.Fatal(err)
	}
	self.gkm.stateLock.Lock()
	defer self.gkm.stateLock.Unlock()
	if self.gkm.wraps[generation] == nil {
		self.gkm.wraps[generation] = map[string][]*bridge.Signed{}
	}
	name := forwarderWrapRecipient(recipient.delegationId)
	self.gkm.wraps[generation][name] = append(self.gkm.wraps[generation][name], signed)
}

// A Forwarder for the host over the world, under ctx, closed at the test's end.
func (self *testForwarderWorld) forwarderIn(ctx context.Context) *Forwarder {
	self.t.Helper()
	genesisChain := bridge.GenesisChain(self.net.signedGenesis)
	forwarder, err := NewForwarder(ctx, &ForwarderArgs{
		NetworkId:     self.net.networkId,
		SidecarId:     self.host.sidecarId,
		Pending:       &bridge.Pending{NetworkId: self.net.networkId.Bytes(), GenesisSha256: genesisChain[:]},
		ConfigRepoId:  self.net.configRepoId(),
		ConfigGroupId: self.groupId,
		Projection:    self.api,
		Heads:         self.forwardHeads,
		Gkm:           self.gkm,
		Binding: func(ctx context.Context, sidecarId Id) ([]byte, error) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if signed, found := self.bindings[sidecarId]; found {
				return signed, nil
			}
			return nil, errors.New("no binding")
		},
		ClientLapsed: self.lapsed.Load,
		Store:        self.forwardStore,
		Keys:         self.keys,
		Sink:         self.sink,
		NameZones:    []string{"net.ur.example"},
		HeapInUse:    self.heapInUse.Load,
		Emit: func(event SidecarEvent) {
			switch event.Kind {
			case SidecarEventBridgeAlarm:
				self.events.add("alarm " + string(event.BridgeAlarm))
			case SidecarEventHeadAlarm:
				self.events.add("head_alarm " + string(event.HeadAlarm))
			}
		},
		Clock:    self.clock,
		Log:      NewNoopLogger(),
		Settings: self.settings,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(forwarder.Close)
	return forwarder
}

// forwarderIn the background context, settled.
func (self *testForwarderWorld) forwarder() *Forwarder {
	self.t.Helper()
	forwarder := self.forwarderIn(context.Background())
	self.settle(forwarder)
	return forwarder
}

// Waits until the Forwarder's loop is idle: every hint read, and no follow or compile due at the clock's time. A
// barrier on the loop's own goroutine, never a sleep.
func (self *testForwarderWorld) settle(forwarder *Forwarder) {
	self.t.Helper()
	for {
		idle := false
		err := forwarder.onRun(func() {
			hint, _ := forwarder.hint.Get()
			now := forwarder.clock.Now()
			idle = hint.seq == forwarder.hintSeen && !forwarder.followWanted && forwarder.followAt.After(now) &&
				(!forwarder.compileWanted || forwarder.compileDueAt().After(now))
		})
		if err != nil {
			self.t.Fatal(err)
		}
		if idle {
			return
		}
	}
}

// Serves what the net sequenced, hints it as a team hint would, and waits for the Forwarder to settle.
func (self *testForwarderWorld) hint(forwarder *Forwarder) {
	self.t.Helper()
	self.publish()
	forwarder.ReceiveHint(self.net.n)
	self.settle(forwarder)
}

// Moves the clock and waits for the Forwarder to settle.
func (self *testForwarderWorld) advance(forwarder *Forwarder, by time.Duration) {
	self.t.Helper()
	self.clock.Advance(by)
	self.settle(forwarder)
}

// How many of the events hold for match.
func (self *testForwarderWorld) count(match func(event string) bool) int {
	count := 0
	for _, event := range self.events.list() {
		if match(event) {
			count += 1
		}
	}
	return count
}

// How many states the sink took.
func (self *testForwarderWorld) stateCount() int {
	return self.count(func(event string) bool {
		return strings.HasPrefix(event, "state ") && !strings.HasSuffix(event, " dropped")
	})
}

// Whether an alarm of the reason stands in a status.
func testForwarderAlarmStands(status ForwarderStatus, reason string) bool {
	return slices.ContainsFunc(status.Alarms, func(alarm BridgeAlarm) bool { return alarm.Reason == SidecarBridgeAlarm(reason) })
}

// The store's names under a prefix.
func (self *testForwarderWorld) stored(prefix string) []string {
	self.t.Helper()
	entries, err := self.forwardStore.List(prefix)
	if err != nil {
		self.t.Fatal(err)
	}
	names := []string{}
	for _, entry := range entries {
		names = append(names, entry.Name)
	}
	return names
}

// A Forwarder over a legacy sink anchors it, follows the log into its store and hands it a first state at the tip with
// the run from the base: the store then holds the genesis, the run, the base's rows, the head and the compile's
// record, and a restart signs by that record with no further compile.
func TestTheForwarderAnchorsFollowsAndCompilesAFirstState(t *testing.T) {
	world := newTestForwarderWorld(t)
	forwarder := world.forwarderIn(context.Background())
	world.settle(forwarder)
	tip := world.net.n
	events := world.events.list()
	if len(events) != 2 || events[0] != "pending" || events[1] != fmt.Sprintf("state %d of %d entries", tip, tip) {
		t.Fatalf("the sink's calls: %v", events)
	}
	status := forwarder.Status()
	if status.Decision.State != BridgeSinkEnforcing || status.Tip.GetVersion() != tip || !proto.Equal(status.CompiledPin, world.net.log.State().Pin()) ||
		status.CompileCount != 1 || status.CompileErrorCount != 0 || status.Admission != ForwarderCompileAdmitted || len(status.Alarms) != 0 {
		t.Fatalf("status %+v", status)
	}
	if !bytes.Equal(status.ForwardDelegationId, world.delegationId) {
		t.Errorf("the state's forwarding Delegation is %x", status.ForwardDelegationId)
	}
	if _, inForce := forwarder.LinkTargets(); !inForce {
		t.Error("no state in force after the sink took one")
	}
	if len(world.stored(forwarderGenesisName)) != 1 || len(world.stored(forwarderLogPrefix)) != int(tip) || len(world.stored(forwarderRowsPrefix)) != 1 ||
		len(world.stored(forwarderHeadPrefix)) != 1 || len(world.stored(forwarderCompiledName)) != 1 {
		t.Errorf("the store holds %v", world.stored(""))
	}

	forwarder.Close()
	restarted := world.forwarder()
	if got := restarted.Status(); !proto.Equal(got.CompiledPin, status.CompiledPin) || got.Digest != status.Digest || got.CompileCount != 0 {
		t.Errorf("a restart's status %+v", got)
	}
	if _, inForce := restarted.LinkTargets(); !inForce || world.stateCount() != 1 || world.forwardHeads.reads.Load() != 1 {
		t.Errorf("a restart compiled again or read the head again: %v", world.events.list())
	}
}

// §8.9's revocation path: a revocation reaches the sink as a delta at its own position and nothing compiles, and an
// entry that opens reaches it as a delta and then only by a compile's state.
func TestARevocationReachesTheSinkWithNoCompileAndAnOpeningOnlyByOne(t *testing.T) {
	world := newTestForwarderWorld(t)
	forwarder := world.forwarder()
	net := world.net
	revoked := net.mustPost(world.host, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(world.peer, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)).Pin.GetVersion()
	world.hint(forwarder)
	if events := world.events.list(); events[len(events)-1] != fmt.Sprint("deltas ", revoked) {
		t.Fatalf("the revocation's calls: %v", events)
	}
	if status := forwarder.Status(); status.CompileCount != 1 || status.Decision.Pin.GetVersion() != revoked || status.CompiledPin.GetVersion() != revoked-1 {
		t.Fatalf("a revocation compiled: %+v", status)
	}
	if _, inForce := forwarder.LinkTargets(); !inForce {
		t.Error("a denial above the state took it out of force")
	}

	net.consentedMember("other")
	opened := net.n
	world.hint(forwarder)
	events := world.events.list()
	state := fmt.Sprintf("state %d of %d entries", opened, opened)
	if events[len(events)-1] != state || !strings.HasPrefix(events[len(events)-2], "deltas ") {
		t.Fatalf("an opening's calls: %v", events)
	}
	if status := forwarder.Status(); status.CompileCount != 2 || status.CompiledPin.GetVersion() != opened {
		t.Errorf("status %+v", status)
	}
}

// 4.2.5's Witness: a pin off the Forwarder's chain is head_alarm fork and one past what api serves is withheld; fork
// true sets the sink's fork, and nothing compiles until a witness with fork false, which compiles what waited.
func TestAWitnessReportsAPinOffItsChainAndHoldsCompilesWhileForked(t *testing.T) {
	world := newTestForwarderWorld(t)
	forwarder := world.forwarder()
	net := world.net
	tip := net.log.State().Pin()
	if err := forwarder.Witness(tip, false); err != nil {
		t.Fatal(err)
	}
	if world.count(func(event string) bool {
		return strings.HasPrefix(event, "head_alarm") || strings.HasPrefix(event, "fork")
	}) != 0 {
		t.Fatalf("a witness on the chain raised: %v", world.events.list())
	}
	if err := forwarder.Witness(&bridge.AuthPin{Version: tip.GetVersion() + 40, Chain: bytes.Repeat([]byte{4}, sha256.Size)}, false); err != nil {
		t.Fatal(err)
	}
	if world.count(func(event string) bool { return event == "head_alarm "+string(SidecarHeadAlarmWithheld) }) != 1 {
		t.Fatalf("a pin past api's tip: %v", world.events.list())
	}
	if err := forwarder.Witness(&bridge.AuthPin{Version: tip.GetVersion(), Chain: bytes.Repeat([]byte{4}, sha256.Size)}, true); err != nil {
		t.Fatal(err)
	}
	events := world.events.list()
	if events[len(events)-2] != "head_alarm "+string(SidecarHeadAlarmFork) || events[len(events)-1] != "fork true" {
		t.Fatalf("a pin off the chain: %v", events)
	}
	if _, inForce := forwarder.LinkTargets(); inForce {
		t.Error("a forked sink's state is in force for the signer")
	}

	net.consentedMember("joined while forked")
	world.hint(forwarder)
	if world.stateCount() != 1 || forwarder.Status().CompileCount != 1 {
		t.Fatalf("a compile ran while forked: %v", world.events.list())
	}
	if err := forwarder.Witness(net.log.State().Pin(), false); err != nil {
		t.Fatal(err)
	}
	world.settle(forwarder)
	events = world.events.list()
	if events[len(events)-2] != "fork false" || events[len(events)-1] != fmt.Sprintf("state %d of %d entries", net.n, net.n) {
		t.Fatalf("the witness that cleared the fork: %v", events)
	}
}

// A page whose first entry does not chain onto the stored tip is head_alarm fork and nothing of it is kept; the log's
// own entry at that position is then taken.
func TestAPageOffTheStoredChainIsAForkAndIsNotKept(t *testing.T) {
	world := newTestForwarderWorld(t)
	forwarder := world.forwarder()
	net := world.net
	tip := net.n
	net.consentedMember("after the fork")
	world.projection.publish(net)
	forged := &bridge.AuthEntry{}
	if err := proto.Unmarshal(net.entries[tip], forged); err != nil {
		t.Fatal(err)
	}
	forged.PrevChain = bytes.Repeat([]byte{9}, sha256.Size)
	world.projection.stateLock.Lock()
	world.projection.entries = append(slices.Clone(world.projection.entries[:tip]), testConfigMarshal(t, forged))
	world.projection.stateLock.Unlock()
	forwarder.ReceiveHint(tip + 1)
	world.settle(forwarder)
	if world.count(func(event string) bool { return event == "head_alarm "+string(SidecarHeadAlarmFork) }) != 1 {
		t.Fatalf("a page off the chain: %v", world.events.list())
	}
	if status := forwarder.Status(); status.Tip.GetVersion() != tip || len(world.stored(forwarderLogPrefix)) != int(tip) || status.CompileCount != 1 {
		t.Fatalf("the forged page was kept: %+v", status)
	}
	world.hint(forwarder)
	if status := forwarder.Status(); status.Tip.GetVersion() != net.n || status.CompiledPin.GetVersion() != net.n {
		t.Errorf("the log's own entries after the forged page: %+v", status)
	}
}

// Single-flight: two hints that arrive while a compile is handing its state make one follow and one more compile, at
// the newest entry.
func TestTwoHintsDuringACompileMakeOneMoreCompile(t *testing.T) {
	world := newTestForwarderWorld(t)
	net := world.net
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	world.sink.onState = func(state *bridge.BridgeState) error {
		once.Do(func() {
			close(entered)
			<-release
		})
		return nil
	}
	forwarder := world.forwarderIn(context.Background())
	<-entered
	first := net.n
	net.consentedMember("first during the compile")
	world.publish()
	forwarder.ReceiveHint(net.n)
	net.consentedMember("second during the compile")
	world.publish()
	forwarder.ReceiveHint(net.n)
	close(release)
	world.settle(forwarder)
	events := world.events.list()
	want := []string{"pending", fmt.Sprintf("state %d of %d entries", first, first)}
	if !slices.Equal(events[:2], want) || len(events) != 4 || !strings.HasPrefix(events[2], "deltas ") || events[3] != fmt.Sprintf("state %d of %d entries", net.n, net.n) {
		t.Fatalf("the sink's calls: %v", events)
	}
	if status := forwarder.Status(); status.CompileCount != 2 || status.FollowCount != 2 {
		t.Errorf("status %+v", status)
	}
}

// A follow that cannot reach api is retried after FollowRetryInterval, doubling, and raises forward_client_lapsed only
// when the forwarding client's credential lapsed; the alarm clears at the next follow that reaches api.
func TestAFailedFollowRetriesAndALapsedClientAlarms(t *testing.T) {
	world := newTestForwarderWorld(t)
	forwarder := world.forwarder()
	world.api.fail.Store(true)
	forwarder.ReceiveHint(0)
	world.settle(forwarder)
	if status := forwarder.Status(); status.FollowCount != 2 || len(status.Alarms) != 0 {
		t.Fatalf("a failed follow with a live client: %+v", status)
	}
	world.lapsed.Store(true)
	world.advance(forwarder, world.settings.FollowRetryInterval-time.Second)
	if forwarder.Status().FollowCount != 2 {
		t.Fatal("the retry ran before its interval")
	}
	world.advance(forwarder, time.Second)
	if status := forwarder.Status(); status.FollowCount != 3 || !testForwarderAlarmStands(status, ForwarderAlarmForwardClientLapsed) {
		t.Fatalf("a failed follow with a lapsed client: %+v", status)
	}
	world.api.fail.Store(false)
	world.advance(forwarder, 2*world.settings.FollowRetryInterval)
	if status := forwarder.Status(); status.FollowCount != 4 || len(status.Alarms) != 0 {
		t.Fatalf("the follow that reached api: %+v", status)
	}
}

// A projection reader that fails while a test says.
type testForwarderFailingProjection struct {
	inner ConfigProjectionReader
	fail  atomic.Bool
}

func (self *testForwarderFailingProjection) ReadConfigProjection(ctx context.Context, after uint64) (*ConfigProjection, error) {
	if self.fail.Load() {
		return nil, errors.New("the test's api is unreachable")
	}
	return self.inner.ReadConfigProjection(ctx, after)
}
