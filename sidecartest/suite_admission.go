// §22.7's admission suite (TEAM-M2-19; S1, S3; R-TEAM-9, D-TEAM-12, D-TEAM-17, D-TEAM-24, D-TRUST-1), with a malicious
// server and a lone admin as its adversaries, end to end on one tier's api: T2's FakeApi here and server's real
// sequencer at T3 (server/api/sidecar_admission_t3_test.go), so a row relies only on what both do (D-TEST-2).
//
// One AdmissionNet is one network on that api, every part of it real code: BootstrapNetwork signs the genesis and base
// 1, a ConfigWriter over its own ConfigClient publishes every later base and saves every config head to sidecartest's
// in-memory config repo (FakeConfigHeads), and statements are signed by the devices, recovery keys, Delegations and
// presence keys a row makes and appended at api, which verifies each at its tip as §7.9's statement row says. Every
// entry api lands is then read back from the store and applied, in position order, by every kind of verifier
// DESIGN-DETAILS 5.2.4 names, and the rest are compared with the first after every entry (5.7's note for this task,
// the property sidecartest/model/details/AuthLog.tla checks, on real code):
//
//	reference    a long-running full reader from the genesis, every base's config head read and checked
//	             (CheckConfigBase) and compiled again
//	new device   a full reader started at each base b as §7.9's retention row starts one, from the entries at b's
//	             retention point through b (RestoreConfigLog, StartAtBase's anchor included)
//	gate         a rows-only verifier restarted at each base the same way (RestoreConfigLogRowsOnly), as api, evs and
//	             gkm verify, then fed each later entry as a run (ApplyRun)
//	follower     the writer's own ConfigClient, the device follower a daemon runs, once it stands at the tip
//
// Each holds, at every position it stands at, the reference's pin, rows, threshold, retention point and open proposals,
// and the reference's verdict class for every entry it judged; a reader that forks where the reference does not, or
// stands anywhere else, fails the row. A row about a malicious server allows forks (AllowForks) and asks who forked.
//
// What is not the system here, each named in the task's report: the acl compile is the suite's stand-in
// (admissionAclCompile) until ACL-M2-04 registers CompileAcl (C-05); the config repo is in memory, since no file-mode
// head reader over evs exists yet (TEAM-M2-10's report); and the rows about MLS, wraps and devices' alarms (a
// recovery-admitted device self-joining, committers' commits, seats' ReaderWraps, agents reading by their reader key,
// M's devices raising admission_alarm) check only the verified state those flows read, since no Sidecar here runs a
// GkmClient or an EvsClient.
//
// A row is a top-level test on each tier (AdmissionRows, RunAdmissionRow); a row fails its test with t.Fatalf.
// Nothing here sleeps: api's clock is a FakeClock the rows move, and every wait is a monitor's.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Tunables of the admission suite.
type AdmissionSuiteSettings struct {
	// How long, in real time, one row may wait on a store or a follower before it fails: only ever a failure's bound,
	// since every wait is a monitor's. 120 s, past a T3 row's store round trips.
	RowTimeout time.Duration
	// Whether api appends a tick that activates a recovery window its verifier holds due (§7.9's Recovery). T2's
	// FakeApi appends every tick and leaves the judgment to readers; server's sequencer refuses every activation until
	// its checkConfigLogTick takes them (TEAM-M2-14), so a T3 run sets this false and a row's activation clauses run
	// on T2 alone, which the T3 test logs.
	ApiTakesActivations bool
	// Whether the tier's api can append what its own check refuses, as a malicious sequencer does (AdmissionApi's
	// SequenceAnyway). A forged clause runs on T2 alone (plan-TEST-small-readings reading 6), so T3 sets this false and
	// a row skips its forged steps there, which the T3 test logs.
	ForgedAppends bool
}

// T2's values.
func DefaultAdmissionSuiteSettings() *AdmissionSuiteSettings {
	return &AdmissionSuiteSettings{
		RowTimeout:          120 * time.Second,
		ApiTakesActivations: true,
		ForgedAppends:       true,
	}
}

// api's log as the suite drives it: §7.9's three appends (ConfigLogSequencer, whose refusals are *ConfigLogRefusal) and
// GET /network/config/projection's read.
type AdmissionApi interface {
	ConfigLogSequencer
	// The entries after after, a page at most, with the rows of their bases and, from 0, the Signed Genesis.
	ReadConfigProjection(ctx context.Context, networkId sidecar.Id, after uint64) (*sidecar.ConfigProjection, error)
	// Appends an entry of any kind with any body at the tip, unverified, as a malicious or compromised sequencer does
	// (FS-102, FS-124): every reader refuses it at its position, or forks on a base that fails. A tier whose
	// AdmissionSuiteSettings.ForgedAppends is false answers an error.
	SequenceAnyway(ctx context.Context, networkId sidecar.Id, kind uint32, body []byte) (*bridge.AuthPin, error)
}

// Makes one api over cluster on clock, the tier's.
type AdmissionApiFactory func(clock sidecar.Clock, cluster sidecar.BlobCluster) AdmissionApi

// FakeApi as an AdmissionApi.
func FakeApiAdmission(api *FakeApi) AdmissionApi {
	return fakeApiAdmission{api: api}
}

type fakeApiAdmission struct {
	api *FakeApi
}

func (self fakeApiAdmission) AppendStatement(ctx context.Context, networkId sidecar.Id, signed []byte) (*bridge.AuthPin, error) {
	return self.api.AppendStatement(ctx, networkId, signed)
}

func (self fakeApiAdmission) AppendBase(ctx context.Context, networkId sidecar.Id, signedHeader []byte, rows []byte, genesis []byte, configPushes [][]byte) (*bridge.AuthPin, error) {
	return self.api.AppendBase(ctx, networkId, signedHeader, rows, genesis, configPushes)
}

func (self fakeApiAdmission) AppendTick(ctx context.Context, networkId sidecar.Id, tick *bridge.ApiTick) (*bridge.AuthPin, error) {
	return self.api.AppendTick(ctx, networkId, tick)
}

func (self fakeApiAdmission) ReadConfigProjection(ctx context.Context, networkId sidecar.Id, after uint64) (*sidecar.ConfigProjection, error) {
	return (&FakeApiConfigReader{Api: self.api, NetworkId: networkId}).ReadConfigProjection(ctx, after)
}

func (self fakeApiAdmission) SequenceAnyway(ctx context.Context, networkId sidecar.Id, kind uint32, body []byte) (*bridge.AuthPin, error) {
	return self.api.SequenceAnyway(ctx, networkId, kind, body)
}

// One tier the suite runs on: a cluster its networks share, each row on a network id of its own, and its api.
type AdmissionTier struct {
	// The tier's first metadata cluster, where api keeps proj/ and projrows/.
	Cluster sidecar.BlobCluster
	// Makes the api a row's network appends through.
	NewApi AdmissionApiFactory
	// nil for DefaultAdmissionSuiteSettings.
	Settings *AdmissionSuiteSettings
	// The clock api and every statement read, which a fault schedule's Net shares; nil for one of the network's own.
	Clock *FakeClock
	// What the network's followers and writer run under, a Net's, so they end with it; nil for the background.
	Context context.Context
}

// What a world fails through: a testing.TB, or a fault schedule's step, which turns a failure into the step's error.
type AdmissionT interface {
	Helper()
	Fatal(args ...any)
	Fatalf(format string, args ...any)
	Logf(format string, args ...any)
}

// The tier a fault schedule's admission world runs on: the Net's first metadata cluster, clock and context, and the
// api NetSettings.ConfigLogApi names, which server's T3 sets to its sequencer, else a FakeApi on the Net's faults and
// barriers (T2).
func (self *Net) AdmissionTier() (*AdmissionTier, error) {
	cluster, err := self.Host().Blobs.FirstCluster()
	if err != nil {
		return nil, err
	}
	tier := &AdmissionTier{Cluster: cluster, Clock: self.clock, Context: self.ctx, NewApi: self.settings.ConfigLogApi}
	if tier.NewApi == nil {
		tier.NewApi = func(clock sidecar.Clock, cluster sidecar.BlobCluster) AdmissionApi {
			return FakeApiAdmission(NewFakeApi(self.ctx, clock, self.faults, self.barriers, cluster, nil))
		}
	}
	if self.settings.ConfigLogSettings != nil {
		tier.Settings = self.settings.ConfigLogSettings
	}
	return tier, nil
}

// One row of §22.7's admission suite.
type AdmissionRow struct {
	// The row's name, as the T2 and T3 tests run it.
	Name string
	Run  func(t testing.TB, net *AdmissionNet)
}

// Runs the row named on tier, on a network of its own, failing t with the row's first failure.
func RunAdmissionRow(t testing.TB, name string, tier *AdmissionTier) {
	t.Helper()
	index := slices.IndexFunc(AdmissionRows(), func(row *AdmissionRow) bool { return row.Name == name })
	if index < 0 {
		t.Fatalf("no admission row %q", name)
	}
	net := NewAdmissionNet(t, tier)
	defer net.Close()
	AdmissionRows()[index].Run(t, net)
}

// One device of the network: its sidecar, its member (zero for a tagged sidecar) and its identity key.
type AdmissionDevice struct {
	Name      string
	SidecarId sidecar.Id
	MemberId  sidecar.Id
	Key       ed25519.PrivateKey
}

// The identity key's public half.
func (self *AdmissionDevice) PublicKey() []byte {
	return self.Key.Public().(ed25519.PublicKey)
}

// A member's recovery key (§7.9's Recovery): what the member's code derives, here a fixed key.
type AdmissionRecoveryKey struct {
	MemberId sidecar.Id
	Key      ed25519.PrivateKey
}

// The key's hash, as rows and a RecoveryBind name it.
func (self *AdmissionRecoveryKey) Sha256() []byte {
	digest := sha256.Sum256(self.Key.Public().(ed25519.PublicKey))
	return digest[:]
}

// A Delegation the network declared (§7.8): its id, the signing key a bundle carries, and what it declared.
type AdmissionDelegation struct {
	Id       []byte
	Key      ed25519.PrivateKey
	TagIds   []sidecar.Id
	NotAfter int64
}

// One verifier the suite runs beside the reference.
type admissionReader struct {
	name string
	log  *sidecar.ConfigLog
	// the base it started at, 0 for one that walked from the genesis
	start uint64
	// the verdict it reached at each position it judged
	verdicts map[uint64]sidecar.ConfigVerdict
	// why it stopped, nil while it applies
	fork error
	// the position it forked at
	forkN uint64
}

// One network on a tier's api, and every verifier of it.
type AdmissionNet struct {
	t        AdmissionT
	ctx      context.Context
	cancel   context.CancelFunc
	settings *AdmissionSuiteSettings
	clock    *FakeClock
	cluster  sidecar.BlobCluster
	newApi   AdmissionApiFactory
	api      AdmissionApi

	networkId    sidecar.Id
	configRepoId sidecar.Id
	heads        *FakeConfigHeads
	owner        *AdmissionDevice
	nonce        uint64

	signedGenesis []byte
	genesisChain  [sha256.Size]byte
	restoreAcl    func()

	// the writer: a config writer's device, its own follower and its ConfigWriter, on a clock of its own that no row
	// moves, so its fold loop publishes only what a row asks
	writerDevice *AdmissionDevice
	writerClock  *FakeClock
	follower     *sidecar.ConfigClient
	writer       *sidecar.ConfigWriter

	// what api served, by position, and every base's rows by rows_sha256
	entries map[uint64][]byte
	rows    map[[sha256.Size]byte][]byte
	// the position every reader has applied through
	applied   uint64
	reference *admissionReader
	readers   []*admissionReader
	// a row about a malicious server lets readers fork
	allowForks bool
	// whether new devices and gates start at each base, and whether readers are compared after every entry or only
	// at bases
	everyBase  bool
	everyEntry bool
	// runs once before the writer's next publish reaches api, as another appender landing first
	beforePublish func()
}

// A fresh network on tier, bootstrapped: its owner's first device signed the genesis and base 1, which every verifier
// applied. The caller closes it.
func NewAdmissionNet(t AdmissionT, tier *AdmissionTier) *AdmissionNet {
	t.Helper()
	settings := tier.Settings
	if settings == nil {
		settings = DefaultAdmissionSuiteSettings()
	}
	parent := tier.Context
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, settings.RowTimeout)
	clock := tier.Clock
	if clock == nil {
		clock = NewFakeClock(DefaultClockStart())
	}
	self := &AdmissionNet{
		t:            t,
		ctx:          ctx,
		cancel:       cancel,
		settings:     settings,
		clock:        clock,
		cluster:      tier.Cluster,
		newApi:       tier.NewApi,
		api:          tier.NewApi(clock, tier.Cluster),
		networkId:    sidecar.NewId(),
		configRepoId: sidecar.NewId(),
		entries:      map[uint64][]byte{},
		rows:         map[[sha256.Size]byte][]byte{},
		everyBase:    true,
		everyEntry:   true,
	}
	self.restoreAcl = sidecar.RegisterConfigAclCompiler(admissionAclCompile)
	self.heads = NewFakeConfigHeads(self.configRepoId)
	ownerMemberId := self.Id("owner member")
	self.owner = self.Device("owner laptop", ownerMemberId)
	result, err := self.Bootstrap(self.owner)
	if err != nil || !result.Won {
		t.Fatalf("bootstrap: %v", err)
	}
	self.signedGenesis, self.genesisChain = result.SignedGenesis, result.GenesisChain
	reference, err := sidecar.NewConfigLog(admissionLogSettings(), self.signedGenesis)
	if err != nil {
		t.Fatal(err)
	}
	self.reference = &admissionReader{name: "the reference", log: reference, verdicts: map[uint64]sidecar.ConfigVerdict{}}
	self.Sync()
	self.UseWriter(self.owner)
	return self
}

// Stops the writer and its follower and restores the acl compile.
func (self *AdmissionNet) Close() {
	if self.writer != nil {
		self.writer.Close()
	}
	if self.follower != nil {
		self.follower.Close()
	}
	self.restoreAcl()
	self.cancel()
}

// A log's tunables, its refusals kept out of the test's output.
func admissionLogSettings() *sidecar.ConfigLogSettings {
	settings := sidecar.DefaultConfigLogSettings()
	settings.Log = sidecar.NewNoopLogger()
	return settings
}

// The suite's stand-in for ACL's compile (C-05) until ACL-M2-04 registers CompileAcl: the log's acl statements as they
// are, but for the tag owners a head's tags file declares, an AclRows whose atoms replace those of the same atom. Pure
// and idempotent, as compile must be, since every reader compiles again what the last base compiled.
func admissionAclCompile(head *sidecar.ConfigHead, aclStatements *protocol.AclRows) (*protocol.AclRows, error) {
	aclRows := proto.Clone(aclStatements).(*protocol.AclRows)
	tagsBytes := head.File(sidecar.ConfigHeadTagsPath)
	if tagsBytes == nil {
		return aclRows, nil
	}
	declared := &protocol.AclRows{}
	if err := proto.Unmarshal(tagsBytes, declared); err != nil {
		return nil, fmt.Errorf("the suite's tags file: %w", err)
	}
	atoms := []*protocol.AclAtom{}
	for _, atom := range aclRows.GetAtoms() {
		if !slices.ContainsFunc(declared.GetAtoms(), func(declaredAtom *protocol.AclAtom) bool {
			return bytes.Equal(declaredAtom.GetAtom(), atom.GetAtom())
		}) {
			atoms = append(atoms, atom)
		}
	}
	for _, atom := range declared.GetAtoms() {
		atoms = append(atoms, proto.Clone(atom).(*protocol.AclAtom))
	}
	slices.SortFunc(atoms, func(a *protocol.AclAtom, b *protocol.AclAtom) int {
		return bytes.Compare(a.GetAtom(), b.GetAtom())
	})
	aclRows.Atoms = atoms
	return aclRows, nil
}

// An id from a label, the same for the label in this network and unique to it, so rows on one real cluster never meet.
func (self *AdmissionNet) Id(label string) sidecar.Id {
	digest := sha256.Sum256(append(self.networkId.Bytes(), []byte("admission suite id "+label)...))
	return sidecar.Id(digest[:len(sidecar.Id{})])
}

// A device of member from a label, its key fixed by the label. A zero member is a tagged sidecar's.
func (self *AdmissionNet) Device(label string, memberId sidecar.Id) *AdmissionDevice {
	seed := sha256.Sum256(append(self.networkId.Bytes(), []byte("admission suite key "+label)...))
	return &AdmissionDevice{Name: label, SidecarId: self.Id("device " + label), MemberId: memberId, Key: ed25519.NewKeyFromSeed(seed[:])}
}

// A member's recovery key from a label.
func (self *AdmissionNet) RecoveryKey(memberId sidecar.Id, label string) *AdmissionRecoveryKey {
	seed := sha256.Sum256(append(self.networkId.Bytes(), []byte("admission suite recovery "+label)...))
	return &AdmissionRecoveryKey{MemberId: memberId, Key: ed25519.NewKeyFromSeed(seed[:])}
}

// The network's id, its owner's first device and the clock api and every statement read.
func (self *AdmissionNet) NetworkId() sidecar.Id {
	return self.networkId
}

func (self *AdmissionNet) Owner() *AdmissionDevice {
	return self.owner
}

func (self *AdmissionNet) Clock() *FakeClock {
	return self.clock
}

// The context a row's calls take, which ends at the row's timeout.
func (self *AdmissionNet) Context() context.Context {
	return self.ctx
}

// Lets readers fork, as a row about a malicious server's entries expects; Forks says who did.
func (self *AdmissionNet) AllowForks() {
	self.allowForks = true
}

// Stops starting a new device and a gate at each base from here on, for a row of many bases that checks its own.
func (self *AdmissionNet) StartReadersAtBases(start bool) {
	self.everyBase = start
}

// Compares readers after every entry, or with false only at each base and at CheckAgreement, for a row of a thousand
// admissions whose comparison would cost the square of them.
func (self *AdmissionNet) CompareEveryEntry(every bool) {
	self.everyEntry = every
}

// Compares every reader that stands with the reference now.
func (self *AdmissionNet) CheckAgreement() {
	self.t.Helper()
	for _, reader := range self.standing() {
		if err := admissionStatesEqual(reader.log.State(), self.State()); err != nil {
			self.t.Fatalf("%s at %d: %v", reader.name, self.applied, err)
		}
	}
}

// A device's signer for BootstrapNetwork and the writer: its identity key under the purpose given.
func (self *AdmissionNet) signFunction(device *AdmissionDevice) sidecar.ConfigSignFunction {
	return func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
		return &bridge.Signed{
			Body:      body,
			SignerId:  device.SidecarId.Bytes(),
			Signature: ed25519.Sign(device.Key, bridge.SignedBytes(purpose, signedType, body)),
			Type:      uint32(signedType),
		}, nil
	}
}

// The api as a ConfigProjectionReader and a ConfigBasePublisher.
func (self *AdmissionNet) projection() sidecar.ConfigProjectionReader {
	return admissionProjection{api: self.api, networkId: self.networkId}
}

func (self *AdmissionNet) publisher() sidecar.ConfigBasePublisher {
	return admissionPublisher{api: self.api, networkId: self.networkId, net: self}
}

// GET /network/config/projection of one network.
type admissionProjection struct {
	api       AdmissionApi
	networkId sidecar.Id
}

func (self admissionProjection) ReadConfigProjection(ctx context.Context, after uint64) (*sidecar.ConfigProjection, error) {
	return self.api.ReadConfigProjection(ctx, self.networkId, after)
}

// POST /network/config/projection of one network, as SidecarApi answers it: a 409 ErrConfigTipMoved, a 403
// ErrConfigRefused.
type admissionPublisher struct {
	api       AdmissionApi
	networkId sidecar.Id
	// the network whose BeforePublish runs first, nil for none
	net *AdmissionNet
}

func (self admissionPublisher) PublishConfigBase(ctx context.Context, base *sidecar.ConfigBasePublish) (*bridge.AuthPin, error) {
	if self.net != nil && self.net.beforePublish != nil {
		before := self.net.beforePublish
		self.net.beforePublish = nil
		before()
	}
	pin, err := self.api.AppendBase(ctx, self.networkId, base.SignedHeader, base.Rows, base.Genesis, base.ConfigPushes)
	if err == nil {
		return pin, nil
	}
	refusal := &ConfigLogRefusal{}
	if errors.As(err, &refusal) {
		switch refusal.Status {
		case http.StatusConflict:
			return nil, fmt.Errorf("%w: %w", sidecar.ErrConfigTipMoved, err)
		case http.StatusForbidden:
			return nil, fmt.Errorf("%w: %w", sidecar.ErrConfigRefused, err)
		}
	}
	return nil, err
}

// BootstrapNetwork by device, the owner's: §7.9's bootstrap on the tier's api.
func (self *AdmissionNet) Bootstrap(device *AdmissionDevice) (*sidecar.ConfigBootstrapResult, error) {
	return sidecar.BootstrapNetwork(self.ctx, &sidecar.ConfigBootstrapArgs{
		NetworkId:         self.networkId,
		OwnerMemberId:     device.MemberId,
		SidecarId:         device.SidecarId,
		IdentityPublicKey: device.PublicKey(),
		Sign:              self.signFunction(device),
		ConfigRepoId:      self.configRepoId,
		Heads:             self.heads.For(device.SidecarId, device.Key),
		Publisher:         self.publisher(),
		Projection:        self.projection(),
		Clock:             self.clock,
	})
}

// Makes device the network's writer: a follower of its own and a ConfigWriter over it, on a clock no row moves.
func (self *AdmissionNet) UseWriter(device *AdmissionDevice) {
	self.t.Helper()
	if self.writer != nil {
		self.writer.Close()
		self.follower.Close()
	}
	self.writerDevice = device
	self.writerClock = NewFakeClock(self.clock.Now())
	clientSettings := sidecar.DefaultConfigClientSettings()
	clientSettings.Log = sidecar.NewNoopLogger()
	clientSettings.LogSettings = admissionLogSettings()
	follower, err := sidecar.NewConfigClient(self.ctx, &sidecar.ConfigClientArgs{
		NetworkId:    self.networkId,
		GenesisChain: self.genesisChain,
		Projection:   self.projection(),
		Heads:        self.heads,
		Clock:        self.writerClock,
		Settings:     clientSettings,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.follower = follower
	writerSettings := sidecar.DefaultConfigWriterSettings()
	writerSettings.Clock = self.writerClock
	writerSettings.Random = func() float64 { return 0 }
	writerSettings.Log = sidecar.NewNoopLogger()
	writer, err := sidecar.NewConfigWriter(self.ctx, &sidecar.ConfigWriterArgs{
		SidecarId: device.SidecarId,
		Sign:      self.signFunction(device),
		Client:    follower,
		Heads:     self.heads.For(device.SidecarId, device.Key),
		Publisher: self.publisher(),
		Settings:  writerSettings,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.writer = writer
	self.catchUpFollower()
}

// Waits for the writer's follower to stand at the reference's pin.
func (self *AdmissionNet) catchUpFollower() {
	self.t.Helper()
	if self.follower == nil || self.reference.fork != nil {
		return
	}
	if _, err := self.follower.WaitFor(self.ctx, self.applied); err != nil {
		if self.allowForks {
			return
		}
		self.t.Fatalf("the writer's follower at %d: %v", self.applied, err)
	}
}

// The newest pin every reader stands at.
func (self *AdmissionNet) Tip() *bridge.AuthPin {
	return self.reference.log.Pin()
}

// The reference's state at the tip.
func (self *AdmissionNet) State() *sidecar.ConfigState {
	return self.reference.log.State()
}

// A StatementHeader at the tip, a fresh nonce, expiring in an hour.
func (self *AdmissionNet) Header() *bridge.StatementHeader {
	return self.HeaderFor(time.Hour)
}

// A StatementHeader at the tip, a fresh nonce, expiring after life: a proposal a recovery window holds lives 7 days.
func (self *AdmissionNet) HeaderFor(life time.Duration) *bridge.StatementHeader {
	self.nonce += 1
	nonce := make([]byte, 16)
	copy(nonce, self.networkId.Bytes()[:8])
	binary.BigEndian.PutUint64(nonce[8:], self.nonce)
	return &bridge.StatementHeader{
		NetworkId:  self.networkId.Bytes(),
		At:         proto.Clone(self.Tip()).(*bridge.AuthPin),
		Nonce:      nonce,
		NotAfterMs: self.clock.Now().Add(life).UnixMilli(),
	}
}

// Deterministic bytes, as a signer writes them.
func (self *AdmissionNet) marshal(message proto.Message) []byte {
	self.t.Helper()
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		self.t.Fatal(err)
	}
	return encoded
}

// body as a Signed of signedType by device's identity key, unencoded, for a countersignature to go on first.
func (self *AdmissionNet) SignedBy(device *AdmissionDevice, signedType bridge.SignedType, body proto.Message) *bridge.Signed {
	self.t.Helper()
	bodyBytes := self.marshal(body)
	purpose, ok := sidecar.ConfigStatementPurpose(signedType)
	if !ok {
		self.t.Fatalf("%s is no config statement", signedType)
	}
	return &bridge.Signed{
		Body:      bodyBytes,
		SignerId:  device.SidecarId.Bytes(),
		Signature: ed25519.Sign(device.Key, bridge.SignedBytes(purpose, signedType, bodyBytes)),
		Type:      uint32(signedType),
	}
}

// body signed by device's identity key, as a Signed's bytes.
func (self *AdmissionNet) Sign(device *AdmissionDevice, signedType bridge.SignedType, body proto.Message) []byte {
	self.t.Helper()
	return self.marshal(self.SignedBy(device, signedType, body))
}

// body signed by a member's recovery key, as §6.9's Signers name it: signer_id the member, key_id the raw key.
func (self *AdmissionNet) SignByRecovery(key *AdmissionRecoveryKey, signedType bridge.SignedType, body proto.Message) []byte {
	self.t.Helper()
	bodyBytes := self.marshal(body)
	purpose, _ := sidecar.ConfigStatementPurpose(signedType)
	return self.marshal(&bridge.Signed{
		Body:      bodyBytes,
		SignerId:  key.MemberId.Bytes(),
		KeyId:     bytes.Clone(key.Key.Public().(ed25519.PublicKey)),
		Signature: ed25519.Sign(key.Key, bridge.SignedBytes(purpose, signedType, bodyBytes)),
		Type:      uint32(signedType),
	})
}

// body signed by a Delegation's key, as §6.9's Signers name it: signer_id its delegation_id, key_id its key's hash.
// Whoever holds a copy of the bundle signs the same.
func (self *AdmissionNet) SignByDelegation(delegation *AdmissionDelegation, signedType bridge.SignedType, body proto.Message) []byte {
	self.t.Helper()
	bodyBytes := self.marshal(body)
	purpose, _ := sidecar.ConfigStatementPurpose(signedType)
	keySha256 := sha256.Sum256(delegation.Key.Public().(ed25519.PublicKey))
	return self.marshal(&bridge.Signed{
		Body:      bodyBytes,
		SignerId:  bytes.Clone(delegation.Id),
		KeyId:     keySha256[:],
		Signature: ed25519.Sign(delegation.Key, bridge.SignedBytes(purpose, signedType, bodyBytes)),
		Type:      uint32(signedType),
	})
}

// A statement's id: SHA-256 of its signed bytes (protos-bridge-statement-id-wrapper), a proposal's proposal_id and a
// Delegation's delegation_id among them.
func AdmissionStatementId(signedBytes []byte) []byte {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(signedBytes, signed); err != nil {
		return nil
	}
	signedType := bridge.SignedType(signed.GetType())
	purpose, _ := sidecar.ConfigStatementPurpose(signedType)
	statementId := bridge.SignedBytesSha256(purpose, signedType, signed.GetBody())
	return statementId[:]
}

// Appends a signed statement at api and moves the clock on a second; every reader then applies what landed. The
// entry's pin, or api's refusal.
func (self *AdmissionNet) Post(signedBytes []byte) (*bridge.AuthPin, error) {
	self.t.Helper()
	pin, err := self.api.AppendStatement(self.ctx, self.networkId, signedBytes)
	self.clock.Advance(time.Second)
	self.Sync()
	return pin, err
}

// Post, failing the row unless api lands the statement and every reader's verdict there is that it took effect.
func (self *AdmissionNet) MustLand(signedBytes []byte) sidecar.ConfigVerdict {
	self.t.Helper()
	pin, err := self.Post(signedBytes)
	if err != nil {
		self.t.Fatalf("api refused a statement that should land: %v", err)
	}
	verdict := self.VerdictAt(pin.GetVersion())
	if !verdict.Accepted() {
		self.t.Fatalf("the entry at %d is refused: %v", pin.GetVersion(), verdict.Refusal)
	}
	return verdict
}

// Fails the row unless api answers 403 to the statement at its tip, appending nothing, and every reader, a new device
// at each base and a gate included, refuses it at the tip with want's class.
func (self *AdmissionNet) MustRefuse(signedBytes []byte, want error) {
	self.t.Helper()
	before := self.Tip()
	_, err := self.api.AppendStatement(self.ctx, self.networkId, signedBytes)
	refusal := &ConfigLogRefusal{}
	if !errors.As(err, &refusal) || refusal.Status != http.StatusForbidden {
		self.t.Fatalf("api's answer: %v, want 403", err)
	}
	self.clock.Advance(time.Second)
	self.Sync()
	if !proto.Equal(self.Tip(), before) {
		self.t.Fatalf("a refused statement moved the tip from %d to %d", before.GetVersion(), self.Tip().GetVersion())
	}
	self.MustRefuseEverywhere(signedBytes, want)
}

// Fails the row unless every reader standing refuses the statement at its tip with want's class.
func (self *AdmissionNet) MustRefuseEverywhere(signedBytes []byte, want error) {
	self.t.Helper()
	timeMs := self.clock.Now().UnixMilli()
	for _, reader := range self.everyReader() {
		if reader.fork != nil {
			continue
		}
		verdict := reader.log.Check(signedBytes, timeMs)
		if verdict.Accepted() || !errors.Is(verdict.Refusal, want) {
			self.t.Fatalf("%s's verdict: %v, want %v", reader.name, verdict.Refusal, want)
		}
	}
}

// Appends what api's own check would refuse, unverified, as a malicious or compromised api does (FS-102, FS-124), and
// every reader applies it. Fails the row on a tier whose api cannot (ForgedAppends).
func (self *AdmissionNet) SequenceAnyway(kind uint32, body []byte) *bridge.AuthPin {
	self.t.Helper()
	if !self.settings.ForgedAppends {
		self.t.Fatal("this tier's api appends nothing unverified: a forged clause runs on T2 alone")
	}
	before := self.applied
	_, err := self.api.SequenceAnyway(self.ctx, self.networkId, kind, body)
	self.clock.Advance(time.Second)
	self.Sync()
	// a base that forks the readers forks api's own verifier too, which answers its 503 though the entry landed
	if self.applied != before+1 {
		self.t.Fatalf("a malicious append landed %d entries: %v", self.applied-before, err)
	}
	entry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(self.entries[self.applied], entry); err != nil {
		self.t.Fatal(err)
	}
	chain, err := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
	if err != nil {
		self.t.Fatal(err)
	}
	return &bridge.AuthPin{Version: entry.GetN(), Chain: chain[:]}
}

// Whether the tier's api can append what its check refuses (ForgedAppends).
func (self *AdmissionNet) ForgedAppends() bool {
	return self.settings.ForgedAppends
}

// Appends api's tick and syncs; the pin, or api's refusal.
func (self *AdmissionNet) Tick(tick *bridge.ApiTick) (*bridge.AuthPin, error) {
	self.t.Helper()
	pin, err := self.api.AppendTick(self.ctx, self.networkId, tick)
	self.clock.Advance(time.Second)
	self.Sync()
	return pin, err
}

// Whether api appends the activation ticks this tier's readers take (AdmissionSuiteSettings.ApiTakesActivations).
func (self *AdmissionNet) ApiTakesActivations() bool {
	return self.settings.ApiTakesActivations
}

// A base by the writer, folding through the tip when fold is set; its pin. Every reader applies it.
func (self *AdmissionNet) Fold(fold bool) *bridge.AuthPin {
	self.t.Helper()
	pin := self.FoldIfAny(fold)
	if pin == nil {
		self.t.Fatal("a base with nothing new to publish")
	}
	return pin
}

// Fold, but nil when the writer has nothing new to publish: no tail to fold and the same head.
func (self *AdmissionNet) FoldIfAny(fold bool) *bridge.AuthPin {
	self.t.Helper()
	self.catchUpFollower()
	pin, err := self.writer.PublishBase(self.ctx, fold)
	if errors.Is(err, sidecar.ErrConfigWriterNothing) {
		return nil
	}
	if err != nil {
		self.t.Fatalf("a base: %v", err)
	}
	self.Sync()
	return pin
}

// A config head edit makes from the current one, saved by the writer with its base; the base's pin.
func (self *AdmissionNet) SaveHead(edit func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error)) *bridge.AuthPin {
	self.t.Helper()
	self.catchUpFollower()
	pin, err := self.writer.SaveHead(self.ctx, edit)
	if err != nil {
		self.t.Fatalf("a head: %v", err)
	}
	self.Sync()
	return pin
}

// The head's ServiceSettings set to settings, signed by the writer's device (an Owner's or Admin's, §7.9's
// ServiceSettings row), with its base: rows carry self_admit from that base on.
func (self *AdmissionNet) SetServiceSettings(settings *protocol.ServiceSettings) *bridge.AuthPin {
	self.t.Helper()
	signed := self.Sign(self.writerDevice, bridge.SignedType_SIGNED_SERVICE_SETTINGS, settings)
	return self.SaveHead(func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error) {
		return head.WithFile(sidecar.ConfigHeadServiceSettingsPath, signed)
	})
}

// The head's tags file declaring each tag's owner, which the suite's acl compile carries into AclRows' atoms.
func (self *AdmissionNet) SetTagOwners(tagOwners map[sidecar.Id]sidecar.Id) *bridge.AuthPin {
	self.t.Helper()
	declared := &protocol.AclRows{}
	for tagId, memberId := range tagOwners {
		declared.Atoms = append(declared.Atoms, &protocol.AclAtom{Atom: tagId.Bytes(), TagOwnerMemberIds: [][]byte{memberId.Bytes()}})
	}
	slices.SortFunc(declared.Atoms, func(a *protocol.AclAtom, b *protocol.AclAtom) int {
		return bytes.Compare(a.GetAtom(), b.GetAtom())
	})
	tagsBytes := self.marshal(declared)
	return self.SaveHead(func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error) {
		return head.WithFile(sidecar.ConfigHeadTagsPath, tagsBytes)
	})
}

// Moves api's clock on.
func (self *AdmissionNet) Wait(duration time.Duration) {
	self.clock.Advance(duration)
}

// The position every reader has read through, a forked one's included.
func (self *AdmissionNet) Applied() uint64 {
	return self.applied
}

// The reference's verdict at position n, failing the row when it holds none.
func (self *AdmissionNet) VerdictAt(n uint64) sidecar.ConfigVerdict {
	self.t.Helper()
	verdict, found := self.reference.verdicts[n]
	if !found {
		self.t.Fatalf("no verdict at %d", n)
	}
	return verdict
}

// What every verifier the suite runs is: the reference, each new device and gate, in start order.
func (self *AdmissionNet) everyReader() []*admissionReader {
	return append([]*admissionReader{self.reference}, self.readers...)
}

// Each reader that forked and the position it forked at, by name; the reference's under "the reference".
func (self *AdmissionNet) Forks() map[string]uint64 {
	forks := map[string]uint64{}
	for _, reader := range self.everyReader() {
		if reader.fork != nil {
			forks[reader.name] = reader.forkN
		}
	}
	return forks
}

// How many verifiers run, the reference's included.
func (self *AdmissionNet) ReaderCount() int {
	return 1 + len(self.readers)
}

// The readers that stand, not forked: new devices and gates (never the reference).
func (self *AdmissionNet) standing() []*admissionReader {
	standing := []*admissionReader{}
	for _, reader := range self.readers {
		if reader.fork == nil {
			standing = append(standing, reader)
		}
	}
	return standing
}

// The full reader's rows source: base rows from what api served, each base's config head read from the config repo
// and checked by CheckConfigBase, its compile against the log's rows at folded_through.
type admissionHeadSource struct {
	net *AdmissionNet
}

func (self admissionHeadSource) Rows(networkId sidecar.Id, rowsSha256 []byte) ([]byte, error) {
	if len(rowsSha256) == sha256.Size {
		if rows, found := self.net.rows[[sha256.Size]byte(rowsSha256)]; found {
			return bytes.Clone(rows), nil
		}
	}
	return nil, fmt.Errorf("%w: api served no rows at %x", sidecar.ErrConfigRowsUnavailable, rowsSha256)
}

func (self admissionHeadSource) CheckHead(check *sidecar.ConfigHeadCheck) (*sidecar.ConfigHeadFacts, error) {
	head, err := self.net.heads.ReadConfigHead(self.net.ctx, check.Header.GetConfigVersion(), check.Header.GetConfigHeadSha256())
	if err != nil {
		return nil, err
	}
	return sidecar.CheckConfigBase(head, check, check.CompileRows)
}

// The gate's: rows alone.
func (self *AdmissionNet) rowsOnlySource() sidecar.ConfigRowsOnlySource {
	return func(networkId sidecar.Id, rowsSha256 []byte) ([]byte, error) {
		return admissionHeadSource{net: self}.Rows(networkId, rowsSha256)
	}
}

// Reads everything api holds past the applied position, page by page, and applies each entry at every reader in
// position order, comparing them after each; then the writer's follower catches up.
func (self *AdmissionNet) Sync() {
	self.t.Helper()
	for {
		projection, err := self.api.ReadConfigProjection(self.ctx, self.networkId, self.applied)
		if err != nil {
			self.t.Fatalf("reading the log after %d: %v", self.applied, err)
		}
		for _, rows := range projection.Rows {
			self.rows[sha256.Sum256(rows)] = bytes.Clone(rows)
		}
		for _, entryBytes := range projection.Entries {
			self.applyEntry(entryBytes)
		}
		if !projection.More || len(projection.Entries) == 0 {
			break
		}
	}
	self.catchUpFollower()
	if !self.allowForks && self.follower != nil {
		if fork := self.follower.Fork(); fork != nil {
			self.t.Fatalf("the writer's follower forked: %v", fork)
		}
		if state := self.follower.State(); self.everyEntry && state != nil && state.Pin().GetVersion() == self.applied {
			if err := admissionStatesEqual(state, self.State()); err != nil {
				self.t.Fatalf("the writer's follower at %d: %v", self.applied, err)
			}
		}
	}
}

// One entry api served, at every reader, then the agreement check.
func (self *AdmissionNet) applyEntry(entryBytes []byte) {
	self.t.Helper()
	entry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(entryBytes, entry); err != nil {
		self.t.Fatalf("api served an entry that does not parse: %v", err)
	}
	n := entry.GetN()
	if n != self.applied+1 {
		self.t.Fatalf("api served %d after %d", n, self.applied)
	}
	self.entries[n] = bytes.Clone(entryBytes)
	self.applied = n

	apply := func(reader *admissionReader) {
		if reader.fork != nil {
			return
		}
		var verdicts []sidecar.ConfigVerdict
		var err error
		if reader.log.RowsOnly() {
			verdicts, err = reader.log.ApplyRun([][]byte{entryBytes}, self.rowsOnlySource())
		} else {
			var verdict sidecar.ConfigVerdict
			verdict, err = reader.log.Apply(entryBytes, admissionHeadSource{net: self})
			if err == nil {
				verdicts = []sidecar.ConfigVerdict{verdict}
			}
		}
		if err != nil {
			if errors.Is(err, sidecar.ErrConfigFork) || errors.Is(err, sidecar.ErrConfigRunRefused) {
				reader.fork, reader.forkN = err, n
				return
			}
			self.t.Fatalf("%s at %d: %v", reader.name, n, err)
		}
		for _, verdict := range verdicts {
			reader.verdicts[verdict.Pin.GetVersion()] = verdict
		}
	}
	for _, reader := range self.everyReader() {
		apply(reader)
	}
	if !self.allowForks {
		for _, reader := range self.everyReader() {
			if reader.fork != nil {
				self.t.Fatalf("%s forked at %d: %v", reader.name, reader.forkN, reader.fork)
			}
		}
	}
	if self.reference.fork != nil {
		return
	}
	if entry.GetKind() == bridge.AuthEntryKindBase && self.everyBase {
		self.startReadersAt(n)
	}
	if !self.everyEntry && entry.GetKind() != bridge.AuthEntryKindBase {
		return
	}
	for _, reader := range self.standing() {
		if err := self.agrees(reader, n); err != nil {
			self.t.Fatalf("%s at %d: %v", reader.name, n, err)
		}
	}
}

// A new device and a gate started at the base at n, from the entries at its retention point through it, as §7.9's
// retention row starts a reader that holds nothing else.
func (self *AdmissionNet) startReadersAt(n uint64) {
	self.t.Helper()
	point := self.State().RetentionPoint()
	retained := &sidecar.ConfigRetained{SignedGenesis: self.signedGenesis, Rows: map[[sha256.Size]byte][]byte{}}
	for k := point; k <= n; k += 1 {
		entryBytes, found := self.entries[k]
		if !found {
			self.t.Fatalf("no entry at %d, inside base %d's retention", k, n)
		}
		retained.Entries = append(retained.Entries, entryBytes)
	}
	device, err := sidecar.RestoreConfigLog(admissionLogSettings(), retained, admissionHeadSource{net: self})
	if err != nil {
		self.t.Fatalf("a new device at base %d: %v", n, err)
	}
	gate, err := sidecar.RestoreConfigLogRowsOnly(admissionLogSettings(), retained, self.rowsOnlySource(), nil)
	if err != nil {
		self.t.Fatalf("a gate at base %d: %v", n, err)
	}
	self.readers = append(self.readers,
		&admissionReader{name: fmt.Sprintf("a new device at base %d", n), log: device, start: n, verdicts: map[uint64]sidecar.ConfigVerdict{}},
		&admissionReader{name: fmt.Sprintf("a gate at base %d", n), log: gate, start: n, verdicts: map[uint64]sidecar.ConfigVerdict{}},
	)
}

// Whether reader stands where the reference does after the entry at n: the same state, and the same verdict class at
// n where it judged n.
func (self *AdmissionNet) agrees(reader *admissionReader, n uint64) error {
	if err := admissionStatesEqual(reader.log.State(), self.State()); err != nil {
		return err
	}
	if n <= reader.start {
		return nil
	}
	want, wantFound := self.reference.verdicts[n]
	got, gotFound := reader.verdicts[n]
	if !wantFound || !gotFound {
		return fmt.Errorf("no verdict at %d", n)
	}
	if want.Accepted() != got.Accepted() || AdmissionRefusalClass(want.Refusal) != AdmissionRefusalClass(got.Refusal) ||
		want.Completed() != got.Completed() {
		return fmt.Errorf("the verdict at %d is %v, the reference's %v", n, got.Refusal, want.Refusal)
	}
	return nil
}

// Whether two states stand alike: pin, rows (ProjectionRows' deterministic bytes, open proposals, ring and settings
// among them), threshold, retention point and the open proposals' ids.
func admissionStatesEqual(a *sidecar.ConfigState, b *sidecar.ConfigState) error {
	if !proto.Equal(a.Pin(), b.Pin()) {
		return fmt.Errorf("pin %d, the reference's %d", a.Pin().GetVersion(), b.Pin().GetVersion())
	}
	encode := proto.MarshalOptions{Deterministic: true}
	aRows, err := encode.Marshal(a.Rows())
	if err != nil {
		return err
	}
	bRows, err := encode.Marshal(b.Rows())
	if err != nil {
		return err
	}
	if !bytes.Equal(aRows, bRows) {
		return fmt.Errorf("rows differ at %d", a.Pin().GetVersion())
	}
	aK, aN := a.Threshold()
	bK, bN := b.Threshold()
	if aK != bK || aN != bN {
		return fmt.Errorf("k %d of %d, the reference's %d of %d", aK, aN, bK, bN)
	}
	if a.RetentionPoint() != b.RetentionPoint() {
		return fmt.Errorf("retention point %d, the reference's %d", a.RetentionPoint(), b.RetentionPoint())
	}
	aProposals, bProposals := a.OpenProposalIds(), b.OpenProposalIds()
	if len(aProposals) != len(bProposals) {
		return fmt.Errorf("%d open proposals, the reference's %d", len(aProposals), len(bProposals))
	}
	for i := range aProposals {
		if !bytes.Equal(aProposals[i], bProposals[i]) {
			return fmt.Errorf("open proposal %d differs", i)
		}
	}
	return nil
}

// The refusal sentinel a verdict carries, the narrowest first, or nil for one that took effect.
func AdmissionRefusalClass(err error) error {
	if err == nil {
		return nil
	}
	for _, class := range []error{sidecar.ErrConfigPresence, sidecar.ErrConfigReadOnly, sidecar.ErrConfigRuleMissing,
		sidecar.ErrConfigReplay, sidecar.ErrConfigSigner, sidecar.ErrConfigAuthority, sidecar.ErrConfigRule, sidecar.ErrConfigRefused} {
		if errors.Is(err, class) {
			return class
		}
	}
	return err
}

// A MemberAdmit at the tip.
func (self *AdmissionNet) MemberAdmit(memberId sidecar.Id, role bridge.MemberRole) *protocol.MemberAdmit {
	return &protocol.MemberAdmit{Header: self.Header(), MemberId: memberId.Bytes(), Role: role}
}

// A SidecarAdmit of device at the tip: its member, or tagIds when there are any.
func (self *AdmissionNet) Admission(device *AdmissionDevice, tagIds []sidecar.Id, ephemeral bool, notAfter int64, capabilities uint32) *protocol.SidecarAdmit {
	admit := &protocol.SidecarAdmit{
		Header:            self.Header(),
		NetworkId:         self.networkId.Bytes(),
		SidecarId:         device.SidecarId.Bytes(),
		IdentityPublicKey: device.PublicKey(),
		IdentityAlg:       "ed25519",
		Ephemeral:         ephemeral,
		NotAfter:          notAfter,
		Capabilities:      capabilities,
	}
	if len(tagIds) == 0 {
		admit.MemberId = device.MemberId.Bytes()
	}
	for _, tagId := range tagIds {
		admit.TagIds = append(admit.TagIds, tagId.Bytes())
	}
	return admit
}

// An AdminSet at the tip.
func (self *AdmissionNet) AdminSet(owners []sidecar.Id, admins []sidecar.Id, threshold uint32) *protocol.AdminSet {
	adminSet := &protocol.AdminSet{Header: self.Header(), Threshold: threshold}
	for _, owner := range owners {
		adminSet.Owners = append(adminSet.Owners, owner.Bytes())
	}
	for _, admin := range admins {
		adminSet.Admins = append(adminSet.Admins, admin.Bytes())
	}
	return adminSet
}

// An AuthorityProposal of body at the tip, good for 7 days, which a recovery window needs.
func (self *AdmissionNet) Proposal(signedType bridge.SignedType, body proto.Message) *protocol.AuthorityProposal {
	return &protocol.AuthorityProposal{Header: self.HeaderFor(7 * 24 * time.Hour), StatementType: uint32(signedType), Statement: self.marshal(body)}
}

// An AuthorityCosign of a proposal at the tip.
func (self *AdmissionNet) Cosign(proposalId []byte) *protocol.AuthorityCosign {
	return &protocol.AuthorityCosign{Header: self.Header(), ProposalId: bytes.Clone(proposalId)}
}

// A SidecarRevoke of device at the tip; sinceN for a compromise.
func (self *AdmissionNet) Revocation(device *AdmissionDevice, reason bridge.SidecarRevokeReason, sinceN uint64) *bridge.SidecarRevoke {
	return &bridge.SidecarRevoke{Header: self.Header(), SidecarId: device.SidecarId.Bytes(), Reason: reason, SinceN: sinceN}
}

// A MemberRevoke at the tip.
func (self *AdmissionNet) MemberRevoke(memberId sidecar.Id) *bridge.MemberRevoke {
	return &bridge.MemberRevoke{Header: self.Header(), MemberId: memberId.Bytes()}
}

// An OwnerConfirm and an AdmissionConfirm of device at the tip.
func (self *AdmissionNet) OwnerConfirm(device *AdmissionDevice) *protocol.OwnerConfirm {
	return &protocol.OwnerConfirm{Header: self.Header(), SidecarId: device.SidecarId.Bytes()}
}

func (self *AdmissionNet) AdmissionConfirm(device *AdmissionDevice) *protocol.AdmissionConfirm {
	return &protocol.AdmissionConfirm{Header: self.Header(), SidecarId: device.SidecarId.Bytes()}
}

// A RecoveryBind of key for its member at the tip, replacing the binding in effect. Its sealed body is opaque here:
// no verifier opens RecoveryBindBody (plan-TEAM-sealed-field-format), and genesis_sig is the code-only device's check.
func (self *AdmissionNet) RecoveryBind(key *AdmissionRecoveryKey) *protocol.RecoveryBind {
	return &protocol.RecoveryBind{
		Header:                 self.Header(),
		MemberId:               key.MemberId.Bytes(),
		PrevSha256:             bytes.Clone(self.State().Member(key.MemberId).GetRecoveryKeySha256()),
		Ed25519PublicKeySha256: key.Sha256(),
		SealedBody:             []byte("sealed body: opened only by a reader holding RK_g"),
	}
}

// A RecoveryRebind of key's member from the binding in effect to next, at the tip.
func (self *AdmissionNet) RecoveryRebind(next *AdmissionRecoveryKey, reason bridge.RecoveryRebindReason) *protocol.RecoveryRebind {
	return &protocol.RecoveryRebind{
		Header:                 self.Header(),
		MemberId:               next.MemberId.Bytes(),
		PrevSha256:             bytes.Clone(self.State().Member(next.MemberId).GetRecoveryKeySha256()),
		Ed25519PublicKeySha256: next.Sha256(),
		SealedBody:             []byte("sealed body: opened only by a reader holding RK_g"),
		Reason:                 reason,
	}
}

// A RecoveryVeto of a proposal at the tip.
func (self *AdmissionNet) RecoveryVeto(proposalId []byte) *protocol.RecoveryVeto {
	return &protocol.RecoveryVeto{Header: self.Header(), ProposalId: bytes.Clone(proposalId)}
}

// A Delegation at the tip, its signing key from label, with tagIds, maxAdmits and notAfter.
func (self *AdmissionNet) DelegationStatement(label string, tagIds []sidecar.Id, maxAdmits uint32, notAfter int64) (*protocol.Delegation, ed25519.PrivateKey) {
	seed := sha256.Sum256(append(self.networkId.Bytes(), []byte("admission suite delegation "+label)...))
	key := ed25519.NewKeyFromSeed(seed[:])
	delegation := &protocol.Delegation{
		Header:               self.Header(),
		Pubkey:               key.Public().(ed25519.PublicKey),
		ReaderXwingPublicKey: bytes.Repeat([]byte{0x5a}, 1216),
		MaxAdmits:            maxAdmits,
		NotAfter:             notAfter,
	}
	for _, tagId := range tagIds {
		delegation.TagIds = append(delegation.TagIds, tagId.Bytes())
	}
	return delegation, key
}

// Declares a Delegation signed by signer, which must land; its id is the statement's.
func (self *AdmissionNet) Delegate(signer *AdmissionDevice, label string, tagIds []sidecar.Id, maxAdmits uint32, notAfter int64) *AdmissionDelegation {
	self.t.Helper()
	statement, key := self.DelegationStatement(label, tagIds, maxAdmits, notAfter)
	signed := self.Sign(signer, bridge.SignedType_SIGNED_DELEGATION, statement)
	self.MustLand(signed)
	return &AdmissionDelegation{Id: AdmissionStatementId(signed), Key: key, TagIds: tagIds, NotAfter: notAfter}
}

// A DelegationRevoke at the tip.
func (self *AdmissionNet) DelegationRevoke(delegationId []byte, sinceN uint64) *protocol.DelegationRevoke {
	return &protocol.DelegationRevoke{Header: self.Header(), DelegationId: bytes.Clone(delegationId), SinceN: sinceN}
}

// Admits a member with a role, signed by signer; the member's id.
func (self *AdmissionNet) AdmitMember(signer *AdmissionDevice, label string, role bridge.MemberRole) sidecar.Id {
	self.t.Helper()
	memberId := self.Id("member " + label)
	self.MustLand(self.Sign(signer, bridge.SignedType_SIGNED_MEMBER_ADMIT, self.MemberAdmit(memberId, role)))
	return memberId
}

// Admits a member device signed by signer, which must land.
func (self *AdmissionNet) AdmitDevice(signer *AdmissionDevice, device *AdmissionDevice, capabilities uint32) sidecar.ConfigVerdict {
	self.t.Helper()
	return self.MustLand(self.Sign(signer, bridge.SignedType_SIGNED_SIDECAR_ADMIT, self.Admission(device, nil, false, 0, capabilities)))
}

// A member outside the AdminSet and its first device, admitted by the writer's device, an Owner's, from an invite, so
// consented (§8.5's invited clause).
func (self *AdmissionNet) ConsentedMember(label string) (sidecar.Id, *AdmissionDevice) {
	self.t.Helper()
	memberId := self.AdmitMember(self.writerDevice, label, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	first := self.Device(label+" first device", memberId)
	self.AdmitDevice(self.writerDevice, first, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
	if !self.Consented(first, memberId) {
		self.t.Fatalf("%s's invited first device is not consented", label)
	}
	return memberId, first
}

// Whether device is consented for member at the tip (§8.5), as every reader that stands answers it alike; a reader
// that answers otherwise fails the row.
func (self *AdmissionNet) Consented(device *AdmissionDevice, memberId sidecar.Id) bool {
	self.t.Helper()
	answers := []bool{}
	for _, reader := range self.everyReader() {
		if reader.fork != nil {
			continue
		}
		acl, err := reader.log.State().Acl()
		if err != nil {
			self.t.Fatalf("%s's acl state: %v", reader.name, err)
		}
		answers = append(answers, acl.ConsentedFor(device.SidecarId, memberId))
	}
	for _, answer := range answers {
		if answer != answers[0] {
			self.t.Fatalf("readers answer %v for %s's consent", answers, device.Name)
		}
	}
	return answers[0]
}

// Posts an AuthorityProposal of body by signer, which must land; its proposal_id and verdict.
func (self *AdmissionNet) Propose(signer *AdmissionDevice, signedType bridge.SignedType, body proto.Message) ([]byte, sidecar.ConfigVerdict) {
	self.t.Helper()
	signed := self.Sign(signer, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, self.Proposal(signedType, body))
	verdict := self.MustLand(signed)
	return AdmissionStatementId(signed), verdict
}

// A sidecar's row at the tip, nil for none.
func (self *AdmissionNet) Row(device *AdmissionDevice) *bridge.SidecarRow {
	return self.State().SidecarRow(device.SidecarId)
}

// Whether device stands admitted at the tip: a row, neither revoked nor parked.
func (self *AdmissionNet) Admitted(device *AdmissionDevice) bool {
	row := self.Row(device)
	return row != nil && row.GetRevokedAt() == 0 && row.GetParkedAt() == 0
}

// The suite's rows, in §22.7's order. A row that needs what this tier's api cannot do yet runs the rest of itself and
// logs what it left.
func AdmissionRows() []*AdmissionRow {
	return []*AdmissionRow{
		{Name: "signers", Run: admissionRowSigners},
		{Name: "outside the AdminSet", Run: admissionRowOutsideTheAdminSet},
		{Name: "the recovery window", Run: admissionRowRecoveryWindow},
		{Name: "two first devices racing", Run: admissionRowFirstDevicesRacing},
		{Name: "owner consent", Run: admissionRowOwnerConsent},
		{Name: "committers", Run: admissionRowCommitters},
		{Name: "seats", Run: admissionRowSeats},
		{Name: "agents cost no commit", Run: admissionRowAgents},
		{Name: "read-only page Workers", Run: admissionRowReadOnlyWorkers},
		{Name: "the compromise cascade", Run: admissionRowCascade},
		{Name: "auth keys", Run: admissionRowAuthKeys},
		{Name: "generated logs", Run: admissionRowGeneratedLogs},
	}
}

// A team at k = 2: the owner, and admins b and c whose first devices the owner admitted from invites, then an
// AdminSet of the three the owner filed alone at k = 1. Answers b's and c's devices.
func admissionTeam(t testing.TB, net *AdmissionNet) (*AdmissionDevice, *AdmissionDevice) {
	t.Helper()
	memberB := net.AdmitMember(net.owner, "admin b", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	memberC := net.AdmitMember(net.owner, "admin c", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	adminB, adminC := net.Device("admin b laptop", memberB), net.Device("admin c laptop", memberC)
	net.AdmitDevice(net.owner, adminB, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
	net.AdmitDevice(net.owner, adminC, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
	net.MustLand(net.Sign(net.owner, bridge.SignedType_SIGNED_ADMIN_SET, net.AdminSet([]sidecar.Id{net.owner.MemberId}, []sidecar.Id{memberB, memberC}, 0)))
	if k, n := net.State().Threshold(); k != 2 || n != 3 {
		t.Fatalf("k %d of n %d", k, n)
	}
	return adminB, adminC
}

// §22.7's signers: at k = 2 one signer's authority statement is refused, targets never counting; an AdminSet member's
// existing device counts as one of k for its new device and for revoking another of its own devices, so its phone's
// revocation of its laptop completes on one other admin's cosign; a member's devices and recovery key count once; a
// read-only device's cosign is refused.
func admissionRowSigners(t testing.TB, net *AdmissionNet) {
	adminB, adminC := admissionTeam(t, net)
	owner := net.Owner()
	// an AdminSet change, a MemberRevoke and an AdminSet member's new device, each by one signer: refused
	memberD := net.AdmitMember(owner, "d", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	dLaptop := net.Device("d laptop", memberD)
	net.AdmitDevice(owner, dLaptop, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
	grantD := func() *protocol.AdminSet {
		return net.AdminSet([]sidecar.Id{owner.MemberId}, []sidecar.Id{adminB.MemberId, adminC.MemberId, memberD}, 0)
	}
	net.MustRefuse(net.Sign(owner, bridge.SignedType_SIGNED_ADMIN_SET, grantD()), sidecar.ErrConfigAuthority)
	net.MustRefuse(net.Sign(owner, bridge.SignedType_SIGNED_MEMBER_REVOKE, net.MemberRevoke(adminB.MemberId)), sidecar.ErrConfigAuthority)
	ownerPhone := net.Device("owner phone", owner.MemberId)
	net.MustRefuse(net.Sign(owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.Admission(ownerPhone, nil, false, 0, 0)), sidecar.ErrConfigAuthority)

	// the AdminSet change granting d: d's own cosign never counts, the target's; b's completes it
	grantId, _ := net.Propose(owner, bridge.SignedType_SIGNED_ADMIN_SET, grantD())
	if pin, err := net.Post(net.Sign(dLaptop, bridge.SignedType_SIGNED_AUTHORITY_COSIGN, net.Cosign(grantId))); err == nil {
		if verdict := net.VerdictAt(pin.GetVersion()); verdict.Completed() {
			t.Fatal("the target's own cosign completed its AdminSet change")
		}
	}
	if !slices.ContainsFunc(net.State().OpenProposalIds(), func(id []byte) bool { return bytes.Equal(id, grantId) }) {
		t.Fatal("the AdminSet change closed before a counted cosign")
	}
	completed := net.MustLand(net.Sign(adminB, bridge.SignedType_SIGNED_AUTHORITY_COSIGN, net.Cosign(grantId)))
	if !completed.Completed() || net.State().Member(memberD).GetRole() != bridge.MemberRole_MEMBER_ROLE_ADMIN {
		t.Fatalf("b's cosign: completed %t, d's role %s", completed.Completed(), net.State().Member(memberD).GetRole())
	}

	// a member's devices and recovery key count once: the owner's proposal of its phone, cosigned by the owner's own
	// recovery key, stays open; c's cosign completes it
	ownerKey := net.RecoveryKey(owner.MemberId, "owner")
	bindId, _ := net.Propose(owner, bridge.SignedType_SIGNED_RECOVERY_BIND, net.RecoveryBind(ownerKey))
	net.MustLand(net.Sign(adminC, bridge.SignedType_SIGNED_AUTHORITY_COSIGN, net.Cosign(bindId)))
	if net.State().CurrentBinding(owner.MemberId) == nil {
		t.Fatal("the owner holds no binding")
	}
	phoneId, _ := net.Propose(owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.Admission(ownerPhone, nil, false, 0, 0))
	if pin, err := net.Post(net.SignByRecovery(ownerKey, bridge.SignedType_SIGNED_AUTHORITY_COSIGN, net.Cosign(phoneId))); err == nil {
		if verdict := net.VerdictAt(pin.GetVersion()); verdict.Completed() {
			t.Fatal("the owner's own recovery key counted as a second signer")
		}
	}
	if net.Admitted(ownerPhone) {
		t.Fatal("the owner's phone admitted on its own member's signatures")
	}
	if completed := net.MustLand(net.Sign(adminC, bridge.SignedType_SIGNED_AUTHORITY_COSIGN, net.Cosign(phoneId))); !completed.Completed() || !net.Admitted(ownerPhone) {
		t.Fatal("c's cosign did not admit the owner's phone")
	}

	// the phone revokes its laptop on one other admin's cosign, the revoked laptop never counting
	revokeId, _ := net.Propose(ownerPhone, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.Revocation(owner, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0))
	if pin, err := net.Post(net.Sign(owner, bridge.SignedType_SIGNED_AUTHORITY_COSIGN, net.Cosign(revokeId))); err == nil {
		if net.VerdictAt(pin.GetVersion()).Completed() {
			t.Fatal("the revoked laptop's own cosign counted")
		}
	}
	net.MustLand(net.Sign(adminB, bridge.SignedType_SIGNED_AUTHORITY_COSIGN, net.Cosign(revokeId)))
	if row := net.Row(owner); row.GetRevokedAt() == 0 {
		t.Fatal("the laptop stands")
	}
	net.UseWriter(ownerPhone)
	net.Fold(true)

	// a read-only device's cosign is refused
	memberM, mFirst := net.ConsentedMember("m")
	worker := net.Device("m page worker", memberM)
	net.AdmitDevice(mFirst, worker, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY))
	openId, _ := net.Propose(ownerPhone, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.MemberAdmit(net.Id("member by proposal"), bridge.MemberRole_MEMBER_ROLE_MEMBER))
	net.MustRefuse(net.Sign(worker, bridge.SignedType_SIGNED_AUTHORITY_COSIGN, net.Cosign(openId)), sidecar.ErrConfigReadOnly)
}

// §22.7 outside the AdminSet: member M's consented device admits M's untagged device at once unless self_admit is off,
// and revokes one whatever self_admit says; with it off an admin's device admits M's new device while M's phone, once
// M's OwnerConfirm consents it, still revokes M's lost laptop alone; M's recovery key admits at once or, with self_admit off, only on one admin's cosign,
// the device then consented (scoped). self_admit rides the config head and compiles into rows, so api and every gate
// judge M's own admission as a full reader does (DESIGN-DETAILS 5.2.3).
func admissionRowOutsideTheAdminSet(t testing.TB, net *AdmissionNet) {
	owner := net.Owner()
	memberM, laptop := net.ConsentedMember("m")
	tablet := net.Device("m tablet", memberM)
	net.AdmitDevice(laptop, tablet, 0)
	if !net.Consented(tablet, memberM) {
		t.Fatal("a device M's consented device admitted is not consented")
	}
	keyM := net.RecoveryKey(memberM, "m")
	net.MustLand(net.Sign(laptop, bridge.SignedType_SIGNED_RECOVERY_BIND, net.RecoveryBind(keyM)))
	watch := net.Device("m watch", memberM)
	net.MustLand(net.SignByRecovery(keyM, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.Admission(watch, nil, false, 0, 0)))
	if !net.Consented(watch, memberM) {
		t.Fatal("the recovery key's admission is not M's consent")
	}

	net.SetServiceSettings(&protocol.ServiceSettings{SelfAdmit: protocol.SelfAdmitMode_SELF_ADMIT_MODE_OFF})
	if net.State().SelfAdmit() {
		t.Fatal("self_admit is on after the head turned it off")
	}
	phone := net.Device("m phone", memberM)
	net.MustRefuse(net.Sign(laptop, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.Admission(phone, nil, false, 0, 0)), sidecar.ErrConfigAuthority)
	net.AdmitDevice(owner, phone, 0)
	net.MustLand(net.Sign(tablet, bridge.SignedType_SIGNED_OWNER_CONFIRM, net.OwnerConfirm(phone)))
	net.MustLand(net.Sign(phone, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.Revocation(laptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0)))

	// the key: a plain admission refused, its proposal completing on one admin's cosign and never M's own
	desktop := net.Device("m desktop", memberM)
	net.MustRefuse(net.SignByRecovery(keyM, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.Admission(desktop, nil, false, 0, 0)), sidecar.ErrConfigAuthority)
	proposal := net.SignByRecovery(keyM, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, net.Proposal(bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.Admission(desktop, nil, false, 0, 0)))
	net.MustLand(proposal)
	proposalId := AdmissionStatementId(proposal)
	net.MustRefuse(net.Sign(phone, bridge.SignedType_SIGNED_AUTHORITY_COSIGN, net.Cosign(proposalId)), sidecar.ErrConfigAuthority)
	if completed := net.MustLand(net.Sign(owner, bridge.SignedType_SIGNED_AUTHORITY_COSIGN, net.Cosign(proposalId))); !completed.Completed() {
		t.Fatal("the admin's cosign did not complete the scoped proposal")
	}
	if !net.Admitted(desktop) || !net.Consented(desktop, memberM) {
		t.Fatal("the desktop the key and an admin admitted is not admitted and consented")
	}
	net.Fold(true)
}

// A tick activating proposalId: whether it took effect at every reader. Before its window ends api may refuse it
// (server's does) or land it for readers to refuse (T2's FakeApi does); either is a refusal. On a tier whose api takes
// no activation, one the window holds due is skipped and logged, never counted a pass.
func (self *AdmissionNet) Activate(proposalId []byte) bool {
	self.t.Helper()
	pin, err := self.Tick(&bridge.ApiTick{ActivatedProposalIds: [][]byte{bytes.Clone(proposalId)}})
	if err != nil {
		refusal := &ConfigLogRefusal{}
		if !errors.As(err, &refusal) || refusal.Status != http.StatusForbidden {
			self.t.Fatalf("api's answer to a tick: %v", err)
		}
		return false
	}
	return self.VerdictAt(pin.GetVersion()).Accepted()
}

// The recovery window's state at the tip, failing the row when no window holds the proposal.
func (self *AdmissionNet) Window(proposalId []byte) *sidecar.ConfigRecoveryWindow {
	self.t.Helper()
	window, ok := self.State().RecoveryWindow(proposalId)
	if !ok {
		self.t.Fatal("no recovery window holds the proposal")
	}
	return window
}

// Files key's AuthorityProposal of admitting device, which must land and open a window; its proposal_id.
func (self *AdmissionNet) ProposeByRecovery(key *AdmissionRecoveryKey, device *AdmissionDevice) []byte {
	self.t.Helper()
	signed := self.SignByRecovery(key, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, self.Proposal(bridge.SignedType_SIGNED_SIDECAR_ADMIT, self.Admission(device, nil, false, 0, 0)))
	if verdict := self.MustLand(signed); verdict.Completed() {
		self.t.Fatal("a recovery key's proposal completed at once")
	}
	return AdmissionStatementId(signed)
}

// §22.7's recovery window (FS-16; owner decision 127) on api's clock: at k = 1 a proposal activates 72 h after its
// entry, a tick at 71 h refused, and a veto at 71 h wins; a RecoveryRebind of the subject voids it. At k = 2 the k-th
// signature completes no proposal a recovery key signed, which activates 72 h after the newest recovery signature,
// and a recovery cosign 72 h after an admin's proposal restarts the window there, a veto between winning.
func admissionRowRecoveryWindow(t testing.TB, net *AdmissionNet) {
	owner := net.Owner()
	key := net.RecoveryKey(owner.MemberId, "owner")
	net.MustLand(net.Sign(owner, bridge.SignedType_SIGNED_RECOVERY_BIND, net.RecoveryBind(key)))
	phone, tablet, watch := net.Device("owner phone", owner.MemberId), net.Device("owner tablet", owner.MemberId), net.Device("owner watch", owner.MemberId)
	net.MustRefuse(net.SignByRecovery(key, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.Admission(phone, nil, false, 0, 0)), sidecar.ErrConfigRefused)
	vetoedId := net.ProposeByRecovery(key, phone)
	activatedId := net.ProposeByRecovery(key, tablet)
	if pending := net.State().PendingProposals(); len(pending) != 2 {
		t.Fatalf("%d pending proposals", len(pending))
	}
	net.Fold(true)
	net.Wait(71 * time.Hour)
	if net.Activate(activatedId) {
		t.Fatal("a proposal activated 71 h after its entry")
	}
	vetoed := net.MustLand(net.Sign(owner, bridge.SignedType_SIGNED_RECOVERY_VETO, net.RecoveryVeto(vetoedId)))
	if window := net.Window(vetoedId); window.Closed != sidecar.ConfigProposalVetoed || window.ClosedAt != vetoed.Pin.GetVersion() {
		t.Fatalf("the vetoed window: %+v", window)
	}
	net.Fold(true)
	net.Wait(time.Hour)
	if net.Activate(vetoedId) {
		t.Fatal("a vetoed proposal activated")
	}
	if net.ApiTakesActivations() {
		if !net.Activate(activatedId) || !net.Admitted(tablet) {
			t.Fatal("the proposal no veto held did not activate at 72 h")
		}
		if net.Activate(activatedId) {
			t.Fatal("a second activation")
		}
	} else {
		t.Logf("this tier's api takes no activation tick, so the 72 h activation was not run here")
	}

	// a RecoveryRebind of the subject voids its open proposal, which then activates nowhere
	voidedId := net.ProposeByRecovery(key, watch)
	next := net.RecoveryKey(owner.MemberId, "owner next")
	net.MustLand(net.Sign(owner, bridge.SignedType_SIGNED_RECOVERY_REBIND, net.RecoveryRebind(next, bridge.RecoveryRebindReason_RECOVERY_REBIND_REASON_ROUTINE)))
	if window := net.Window(voidedId); window.Closed != sidecar.ConfigProposalVoided {
		t.Fatalf("the window after the rebind: %+v", window)
	}
	net.Wait(73 * time.Hour)
	if net.Activate(voidedId) || net.Admitted(watch) {
		t.Fatal("a voided proposal activated")
	}

	// k = 2: b's key and c's device
	adminB, adminC := admissionTeam(t, net)
	keyB := net.RecoveryKey(adminB.MemberId, "b")
	net.MustRefuse(net.Sign(adminB, bridge.SignedType_SIGNED_RECOVERY_BIND, net.RecoveryBind(keyB)), sidecar.ErrConfigAuthority)
	bindId, _ := net.Propose(adminB, bridge.SignedType_SIGNED_RECOVERY_BIND, net.RecoveryBind(keyB))
	net.MustLand(net.Sign(adminC, bridge.SignedType_SIGNED_AUTHORITY_COSIGN, net.Cosign(bindId)))
	bPhone := net.Device("b phone", adminB.MemberId)
	bProposalId := net.ProposeByRecovery(keyB, bPhone)
	if cosigned := net.MustLand(net.Sign(adminC, bridge.SignedType_SIGNED_AUTHORITY_COSIGN, net.Cosign(bProposalId))); cosigned.Completed() {
		t.Fatal("the k-th signature completed a recovery proposal")
	}
	net.Fold(true)
	net.Wait(72 * time.Hour)
	if net.ApiTakesActivations() {
		if !net.Activate(bProposalId) || !net.Admitted(bPhone) {
			t.Fatal("b's cosigned recovery proposal did not activate at 72 h")
		}
	}

	// the owner's proposal of c's tablet; b's key cosigns 72 h later and restarts the window there
	cTablet := net.Device("c tablet", adminC.MemberId)
	adminProposalId, _ := net.Propose(owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.Admission(cTablet, nil, false, 0, 0))
	net.Wait(72 * time.Hour)
	late := net.MustLand(net.SignByRecovery(keyB, bridge.SignedType_SIGNED_AUTHORITY_COSIGN, net.Cosign(adminProposalId)))
	if window := net.Window(adminProposalId); window.Row.GetWindowEntry() != late.Pin.GetVersion() {
		t.Fatalf("the window after the late recovery cosign: %+v", window.Row)
	}
	net.Fold(true)
	net.Wait(71 * time.Hour)
	if net.Activate(adminProposalId) {
		t.Fatal("an activation 71 h after the newest recovery signature")
	}
	net.MustLand(net.Sign(adminC, bridge.SignedType_SIGNED_RECOVERY_VETO, net.RecoveryVeto(adminProposalId)))
	net.Wait(2 * time.Hour)
	if net.Activate(adminProposalId) || net.Admitted(cTablet) {
		t.Fatal("a proposal vetoed between the late cosign and its activation activated")
	}
}

// §22.7: two first devices racing base 1 (proj/<network_id>/1/_) on two api instances over one cluster leave one
// genesis, which the loser learns and follows; the winner then admits the loser like any device, and a full reader
// of the winning genesis holds both.
func admissionRowFirstDevicesRacing(t testing.TB, net *AdmissionNet) {
	networkId := net.Id("racing network")
	heads := NewFakeConfigHeads(net.Id("racing config repo"))
	ownerMemberId := net.Id("racing owner")
	devices := []*AdmissionDevice{net.Device("racing first", ownerMemberId), net.Device("racing second", ownerMemberId)}
	apis := []AdmissionApi{net.newApi(net.clock, net.cluster), net.newApi(net.clock, net.cluster)}
	results := make([]*sidecar.ConfigBootstrapResult, len(devices))
	errs := make([]error, len(devices))
	done := make(chan int, len(devices))
	for i, device := range devices {
		go func() {
			defer func() { done <- i }()
			// a loser that read between the winner's entry 1 and its genesis, on another api instance, answers that
			// api's 503 (plan-TEAM-genesis-custody #3); its daemon bootstraps again, which learns the genesis
			for range 3 {
				results[i], errs[i] = sidecar.BootstrapNetwork(net.ctx, &sidecar.ConfigBootstrapArgs{
					NetworkId:         networkId,
					OwnerMemberId:     ownerMemberId,
					SidecarId:         device.SidecarId,
					IdentityPublicKey: device.PublicKey(),
					Sign:              net.signFunction(device),
					ConfigRepoId:      net.Id("racing config repo"),
					Heads:             heads.For(device.SidecarId, device.Key),
					Publisher:         admissionPublisher{api: apis[i], networkId: networkId},
					Projection:        admissionProjection{api: apis[i], networkId: networkId},
					Clock:             net.clock,
				})
				if errs[i] == nil {
					return
				}
			}
		}()
	}
	for range devices {
		<-done
	}
	for i, err := range errs {
		if err != nil {
			t.Fatalf("device %d: %v", i, err)
		}
	}
	if results[0].Won == results[1].Won || !bytes.Equal(results[0].SignedGenesis, results[1].SignedGenesis) {
		t.Fatalf("won %t and %t, one genesis %t", results[0].Won, results[1].Won, bytes.Equal(results[0].SignedGenesis, results[1].SignedGenesis))
	}
	winner, loser := 0, 1
	if results[1].Won {
		winner, loser = 1, 0
	}
	read, err := apis[loser].ReadConfigProjection(net.ctx, networkId, 0)
	if err != nil || !bytes.Equal(read.SignedGenesis, results[winner].SignedGenesis) || len(read.Entries) != 1 {
		t.Fatalf("api holds %d entries after the race: %v", len(read.Entries), err)
	}

	// the winner admits the loser at the tip, on the loser's api instance, which reads the winner's base
	tip := read.Tip
	net.nonce += 1
	nonce := make([]byte, 16)
	binary.BigEndian.PutUint64(nonce[8:], net.nonce)
	admit := &protocol.SidecarAdmit{
		Header:            &bridge.StatementHeader{NetworkId: networkId.Bytes(), At: tip, Nonce: nonce, NotAfterMs: net.clock.Now().Add(time.Hour).UnixMilli()},
		NetworkId:         networkId.Bytes(),
		SidecarId:         devices[loser].SidecarId.Bytes(),
		IdentityPublicKey: devices[loser].PublicKey(),
		IdentityAlg:       "ed25519",
		MemberId:          ownerMemberId.Bytes(),
	}
	if _, err := apis[loser].AppendStatement(net.ctx, networkId, net.Sign(devices[winner], bridge.SignedType_SIGNED_SIDECAR_ADMIT, admit)); err != nil {
		t.Fatalf("the winner's admission of the loser: %v", err)
	}
	clientSettings := sidecar.DefaultConfigClientSettings()
	clientSettings.Log = sidecar.NewNoopLogger()
	clientSettings.LogSettings = admissionLogSettings()
	client, err := sidecar.NewConfigClient(net.ctx, &sidecar.ConfigClientArgs{
		NetworkId:    networkId,
		GenesisChain: results[winner].GenesisChain,
		Projection:   admissionProjection{api: apis[winner], networkId: networkId},
		Heads:        heads,
		Clock:        NewFakeClock(net.clock.Now()),
		Settings:     clientSettings,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	state, err := client.WaitFor(net.ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range devices {
		if row := state.SidecarRow(device.SidecarId); row == nil || row.GetRevokedAt() != 0 {
			t.Fatalf("%s is not admitted", device.Name)
		}
	}
	if !state.IsConfigWriter(devices[loser].SidecarId) {
		t.Fatal("the loser, an Owner's device, writes no config")
	}
}

// §22.7's owner consent (owner decision 126): a device one admin admits under M reads neither M's vault nor mail
// until M's OwnerConfirm, consent resting with M's consented devices (scoped, first, confirmed); in M's vault an
// admin's grant to a reader is refused.
func admissionRowOwnerConsent(t testing.TB, net *AdmissionNet) {
	owner := net.Owner()
	memberM, first := net.ConsentedMember("m")
	scoped := net.Device("m scoped", memberM)
	net.AdmitDevice(first, scoped, 0)
	adminAdmitted := net.Device("m admin admitted", memberM)
	net.AdmitDevice(owner, adminAdmitted, 0)
	if !net.Consented(first, memberM) || !net.Consented(scoped, memberM) {
		t.Fatal("M's first or scoped device is not consented")
	}
	if net.Consented(adminAdmitted, memberM) {
		t.Fatal("a device an admin admitted under M is consented before M's OwnerConfirm")
	}
	vault := net.Sign(first, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{Header: net.Header(), RepoId: net.Id("m vault").Bytes(), Kind: protocol.RepoKind_REPO_KIND_VAULT})
	net.MustLand(vault)
	net.MustRefuse(net.Sign(owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
		Header: net.Header(), RepoId: net.Id("m vault").Bytes(), Subject: adminAdmitted.SidecarId.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER,
	}), sidecar.ErrConfigRule)
	net.Fold(true)
	net.MustLand(net.Sign(first, bridge.SignedType_SIGNED_OWNER_CONFIRM, net.OwnerConfirm(adminAdmitted)))
	if !net.Consented(adminAdmitted, memberM) {
		t.Fatal("M's OwnerConfirm did not consent the device")
	}
	net.Fold(true)
}

// §22.7's committers (owner decisions 113, 128): the signer of an admission or revocation commits what it requires
// though it is no config writer, while a config head from it is refused; a device that signed neither commits nothing
// for the target. Every reader answers alike, MayCommit being a function of the state.
func admissionRowCommitters(t testing.TB, net *AdmissionNet) {
	memberM, first := net.ConsentedMember("m")
	tablet, other := net.Device("m tablet", memberM), net.Device("m other", memberM)
	net.AdmitDevice(first, tablet, 0)
	net.AdmitDevice(first, other, 0)
	mayCommit := func(signer *AdmissionDevice, target *AdmissionDevice) sidecar.ConfigCommits {
		commits := net.State().MayCommit(signer.SidecarId, target.SidecarId)
		for _, reader := range net.standing() {
			if got := reader.log.State().MayCommit(signer.SidecarId, target.SidecarId); got != commits {
				t.Fatalf("%s answers %+v for %s's commit of %s, the reference %+v", reader.name, got, signer.Name, target.Name, commits)
			}
		}
		return commits
	}
	if commits := mayCommit(first, tablet); !commits.Add {
		t.Fatalf("the admission's signer may not Add the tablet: %+v", commits)
	}
	if commits := mayCommit(other, tablet); commits.Add || commits.FirstWrap {
		t.Fatalf("a device that signed no admission may commit the tablet: %+v", commits)
	}
	if err := sidecar.CheckConfigHeadWriter(net.State(), first.SidecarId); err == nil && !net.State().IsConfigWriter(first.SidecarId) {
		t.Fatal("a member's device outside the AdminSet may write the config head")
	}
	if net.State().IsConfigWriter(first.SidecarId) {
		t.Fatal("a member's device outside the AdminSet is a config writer")
	}
	net.MustLand(net.Sign(first, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.Revocation(tablet, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0)))
	if commits := mayCommit(first, tablet); !commits.Remove || !commits.Rotate {
		t.Fatalf("the revocation's signer may not Remove the tablet: %+v", commits)
	}
	net.Fold(true)
	if commits := mayCommit(first, tablet); !commits.Remove {
		t.Fatalf("after a base the revocation's signer may not Remove the tablet: %+v", commits)
	}
}

// §22.7's seats (owner decisions 144, 182): the 1,001st live member device is no leaf, reads the config by its
// ReaderWrap and gets no Add; signing an admission it writes the new device's first wrap, and signing a revocation it
// rotates and commits no Remove; once a leaf-entitled device is revoked, the first wrapped one by rank becomes
// leaf-entitled and nothing shrinks. 1,000 admissions, readers compared at each base and at the end.
func admissionRowSeats(t testing.TB, net *AdmissionNet) {
	owner := net.Owner()
	net.CompareEveryEntry(false)
	devices := []*AdmissionDevice{owner}
	for i := range 1000 {
		device := net.Device(fmt.Sprintf("owner device %d", i), owner.MemberId)
		net.AdmitDevice(owner, device, 0)
		devices = append(devices, device)
		if i == 499 {
			net.Fold(true)
		}
	}
	net.Fold(true)
	net.CompareEveryEntry(true)
	net.CheckAgreement()
	state := net.State()
	last := devices[1000]
	if rank, live := state.LeafRank(last.SidecarId); !live || rank != 1000 || state.LeafEntitled(last.SidecarId) {
		t.Fatalf("the 1,001st device: rank %d, live %t, entitled %t", rank, live, state.LeafEntitled(last.SidecarId))
	}
	if wrapped := state.WrappedMembers(); len(wrapped) != 1 || wrapped[0] != last.SidecarId {
		t.Fatalf("wrapped members %v", wrapped)
	}
	if commits := state.MayCommit(owner.SidecarId, last.SidecarId); commits.Add || !commits.FirstWrap {
		t.Fatalf("the 1,001st device's admission signer may commit %+v", commits)
	}
	next := net.Device("owner device past the leaves", owner.MemberId)
	net.AdmitDevice(last, next, 0)
	if commits := net.State().MayCommit(last.SidecarId, next.SidecarId); commits.Add || !commits.FirstWrap {
		t.Fatalf("a wrapped signer's admission commits %+v", commits)
	}
	// next, wrapped behind last, revokes a leaf: it rotates and commits no Remove, and last, first by rank among the
	// wrapped, becomes leaf-entitled at that position
	leaf := devices[1]
	net.MustLand(net.Sign(next, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.Revocation(leaf, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0)))
	state = net.State()
	if commits := state.MayCommit(next.SidecarId, leaf.SidecarId); commits.Remove || !commits.Rotate {
		t.Fatalf("a wrapped signer's revocation commits %+v", commits)
	}
	if !state.LeafEntitled(last.SidecarId) {
		t.Fatal("the first wrapped device did not become leaf-entitled when a leaf was revoked")
	}
	if wrapped := state.WrappedMembers(); len(wrapped) != 1 || wrapped[0] != next.SidecarId {
		t.Fatalf("wrapped members after the revocation %v", wrapped)
	}
}

// §22.7's agents cost no commit or leaf (owner decision 114): a Delegation-admitted agent is no leaf, so its admission
// takes a first wrap and no Add, and its revocation a rotation and no Remove.
func admissionRowAgents(t testing.TB, net *AdmissionNet) {
	owner := net.Owner()
	tagId := net.Id("tag ci")
	net.SetTagOwners(map[sidecar.Id]sidecar.Id{tagId: owner.MemberId})
	notAfter := net.clock.Now().Add(30 * 24 * time.Hour).UnixMilli()
	delegation := net.Delegate(owner, "ci", []sidecar.Id{tagId}, 10, notAfter)
	agent := net.Device("ci agent", sidecar.Id{})
	net.MustLand(net.SignByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.Admission(agent, []sidecar.Id{tagId}, false, notAfter, 0)))
	state := net.State()
	if _, live := state.LeafRank(agent.SidecarId); live || state.LeafEntitled(agent.SidecarId) {
		t.Fatal("an agent ranks among the leaves")
	}
	net.MustLand(net.Sign(owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.Revocation(agent, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED, 0)))
	if commits := net.State().MayCommit(owner.SidecarId, agent.SidecarId); commits.Remove || commits.Add || !commits.Rotate {
		t.Fatalf("an agent's revocation commits %+v", commits)
	}
	net.Fold(true)
}

// §22.7's read-only page Workers at k = 1 and k = 2: each statement a Worker signs that §7.9's read_only row refuses
// (config statements, admissions, cosigns) is refused by api and every reader, while its own SidecarRevoke lands.
func admissionRowReadOnlyWorkers(t testing.TB, net *AdmissionNet) {
	owner := net.Owner()
	for _, k := range []int{1, 2} {
		if k == 2 {
			admissionTeam(t, net)
		}
		memberM, first := net.ConsentedMember(fmt.Sprintf("m at %d", k))
		worker := net.Device(fmt.Sprintf("m page worker at %d", k), memberM)
		net.AdmitDevice(first, worker, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY))
		if !net.State().ReadOnly(worker.SidecarId) {
			t.Fatal("the Worker is not read_only")
		}
		net.MustRefuse(net.Sign(worker, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.MemberAdmit(net.Id(fmt.Sprintf("by a worker at %d", k)), bridge.MemberRole_MEMBER_ROLE_MEMBER)), sidecar.ErrConfigReadOnly)
		net.MustRefuse(net.Sign(worker, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.Admission(net.Device(fmt.Sprintf("m by worker at %d", k), memberM), nil, false, 0, 0)), sidecar.ErrConfigReadOnly)
		net.MustRefuse(net.Sign(worker, bridge.SignedType_SIGNED_OWNER_CONFIRM, net.OwnerConfirm(first)), sidecar.ErrConfigReadOnly)
		proposalId, _ := net.Propose(owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.MemberAdmit(net.Id(fmt.Sprintf("proposed at %d", k)), bridge.MemberRole_MEMBER_ROLE_MEMBER))
		net.MustRefuse(net.Sign(worker, bridge.SignedType_SIGNED_AUTHORITY_COSIGN, net.Cosign(proposalId)), sidecar.ErrConfigReadOnly)
		net.MustLand(net.Sign(worker, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.Revocation(worker, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED, 0)))
		if net.Admitted(worker) {
			t.Fatal("the Worker's own revocation left it standing")
		}
		net.Fold(true)
	}
}

// §22.7's compromise cascade: P counts each record from its carrying entry from since_n. A admits B and B admits C
// after since_n: both parked; a signer outside P lifts B's park by AdmissionConfirm and C stays parked; the stolen
// device's OwnerConfirm of an admin-admitted G, G's only consent, parks G and of an already consented H parks
// nothing; and a personal network revokes its stolen first device from the phone it admitted, refused from since_n 1
// where P would hold the phone and accepted from the loss position.
func admissionRowCascade(t testing.TB, net *AdmissionNet) {
	owner := net.Owner()
	memberM, laptop := net.ConsentedMember("m")
	phone, tablet, watch := net.Device("m phone", memberM), net.Device("m tablet", memberM), net.Device("m watch", memberM)
	net.AdmitDevice(laptop, phone, 0)
	sinceN := net.Tip().GetVersion() + 1
	net.AdmitDevice(phone, tablet, 0)
	net.AdmitDevice(tablet, watch, 0)
	deviceG, deviceH := net.Device("m g", memberM), net.Device("m h", memberM)
	net.AdmitDevice(owner, deviceG, 0)
	net.AdmitDevice(laptop, deviceH, 0)
	net.MustLand(net.Sign(phone, bridge.SignedType_SIGNED_OWNER_CONFIRM, net.OwnerConfirm(deviceG)))
	net.MustLand(net.Sign(phone, bridge.SignedType_SIGNED_OWNER_CONFIRM, net.OwnerConfirm(deviceH)))
	net.Fold(true)
	net.MustLand(net.Sign(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.Revocation(phone, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_COMPROMISE, sinceN)))
	state := net.State()
	for _, device := range []*AdmissionDevice{tablet, watch, deviceG} {
		if !state.Parked(device.SidecarId) {
			t.Fatalf("%s is not parked", device.Name)
		}
	}
	for _, device := range []*AdmissionDevice{laptop, deviceH} {
		if state.Parked(device.SidecarId) {
			t.Fatalf("%s is parked", device.Name)
		}
	}
	net.MustLand(net.Sign(owner, bridge.SignedType_SIGNED_ADMISSION_CONFIRM, net.AdmissionConfirm(tablet)))
	if state := net.State(); state.Parked(tablet.SidecarId) || !state.Parked(watch.SidecarId) {
		t.Fatalf("after the lift the tablet parked %t, the watch %t", state.Parked(tablet.SidecarId), state.Parked(watch.SidecarId))
	}
	net.Fold(true)

	// the personal network's stolen first device
	ownerPhone := net.Device("owner phone", owner.MemberId)
	net.AdmitDevice(owner, ownerPhone, 0)
	lossN := net.Tip().GetVersion() + 1
	net.AdmitMember(owner, "after the loss", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	net.MustRefuse(net.Sign(ownerPhone, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.Revocation(owner, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_COMPROMISE, 1)), sidecar.ErrConfigAuthority)
	net.MustLand(net.Sign(ownerPhone, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.Revocation(owner, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_COMPROMISE, lossN)))
	if state := net.State(); state.Parked(ownerPhone.SidecarId) || !state.IsConfigWriter(ownerPhone.SidecarId) || state.IsConfigWriter(owner.SidecarId) {
		t.Fatal("the phone is parked or no config writer, or the stolen device still writes the config")
	}
	net.UseWriter(ownerPhone)
	net.Fold(true)
}

// §22.7's auth keys (FS-18, FS-102): an admission by a Delegation's key is refused by api and every reader, a new
// device included, when it names tags other than the Delegation's, a non-ephemeral not_after before the Delegation's,
// or lands after the Delegation's end, and taken when it carries exactly its tags; max_admits holds across a fold.
func admissionRowAuthKeys(t testing.TB, net *AdmissionNet) {
	owner := net.Owner()
	ci, deploy := net.Id("tag ci"), net.Id("tag deploy")
	net.SetTagOwners(map[sidecar.Id]sidecar.Id{ci: owner.MemberId, deploy: owner.MemberId})
	notAfter := net.clock.Now().Add(30 * 24 * time.Hour).UnixMilli()
	delegation := net.Delegate(owner, "bundle", []sidecar.Id{ci}, 2, notAfter)
	admit := func(label string, tagIds []sidecar.Id, ephemeral bool, agentNotAfter int64) []byte {
		return net.SignByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.Admission(net.Device(label, sidecar.Id{}), tagIds, ephemeral, agentNotAfter, 0))
	}
	net.MustRefuse(admit("other tags", []sidecar.Id{deploy}, false, notAfter), sidecar.ErrConfigRefused)
	net.MustRefuse(admit("more tags", []sidecar.Id{ci, deploy}, false, notAfter), sidecar.ErrConfigRefused)
	net.MustRefuse(admit("an early not_after", []sidecar.Id{ci}, false, notAfter-1), sidecar.ErrConfigRefused)
	net.MustLand(admit("agent a", []sidecar.Id{ci}, false, notAfter))
	net.Fold(true)
	net.MustLand(admit("agent b", []sidecar.Id{ci}, true, net.clock.Now().Add(time.Hour).UnixMilli()))
	net.MustRefuse(admit("past max_admits", []sidecar.Id{ci}, false, notAfter), sidecar.ErrConfigRefused)

	second := net.Delegate(owner, "second bundle", []sidecar.Id{ci}, 10, notAfter)
	net.MustLand(net.Sign(owner, bridge.SignedType_SIGNED_DELEGATION_REVOKE, net.DelegationRevoke(second.Id, 0)))
	if _, ended := net.State().DelegationEnded(second.Id); !ended {
		t.Fatal("the revoked Delegation has not ended")
	}
	net.MustRefuse(net.SignByDelegation(second, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.Admission(net.Device("after the end", sidecar.Id{}), []sidecar.Id{ci}, false, notAfter, 0)), sidecar.ErrConfigRefused)
	net.Fold(true)
}

// DESIGN-DETAILS 5.6's TestRowsOnlyAndFullReadersAgreeOverGeneratedLogs on real code: from a fixed seed, a log of
// members and their devices admitted by the owner and by members' own consented devices, admin-admitted devices and
// their OwnerConfirms, lost and compromise revocations, a team's proposals and cosigns at k = 2, self_admit toggled by
// a head, statements api refuses, statements a malicious api lands that every reader refuses at their positions, and
// bases that fold or keep the fold, so tails carry 0, 1 and 2; every reader is compared with the reference after
// every entry, a new device and a gate started at each base among them.
func admissionRowGeneratedLogs(t testing.TB, net *AdmissionNet) {
	owner := net.Owner()
	random := rand.New(rand.NewPCG(1, 0x5ade))
	type member struct {
		id      sidecar.Id
		first   *AdmissionDevice
		devices []*AdmissionDevice
	}
	members := []*member{}
	selfAdmit := true
	var adminB *AdmissionDevice
	pick := func() *member {
		if len(members) == 0 {
			return nil
		}
		return members[random.IntN(len(members))]
	}
	for step := range 48 {
		switch choice := random.IntN(11); {
		case choice == 0 || len(members) == 0:
			id, first := net.ConsentedMember(fmt.Sprintf("generated %d", step))
			members = append(members, &member{id: id, first: first, devices: []*AdmissionDevice{first}})
		case choice == 1:
			m := pick()
			device := net.Device(fmt.Sprintf("generated device %d", step), m.id)
			if selfAdmit && net.Admitted(m.first) {
				net.AdmitDevice(m.first, device, 0)
			} else {
				net.AdmitDevice(owner, device, 0)
			}
			m.devices = append(m.devices, device)
		case choice == 2:
			m := pick()
			device := net.Device(fmt.Sprintf("generated admin admitted %d", step), m.id)
			net.AdmitDevice(owner, device, 0)
			m.devices = append(m.devices, device)
			if net.Admitted(m.first) {
				net.MustLand(net.Sign(m.first, bridge.SignedType_SIGNED_OWNER_CONFIRM, net.OwnerConfirm(device)))
			}
		case choice == 3:
			m := pick()
			if len(m.devices) < 2 {
				continue
			}
			target := m.devices[len(m.devices)-1]
			if net.Admitted(target) {
				net.MustLand(net.Sign(owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.Revocation(target, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0)))
			}
		case choice == 4:
			// a stranger's statement api refuses, and the same landed by a malicious api, which every reader refuses
			stranger := net.Device(fmt.Sprintf("stranger %d", step), net.Id(fmt.Sprintf("stranger member %d", step)))
			signed := net.Sign(stranger, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.MemberAdmit(net.Id(fmt.Sprintf("by a stranger %d", step)), bridge.MemberRole_MEMBER_ROLE_MEMBER))
			net.MustRefuse(signed, sidecar.ErrConfigRefused)
			if net.ForgedAppends() {
				pin := net.SequenceAnyway(bridge.AuthEntryKindStatement, signed)
				if net.VerdictAt(pin.GetVersion()).Accepted() {
					t.Fatal("a stranger's statement took effect")
				}
			}
		case choice == 5:
			net.FoldIfAny(true)
		case choice == 6:
			selfAdmit = !selfAdmit
			mode := protocol.SelfAdmitMode_SELF_ADMIT_MODE_ON
			if !selfAdmit {
				mode = protocol.SelfAdmitMode_SELF_ADMIT_MODE_OFF
			}
			net.SetServiceSettings(&protocol.ServiceSettings{SelfAdmit: mode})
		case choice == 7:
			net.Wait(time.Duration(1+random.IntN(30)) * time.Hour)
		case choice == 8:
			if adminB == nil {
				adminB, _ = admissionTeam(t, net)
			}
			proposalId, _ := net.Propose(owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.MemberAdmit(net.Id(fmt.Sprintf("proposed %d", step)), bridge.MemberRole_MEMBER_ROLE_MEMBER))
			if random.IntN(2) == 0 {
				net.FoldIfAny(true)
			}
			if completed := net.MustLand(net.Sign(adminB, bridge.SignedType_SIGNED_AUTHORITY_COSIGN, net.Cosign(proposalId))); !completed.Completed() {
				t.Fatal("the k-th cosign did not complete the proposal")
			}
		case choice == 9:
			// a compromise revocation from the position before a device's own admissions: what it admitted parks
			m := pick()
			if len(m.devices) < 2 || !net.Admitted(m.devices[1]) || !net.Admitted(m.first) {
				continue
			}
			admitted := net.Row(m.devices[1]).GetAdmittedAt()
			net.MustLand(net.Sign(m.first, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.Revocation(m.devices[1], bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_COMPROMISE, admitted+1)))
		default:
			net.AdmitMember(owner, fmt.Sprintf("generated plain %d", step), bridge.MemberRole_MEMBER_ROLE_MEMBER)
		}
	}
	net.FoldIfAny(true)
	if net.ReaderCount() < 3 {
		t.Fatalf("only %d readers ran", net.ReaderCount())
	}
}

// Runs before once before the writer's next base reaches api, as another appender's entry landing first, so the base
// meets api's 409 and the writer re-signs at the new tip (§7.9's base row). before appends through the api directly,
// since the writer's publish holds the world: Post and Sync are not called from it.
func (self *AdmissionNet) BeforeNextPublish(before func()) {
	self.beforePublish = before
}

// Appends a signed statement at api without syncing: what BeforeNextPublish's function does.
func (self *AdmissionNet) AppendOnly(signedBytes []byte) (*bridge.AuthPin, error) {
	pin, err := self.api.AppendStatement(self.ctx, self.networkId, signedBytes)
	self.clock.Advance(time.Second)
	return pin, err
}

// The two bits each entry in (foldedThrough, tip] takes at the reference (DESIGN-DETAILS 5.2.2): 0 refused or a base,
// 1 took effect, 2 took effect and completed a proposal; encoded as a base's tail_verdicts.
func (self *AdmissionNet) TailVerdicts(foldedThrough uint64) []byte {
	self.t.Helper()
	tip := self.applied
	if tip <= foldedThrough {
		return nil
	}
	data := make([]byte, (2*(tip-foldedThrough)+7)/8)
	for k := foldedThrough + 1; k <= tip; k += 1 {
		verdict := self.VerdictAt(k)
		bits := byte(1)
		switch {
		case verdict.Kind == bridge.AuthEntryKindBase || !verdict.Accepted():
			bits = 0
		case verdict.Completed():
			bits = 2
		}
		j := k - foldedThrough - 1
		data[j/4] |= bits << (2 * (j % 4))
	}
	return data
}

// A base at the tip's next position by signer that keeps the newest base's fold and config head, so its rows are that
// base's, with the tail_verdicts the reference holds: what an honest writer publishes for a policy-only change at an
// unchanged fold. edit, when not nil, changes the header before it is signed, as a lying or stale writer does. The
// Signed header's bytes and the rows.
func (self *AdmissionNet) BaseKeepingTheFold(signer *AdmissionDevice, edit func(header *bridge.ProjectionHeader)) ([]byte, []byte) {
	self.t.Helper()
	previous := self.State().Base()
	if previous == nil {
		self.t.Fatal("no base to keep the fold of")
	}
	rows, found := self.rows[[sha256.Size]byte(previous.GetRowsSha256())]
	if !found {
		self.t.Fatal("the newest base's rows were not served")
	}
	tip := self.Tip()
	header := &bridge.ProjectionHeader{
		NetworkId:        self.networkId.Bytes(),
		Version:          tip.GetVersion() + 1,
		PrevChain:        bytes.Clone(tip.GetChain()),
		FoldedThrough:    previous.GetFoldedThrough(),
		ConfigVersion:    previous.GetConfigVersion(),
		ConfigHeadSha256: bytes.Clone(previous.GetConfigHeadSha256()),
		RowsSha256:       bytes.Clone(previous.GetRowsSha256()),
		RowsByteCount:    previous.GetRowsByteCount(),
		Threshold:        previous.GetThreshold(),
		TailVerdicts:     self.TailVerdicts(previous.GetFoldedThrough()),
	}
	if edit != nil {
		edit(header)
	}
	return self.Sign(signer, bridge.SignedType_SIGNED_PROJECTION_HEADER, header), bytes.Clone(rows)
}

// Appends a base at api, no genesis and no config pushes, and syncs; the pin, or api's refusal.
func (self *AdmissionNet) AppendBase(signedHeader []byte, rows []byte) (*bridge.AuthPin, error) {
	self.t.Helper()
	pin, err := self.api.AppendBase(self.ctx, self.networkId, signedHeader, rows, nil, nil)
	self.clock.Advance(time.Second)
	self.Sync()
	return pin, err
}

// The writer's device: an Owner's, which signs bases and heads.
func (self *AdmissionNet) WriterDevice() *AdmissionDevice {
	return self.writerDevice
}

// Registers key as a presence key of device's member, signed by device and, where device holds a live key already,
// countersigned by countersigner, since a presence key's KeyRegister is covered (§7.9's presence row).
func (self *AdmissionNet) RegisterPresenceKey(device *AdmissionDevice, key *FixturePresenceKey, countersigner *FixturePresenceKey) sidecar.ConfigVerdict {
	self.t.Helper()
	body, err := key.RegisterBody(&protocol.KeyRegister{
		Header:   self.Header(),
		MemberId: device.MemberId.Bytes(),
		NotAfter: self.clock.Now().Add(30 * 24 * time.Hour).UnixMilli(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	purpose, _ := sidecar.ConfigStatementPurpose(bridge.SignedType_SIGNED_KEY_REGISTER)
	signed := &bridge.Signed{
		Body:      body,
		SignerId:  device.SidecarId.Bytes(),
		Signature: ed25519.Sign(device.Key, bridge.SignedBytes(purpose, bridge.SignedType_SIGNED_KEY_REGISTER, body)),
		Type:      uint32(bridge.SignedType_SIGNED_KEY_REGISTER),
	}
	if countersigner != nil {
		self.Countersign(countersigner, device, signed)
	}
	return self.MustLand(self.marshal(signed))
}

// Puts key's countersignature on signed statements as one act of device's (§7.9's act): their identity signatures stay,
// since the countersignature covers each statement's purpose, type and body alone.
func (self *AdmissionNet) Countersign(key *FixturePresenceKey, device *AdmissionDevice, signed ...*bridge.Signed) {
	self.t.Helper()
	statements := make([]*FixturePresenceStatement, len(signed))
	for i, statement := range signed {
		purpose, _ := sidecar.ConfigStatementPurpose(bridge.SignedType(statement.GetType()))
		statements[i] = &FixturePresenceStatement{Purpose: purpose, Signed: statement}
	}
	if err := key.Countersign(device.SidecarId.Bytes(), statements); err != nil {
		self.t.Fatal(err)
	}
}

// A Signed's bytes.
func (self *AdmissionNet) Marshal(signed *bridge.Signed) []byte {
	return self.marshal(signed)
}
