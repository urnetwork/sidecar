// A small network's authorization log as tests drive it: a genesis, base 1 from its owner's device, and a fake
// sequencer that signs, chains and applies each entry, keeping every state it reached so a later base can name the
// rows of any fold point. Entries carry their own times, so nothing here reads a clock; the log reads none either.
// Then the state's own tests: what S(0) and base 1 hold, the views it implements, and snapshots that never change.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What every state implements, checked at compile time.
var (
	_ AclAuthView = (*ConfigState)(nil)
	_ GkmAuthView = (*ConfigState)(nil)
)

// The first entry's time, ms since the epoch.
const testConfigStartMs = int64(1_800_000_000_000)

// The defaults with a logger that keeps refusals and forks out of the test's output.
func testConfigLogSettings() *ConfigLogSettings {
	settings := DefaultConfigLogSettings()
	settings.Log = NewNoopLogger()
	return settings
}

// A synthetic id from a label, the same on every run.
func testConfigId(label string) Id {
	digest := sha256.Sum256([]byte("config test id " + label))
	return Id(digest[:len(Id{})])
}

// One device of the test network: its sidecar, its member (zero for a tagged one) and its identity key.
type testConfigDevice struct {
	sidecarId Id
	memberId  Id
	key       ed25519.PrivateKey
}

// A device's key from its label.
func testConfigDeviceKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("config test key " + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

// The identity key.
func (self testConfigDevice) publicKey() []byte {
	return self.key.Public().(ed25519.PublicKey)
}

// A rows source over what the test published, whose head check records what it was given and answers each head's
// settings.
type testConfigRowsSource struct {
	rows      map[[sha256.Size]byte][]byte
	settings  map[[sha256.Size]byte]*protocol.ServiceSettings
	checks    []*ConfigHeadCheck
	headError error
}

func newTestConfigRowsSource() *testConfigRowsSource {
	return &testConfigRowsSource{
		rows:     map[[sha256.Size]byte][]byte{},
		settings: map[[sha256.Size]byte]*protocol.ServiceSettings{},
	}
}

// The published rows.
func (self *testConfigRowsSource) Rows(networkId Id, rowsSha256 []byte) ([]byte, error) {
	rows, found := self.rows[[sha256.Size]byte(rowsSha256)]
	if !found {
		return nil, errors.New("no such rows")
	}
	return bytes.Clone(rows), nil
}

// Records the check and answers the head's settings, or headError.
func (self *testConfigRowsSource) CheckHead(check *ConfigHeadCheck) (*ConfigHeadFacts, error) {
	self.checks = append(self.checks, check)
	if self.headError != nil {
		return nil, self.headError
	}
	return &ConfigHeadFacts{Settings: self.settings[[sha256.Size]byte(check.Header.GetConfigHeadSha256())]}, nil
}

// A test network: its genesis, the fake sequencer's tip, the reader under test and every state it reached.
type testConfigNet struct {
	t testing.TB

	networkId     Id
	ownerMemberId Id
	owner         testConfigDevice
	signedGenesis []byte
	source        *testConfigRowsSource

	n       uint64
	chain   [sha256.Size]byte
	timeMs  int64
	nonce   uint64
	entries [][]byte

	log      *ConfigLog
	statesAt map[uint64]*ConfigState
}

// A network at base 1: its owner a member with role OWNER and its first device the genesis device, base 1 signed by
// it with the default settings.
func newTestConfigNet(t testing.TB) *testConfigNet {
	self := &testConfigNet{
		t:             t,
		networkId:     testConfigId("network"),
		ownerMemberId: testConfigId("owner member"),
		source:        newTestConfigRowsSource(),
		timeMs:        testConfigStartMs,
		statesAt:      map[uint64]*ConfigState{},
	}
	self.owner = testConfigDevice{sidecarId: testConfigId("owner device"), memberId: self.ownerMemberId, key: testConfigDeviceKey("owner device")}
	genesis := &bridge.Genesis{
		NetworkId:              self.networkId.Bytes(),
		ConfigRepoId:           testConfigId("config repo").Bytes(),
		OwnerMemberId:          self.ownerMemberId.Bytes(),
		OwnerSidecarId:         self.owner.sidecarId.Bytes(),
		OwnerIdentityPublicKey: self.owner.publicKey(),
		TimeMs:                 testConfigStartMs,
	}
	self.signedGenesis = self.sign(self.owner, bridge.SignedType_SIGNED_GENESIS, genesis)
	self.chain = bridge.GenesisChain(self.signedGenesis)
	log, err := NewConfigLog(testConfigLogSettings(), self.signedGenesis)
	if err != nil {
		t.Fatal(err)
	}
	self.log = log
	self.statesAt[0] = log.State()

	rows := &bridge.ProjectionRows{
		Members: []*bridge.MemberRow{{MemberId: self.ownerMemberId.Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_OWNER}},
		Sidecars: []*bridge.SidecarRow{{
			SidecarId:         self.owner.sidecarId.Bytes(),
			AdmissionSigners:  [][]byte{self.owner.sidecarId.Bytes()},
			IdentityPublicKey: self.owner.publicKey(),
			IdentityAlg:       configIdentityAlgEd25519,
			MemberId:          self.ownerMemberId.Bytes(),
		}},
	}
	verdict := self.pushBase(self.owner, rows, 0, 1, 0)
	if !verdict.Accepted() {
		t.Fatalf("base 1: %v", verdict.Refusal)
	}
	return self
}

// Deterministic bytes, as a signer writes them.
func testConfigMarshal(t testing.TB, message proto.Message) []byte {
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// body signed by signer's identity key under its type's purpose, as a Signed's bytes.
func (self *testConfigNet) sign(signer testConfigDevice, signedType bridge.SignedType, body proto.Message) []byte {
	bodyBytes := testConfigMarshal(self.t, body)
	purpose, _ := ConfigStatementPurpose(signedType)
	signed := &bridge.Signed{
		Body:      bodyBytes,
		SignerId:  signer.sidecarId.Bytes(),
		Signature: ed25519.Sign(signer.key, bridge.SignedBytes(purpose, signedType, bodyBytes)),
		Type:      uint32(signedType),
	}
	return testConfigMarshal(self.t, signed)
}

// A header at the sequencer's tip, a fresh nonce, expiring in an hour.
func (self *testConfigNet) header() *bridge.StatementHeader {
	self.nonce += 1
	nonce := make([]byte, configNonceByteCount)
	binary.BigEndian.PutUint64(nonce[8:], self.nonce)
	return &bridge.StatementHeader{
		NetworkId:  self.networkId.Bytes(),
		At:         &bridge.AuthPin{Version: self.n, Chain: bytes.Clone(self.chain[:])},
		Nonce:      nonce,
		NotAfterMs: self.timeMs + 60*60*1000,
	}
}

// The entry at the tip's next position, without moving the tip.
func (self *testConfigNet) makeEntry(kind uint32, body []byte) []byte {
	return testConfigMarshal(self.t, &bridge.AuthEntry{
		NetworkId: self.networkId.Bytes(),
		N:         self.n + 1,
		PrevChain: bytes.Clone(self.chain[:]),
		Kind:      kind,
		TimeMs:    self.timeMs + 1000,
		Body:      body,
	})
}

// Sequences an entry made at the tip: the tip moves to it and the reader under test applies it.
func (self *testConfigNet) push(entryBytes []byte) ConfigVerdict {
	self.t.Helper()
	entry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(entryBytes, entry); err != nil {
		self.t.Fatal(err)
	}
	chain, err := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
	if err != nil {
		self.t.Fatal(err)
	}
	self.n, self.chain, self.timeMs = entry.GetN(), chain, entry.GetTimeMs()
	self.entries = append(self.entries, entryBytes)
	verdict, err := self.log.Apply(entryBytes, self.source)
	if err != nil {
		self.t.Fatalf("entry %d: %v", entry.GetN(), err)
	}
	self.statesAt[entry.GetN()] = self.log.State()
	return verdict
}

// Signs, sequences and applies one statement.
func (self *testConfigNet) post(signer testConfigDevice, signedType bridge.SignedType, body proto.Message) ConfigVerdict {
	self.t.Helper()
	return self.push(self.makeEntry(bridge.AuthEntryKindStatement, self.sign(signer, signedType, body)))
}

// post, failing the test unless the statement takes effect.
func (self *testConfigNet) mustPost(signer testConfigDevice, signedType bridge.SignedType, body proto.Message) ConfigVerdict {
	self.t.Helper()
	verdict := self.post(signer, signedType, body)
	if !verdict.Accepted() {
		self.t.Fatalf("%s at %d: %v", signedType, verdict.Pin.GetVersion(), verdict.Refusal)
	}
	return verdict
}

// post, failing the test unless the statement is refused with want.
func (self *testConfigNet) mustRefuse(signer testConfigDevice, signedType bridge.SignedType, body proto.Message, want error) ConfigVerdict {
	self.t.Helper()
	verdict := self.post(signer, signedType, body)
	if verdict.Accepted() || !errors.Is(verdict.Refusal, want) {
		self.t.Fatalf("%s at %d: got %v, want %v", signedType, verdict.Pin.GetVersion(), verdict.Refusal, want)
	}
	return verdict
}

// Sequences a tick.
func (self *testConfigNet) tick(tick *bridge.ApiTick) ConfigVerdict {
	self.t.Helper()
	return self.push(self.makeEntry(bridge.AuthEntryKindTick, testConfigMarshal(self.t, tick)))
}

// The head hash a test base names for a config version.
func testConfigHeadSha256(configVersion uint64) []byte {
	digest := sha256.Sum256(binary.BigEndian.AppendUint64([]byte("config test head"), configVersion))
	return digest[:]
}

// The entry of a base over rows at the tip's next position, without moving the tip, its rows published.
func (self *testConfigNet) makeBase(signer testConfigDevice, rows *bridge.ProjectionRows, foldedThrough uint64, configVersion uint64, threshold uint32) []byte {
	rowsBytes := testConfigMarshal(self.t, rows)
	rowsSha256 := sha256.Sum256(rowsBytes)
	self.source.rows[rowsSha256] = rowsBytes
	header := &bridge.ProjectionHeader{
		NetworkId:        self.networkId.Bytes(),
		Version:          self.n + 1,
		PrevChain:        bytes.Clone(self.chain[:]),
		FoldedThrough:    foldedThrough,
		ConfigVersion:    configVersion,
		ConfigHeadSha256: testConfigHeadSha256(configVersion),
		RowsSha256:       rowsSha256[:],
		RowsByteCount:    uint32(len(rowsBytes)),
		Threshold:        threshold,
	}
	return self.makeEntry(bridge.AuthEntryKindBase, self.sign(signer, bridge.SignedType_SIGNED_PROJECTION_HEADER, header))
}

// Sequences and applies a base over rows.
func (self *testConfigNet) pushBase(signer testConfigDevice, rows *bridge.ProjectionRows, foldedThrough uint64, configVersion uint64, threshold uint32) ConfigVerdict {
	self.t.Helper()
	return self.push(self.makeBase(signer, rows, foldedThrough, configVersion, threshold))
}

// A base folding through foldedThrough, its rows the reader's state there, signed by signer.
func (self *testConfigNet) fold(signer testConfigDevice, foldedThrough uint64, configVersion uint64) ConfigVerdict {
	self.t.Helper()
	folded := self.statesAt[foldedThrough]
	if folded == nil {
		self.t.Fatalf("no state at %d", foldedThrough)
	}
	return self.pushBase(signer, folded.Rows(), foldedThrough, configVersion, folded.threshold)
}

// A new device of a member, not admitted yet.
func (self *testConfigNet) device(label string, memberId Id) testConfigDevice {
	return testConfigDevice{sidecarId: testConfigId(label), memberId: memberId, key: testConfigDeviceKey(label)}
}

// A SidecarAdmit of device under the tip's header: its member, or tags when tagIds is not empty.
func (self *testConfigNet) admission(device testConfigDevice, tagIds []Id, ephemeral bool, notAfter int64, capabilities uint32) *protocol.SidecarAdmit {
	admit := &protocol.SidecarAdmit{
		Header:            self.header(),
		NetworkId:         self.networkId.Bytes(),
		SidecarId:         device.sidecarId.Bytes(),
		IdentityPublicKey: device.publicKey(),
		IdentityAlg:       configIdentityAlgEd25519,
		Ephemeral:         ephemeral,
		NotAfter:          notAfter,
		Capabilities:      capabilities,
	}
	if len(tagIds) == 0 {
		admit.MemberId = device.memberId.Bytes()
	}
	for _, tagId := range tagIds {
		admit.TagIds = append(admit.TagIds, tagId.Bytes())
	}
	return admit
}

// Admits a member device, signed by signer, failing the test unless it takes effect.
func (self *testConfigNet) admitDevice(signer testConfigDevice, device testConfigDevice, capabilities uint32) {
	self.t.Helper()
	self.mustPost(signer, bridge.SignedType_SIGNED_SIDECAR_ADMIT, self.admission(device, nil, false, 0, capabilities))
}

// Admits a member with a role, signed by signer.
func (self *testConfigNet) admitMember(signer testConfigDevice, memberId Id, role bridge.MemberRole) {
	self.t.Helper()
	self.mustPost(signer, bridge.SignedType_SIGNED_MEMBER_ADMIT, &protocol.MemberAdmit{
		Header: self.header(), MemberId: memberId.Bytes(), Role: role,
	})
}

// A second reader of the same log, which has applied every entry so far.
func (self *testConfigNet) newReader() *ConfigLog {
	self.t.Helper()
	reader, err := NewConfigLog(testConfigLogSettings(), self.signedGenesis)
	if err != nil {
		self.t.Fatal(err)
	}
	for _, entryBytes := range self.entries {
		if _, err := reader.Apply(entryBytes, self.source); err != nil {
			self.t.Fatal(err)
		}
	}
	return reader
}

// A state's rows as bytes, which two readers that agree give alike.
func testConfigRowsBytes(t testing.TB, state *ConfigState) []byte {
	return testConfigMarshal(t, state.Rows())
}

// Whether two readers stand on the same state: pin, rows, threshold, open proposals and retention point.
func testConfigStatesEqual(t testing.TB, a *ConfigState, b *ConfigState) {
	t.Helper()
	if !proto.Equal(a.Pin(), b.Pin()) {
		t.Errorf("pins %v and %v", a.Pin(), b.Pin())
	}
	if !bytes.Equal(testConfigRowsBytes(t, a), testConfigRowsBytes(t, b)) {
		t.Errorf("rows differ at %d", a.n)
	}
	if a.threshold != b.threshold || a.RetentionPoint() != b.RetentionPoint() {
		t.Errorf("threshold %d and %d, retention %d and %d", a.threshold, b.threshold, a.RetentionPoint(), b.RetentionPoint())
	}
	aProposals, bProposals := a.OpenProposalIds(), b.OpenProposalIds()
	if len(aProposals) != len(bProposals) {
		t.Errorf("%d and %d open proposals", len(aProposals), len(bProposals))
	}
}

// Before base 1 the genesis owner's device is the one config writer (§7.9's bootstrap), and S(0)'s pin is (0, A_0).
func TestConfigStateAtGenesisHasItsOwnerAsTheOneWriter(t *testing.T) {
	net := newTestConfigNet(t)
	genesisState := net.statesAt[0]
	if !genesisState.IsConfigWriter(net.owner.sidecarId) || genesisState.IsConfigWriter(testConfigId("stranger")) {
		t.Error("S(0)'s writer is the genesis device alone")
	}
	wantChain := bridge.GenesisChain(net.signedGenesis)
	if pin := genesisState.Pin(); pin.GetVersion() != 0 || !bytes.Equal(pin.GetChain(), wantChain[:]) {
		t.Errorf("S(0)'s pin is %v", pin)
	}
	if genesisState.Base() != nil || genesisState.RetentionPoint() != 0 {
		t.Error("S(0) stands on no base")
	}
}

// Base 1's rows are S(1): its owner an Owner, its device a config writer, k = 1, and its pin A_1 by §7.9's formula.
func TestConfigStateAtBaseOneHoldsItsRows(t *testing.T) {
	net := newTestConfigNet(t)
	state := net.log.State()
	entry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(net.entries[0], entry); err != nil {
		t.Fatal(err)
	}
	wantChain, err := bridge.AuthChainDigest(1, entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
	if err != nil {
		t.Fatal(err)
	}
	if pin := net.log.Pin(); pin.GetVersion() != 1 || !bytes.Equal(pin.GetChain(), wantChain[:]) {
		t.Errorf("pin %v", pin)
	}
	if state.Member(net.ownerMemberId).GetRole() != bridge.MemberRole_MEMBER_ROLE_OWNER {
		t.Error("the owner is no Owner")
	}
	if !state.IsConfigWriter(net.owner.sidecarId) {
		t.Error("the owner's device writes no config")
	}
	if k, n := state.Threshold(); k != 1 || n != 1 {
		t.Errorf("k %d of n %d", k, n)
	}
	if !bytes.Equal(state.IdentityKey(net.owner.sidecarId), net.owner.publicKey()) {
		t.Error("the owner device's identity key")
	}
	if settings, known := state.Settings(); !known || settings != nil {
		t.Errorf("settings %v, known %t", settings, known)
	}
	if state.RetentionPoint() != 1 {
		t.Errorf("retention point %d", state.RetentionPoint())
	}
	if _, err := state.Acl(); err != nil {
		t.Error(err)
	}
}

// A state a reader holds never changes as the log goes on: each statement copies what it writes.
func TestConfigStateSnapshotsNeverChange(t *testing.T) {
	net := newTestConfigNet(t)
	member := testConfigId("member m")
	net.admitMember(net.owner, member, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	held := net.log.State()
	heldRows := testConfigRowsBytes(t, held)

	laptop := net.device("m laptop", member)
	net.admitDevice(net.owner, laptop, 0)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, &bridge.SidecarRevoke{
		Header: net.header(), SidecarId: laptop.sidecarId.Bytes(), Reason: bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST,
	})
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_REVOKE, &bridge.MemberRevoke{Header: net.header(), MemberId: member.Bytes()})

	if !bytes.Equal(testConfigRowsBytes(t, held), heldRows) {
		t.Error("a held state changed")
	}
	if held.SidecarRow(laptop.sidecarId) != nil || held.Member(member) == nil {
		t.Error("a held state sees later entries")
	}
	if net.log.State().Member(member) != nil || net.log.State().SidecarRow(laptop.sidecarId).GetRevokedAt() == 0 {
		t.Error("the tip missed the revocations")
	}
}

// GkmAuthView's chain checks: a state is at its own pin, a pin above waits, one off the chain is a fork, and one
// below on the chain is the state the log published there (StateAt, config_state_at.go).
func TestConfigStateAnswersPinsAsAGkmView(t *testing.T) {
	net := newTestConfigNet(t)
	net.tick(&bridge.ApiTick{})
	net.tick(&bridge.ApiTick{})
	state := net.log.State()
	if view, err := state.At(state.Pin()); err != nil || view != GkmAuthView(state) {
		t.Errorf("own pin: %v", err)
	}
	if _, err := state.At(&bridge.AuthPin{Version: state.n + 1, Chain: make([]byte, sha256.Size)}); !errors.Is(err, ErrGkmAuthAhead) {
		t.Errorf("ahead: %v", err)
	}
	if _, err := state.At(&bridge.AuthPin{Version: 2, Chain: make([]byte, sha256.Size)}); !errors.Is(err, ErrGkmAuthOffChain) {
		t.Errorf("off the chain: %v", err)
	}
	older := net.statesAt[2].Pin()
	if !state.OnChain(older) {
		t.Error("an older pin is on the chain")
	}
	if view, err := state.At(older); err != nil || !proto.Equal(view.Pin(), older) {
		t.Errorf("an older pin: %v", err)
	}
	genesisChain := bridge.GenesisChain(net.signedGenesis)
	if !state.OnChain(&bridge.AuthPin{Version: 0, Chain: genesisChain[:]}) {
		t.Error("A_0 is on the chain")
	}
}

// AclAuthView's admissions come from the rows: an untagged device names its member, a tagged one its tags and its
// admitting member as sponsor, until that member goes.
func TestConfigStateGivesAclItsAdmissions(t *testing.T) {
	net := newTestConfigNet(t)
	member := testConfigId("tag owner")
	tagId := testConfigId("tag ci")
	net.admitMember(net.owner, member, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	ownerDevice := net.device("tag owner device", member)
	net.admitDevice(net.owner, ownerDevice, 0)
	net.withTagOwner(tagId, member)

	agent := net.device("ci agent", Id{})
	net.mustPost(ownerDevice, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(agent, []Id{tagId}, true, net.timeMs+60*60*1000, 0))
	state := net.log.State()
	facts := state.Sidecar(agent.sidecarId)
	if facts == nil || len(facts.TagIds) != 1 || facts.TagIds[0] != tagId || !facts.Ephemeral || facts.MemberId != (Id{}) {
		t.Fatalf("the agent's admission: %+v", facts)
	}
	if sponsor, ok := state.Sponsor(agent.sidecarId); !ok || sponsor != member {
		t.Errorf("sponsor %s, %t", sponsor, ok)
	}
	if facts := state.Sidecar(ownerDevice.sidecarId); facts == nil || facts.MemberId != member || 0 < len(facts.TagIds) {
		t.Errorf("the member device's admission: %+v", facts)
	}

	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_REVOKE, &bridge.MemberRevoke{Header: net.header(), MemberId: member.Bytes()})
	if _, ok := net.log.State().Sponsor(agent.sidecarId); ok {
		t.Error("a removed member still sponsors")
	}
}

// Makes member the owner of tagId in the acl rows, by a base at the tip that folds everything.
func (self *testConfigNet) withTagOwner(tagId Id, member Id) {
	self.t.Helper()
	state := self.log.State()
	rows := state.Rows()
	aclRows := proto.Clone(state.aclRows).(*protocol.AclRows)
	aclRows.Atoms = append(aclRows.Atoms, &protocol.AclAtom{Atom: tagId.Bytes(), TagOwnerMemberIds: [][]byte{member.Bytes()}})
	rows.Acl = testConfigMarshal(self.t, aclRows)
	configVersion := state.Base().GetConfigVersion() + 1
	verdict := self.pushBase(self.owner, rows, self.n, configVersion, state.threshold)
	if !verdict.Accepted() {
		self.t.Fatal(verdict.Refusal)
	}
}
