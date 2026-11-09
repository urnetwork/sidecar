// A synthetic network for the posture's tests: ids and keys from fixed seeds, a genesis, members and sidecars,
// ProjectionRows and an authorization log built as §7.9 writes one, so every run and every leg builds the same bytes
// (testdata/device/). Nothing here is a real identity.

package device

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A member of the fixture network.
type postureFixtureMember struct {
	id   []byte
	role bridge.MemberRole
}

// A sidecar of the fixture network, with its identity key.
type postureFixtureSidecar struct {
	id       []byte
	key      ed25519.PrivateKey
	member   *postureFixtureMember
	sponsor  *postureFixtureMember
	readOnly bool
	revoked  bool
}

// The public half of the sidecar's identity key.
func (self *postureFixtureSidecar) publicKey() []byte {
	return self.key.Public().(ed25519.PublicKey)
}

// The network and its log, positions 1 on.
type postureFixture struct {
	t         testing.TB
	networkId []byte
	genesis   []byte
	anchor    [sha256.Size]byte
	owner     *postureFixtureMember
	alice     *postureFixtureMember
	// the owner's phone, a config writer
	ownerPhone *postureFixtureSidecar
	// this device's sidecar role, the owner's too
	self        *postureFixtureSidecar
	aliceLaptop *postureFixtureSidecar
	// tagged, sponsored by alice
	agent *postureFixtureSidecar
	// a page Worker of alice's, read_only
	aliceWorker *postureFixtureSidecar
	// every row the next rows hold, in order
	sidecars []*postureFixtureSidecar
	members  []*postureFixtureMember
	// rows by their SHA-256
	rowsBySha256 map[[sha256.Size]byte][]byte
	// the log: entries[i] is position i+1, chains[i] its A_n
	entries [][]byte
	chains  [][sha256.Size]byte
	timeMs  int64
	nonce   byte
	// filler bytes in each AclRows, so rows can be made large
	aclFillerByteCount int
}

// A synthetic id of 16 bytes.
func postureFixtureId(seed byte) []byte {
	return bytes.Repeat([]byte{seed}, postureIdByteCount)
}

// A synthetic identity key.
func postureFixtureKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

// The fixture network: an owner and a member, alice, with their devices, and no log yet.
func newPostureFixture(t testing.TB) *postureFixture {
	self := &postureFixture{
		t:            t,
		networkId:    postureFixtureId(0x01),
		owner:        &postureFixtureMember{id: postureFixtureId(0x02), role: bridge.MemberRole_MEMBER_ROLE_OWNER},
		alice:        &postureFixtureMember{id: postureFixtureId(0x03), role: bridge.MemberRole_MEMBER_ROLE_MEMBER},
		rowsBySha256: map[[sha256.Size]byte][]byte{},
		timeMs:       1_800_000_000_000,
	}
	self.ownerPhone = &postureFixtureSidecar{id: postureFixtureId(0x11), key: postureFixtureKey(0x11), member: self.owner}
	self.self = &postureFixtureSidecar{id: postureFixtureId(0x12), key: postureFixtureKey(0x12), member: self.owner}
	self.aliceLaptop = &postureFixtureSidecar{id: postureFixtureId(0x13), key: postureFixtureKey(0x13), member: self.alice}
	self.agent = &postureFixtureSidecar{id: postureFixtureId(0x14), key: postureFixtureKey(0x14), sponsor: self.alice}
	self.aliceWorker = &postureFixtureSidecar{id: postureFixtureId(0x15), key: postureFixtureKey(0x15), member: self.alice, readOnly: true}
	self.members = []*postureFixtureMember{self.owner, self.alice}
	self.sidecars = []*postureFixtureSidecar{self.ownerPhone, self.self, self.aliceLaptop, self.agent, self.aliceWorker}
	genesisBody, err := proto.MarshalOptions{Deterministic: true}.Marshal(&bridge.Genesis{
		NetworkId: self.networkId, ConfigRepoId: postureFixtureId(0x04), OwnerMemberId: self.owner.id,
		OwnerSidecarId: self.ownerPhone.id, OwnerIdentityPublicKey: self.ownerPhone.publicKey(), TimeMs: self.timeMs,
	})
	if err != nil {
		t.Fatal(err)
	}
	self.genesis = self.sign(self.ownerPhone, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_GENESIS, genesisBody)
	self.anchor = bridge.GenesisChain(self.genesis)
	return self
}

// A Signed's bytes over body, by sidecar's identity key.
func (self *postureFixture) sign(sidecar *postureFixtureSidecar, purpose string, signedType bridge.SignedType, body []byte) []byte {
	signed := &bridge.Signed{
		Body:      body,
		SignerId:  sidecar.id,
		Signature: ed25519.Sign(sidecar.key, bridge.SignedBytes(purpose, signedType, body)),
		Type:      uint32(signedType),
	}
	signedBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	if err != nil {
		self.t.Fatal(err)
	}
	return signedBytes
}

// AclRows' bytes, hand-written as protowire since acl.proto is not linkable here: has_document, then filler in field 2.
func (self *postureFixture) aclRows(hasDocument bool) []byte {
	acl := []byte{}
	if hasDocument {
		acl = protowire.AppendTag(acl, postureAclFieldHasDocument, protowire.VarintType)
		acl = protowire.AppendVarint(acl, 1)
	}
	if 0 < self.aclFillerByteCount {
		acl = protowire.AppendTag(acl, 2, protowire.BytesType)
		acl = protowire.AppendBytes(acl, bytes.Repeat([]byte{0xa5}, self.aclFillerByteCount))
	}
	return acl
}

// The rows of the network as it stands, with has_document.
func (self *postureFixture) rows(hasDocument bool) []byte {
	rows := &bridge.ProjectionRows{Acl: self.aclRows(hasDocument)}
	for _, member := range self.members {
		rows.Members = append(rows.Members, &bridge.MemberRow{MemberId: member.id, Role: member.role})
	}
	for _, sidecar := range self.sidecars {
		row := &bridge.SidecarRow{
			SidecarId: sidecar.id, IdentityPublicKey: sidecar.publicKey(), IdentityAlg: "ed25519", AdmittedAt: 1,
		}
		if sidecar.member != nil {
			row.MemberId = sidecar.member.id
		} else {
			row.TagIds = [][]byte{postureFixtureId(0x30)}
		}
		if sidecar.sponsor != nil {
			row.Sponsor = sidecar.sponsor.id
		}
		if sidecar.readOnly {
			row.Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
		}
		if sidecar.revoked {
			row.RevokedAt = 1
		}
		rows.Sidecars = append(rows.Sidecars, row)
	}
	rowsBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(rows)
	if err != nil {
		self.t.Fatal(err)
	}
	self.rowsBySha256[sha256.Sum256(rowsBytes)] = rowsBytes
	return rowsBytes
}

// The newest position.
func (self *postureFixture) tip() uint64 {
	return uint64(len(self.entries))
}

// A_n, A_0 being the anchor.
func (self *postureFixture) chain(n uint64) [sha256.Size]byte {
	if n == 0 {
		return self.anchor
	}
	return self.chains[n-1]
}

// Appends an entry of kind over body at the next position and returns its bytes.
func (self *postureFixture) append(kind uint32, body []byte) []byte {
	n := self.tip() + 1
	prev := self.chain(n - 1)
	self.timeMs += 1000
	entry := &bridge.AuthEntry{NetworkId: self.networkId, N: n, PrevChain: prev[:], Kind: kind, TimeMs: self.timeMs, Body: body}
	entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
	if err != nil {
		self.t.Fatal(err)
	}
	chain, err := bridge.AuthChainDigest(n, prev[:], kind, self.timeMs, body)
	if err != nil {
		self.t.Fatal(err)
	}
	self.entries = append(self.entries, entryBytes)
	self.chains = append(self.chains, chain)
	return entryBytes
}

// A base at the next position over the network's rows as they stand, signed by signer.
func (self *postureFixture) base(signer *postureFixtureSidecar, hasDocument bool) uint64 {
	rows := self.rows(hasDocument)
	rowsSha256 := sha256.Sum256(rows)
	n := self.tip() + 1
	prev := self.chain(n - 1)
	header, err := proto.MarshalOptions{Deterministic: true}.Marshal(&bridge.ProjectionHeader{
		NetworkId: self.networkId, Version: n, PrevChain: prev[:], FoldedThrough: n - 1, ConfigVersion: n,
		ConfigHeadSha256: postureFixtureId(0x40), RowsSha256: rowsSha256[:], RowsByteCount: uint32(len(rows)), Threshold: 1,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.append(bridge.AuthEntryKindBase, self.sign(signer, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_PROJECTION_HEADER, header))
	return n
}

// A header for a statement at the next position.
func (self *postureFixture) header() *bridge.StatementHeader {
	self.nonce += 1
	at := self.chain(self.tip())
	return &bridge.StatementHeader{
		NetworkId:  self.networkId,
		At:         &bridge.AuthPin{Version: self.tip(), Chain: at[:]},
		Nonce:      bytes.Repeat([]byte{self.nonce}, 16),
		NotAfterMs: self.timeMs + 7*24*60*60*1000,
	}
}

// A statement at the next position, signed by signer.
func (self *postureFixture) statement(signer *postureFixtureSidecar, purpose string, signedType bridge.SignedType, message proto.Message) uint64 {
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		self.t.Fatal(err)
	}
	self.append(bridge.AuthEntryKindStatement, self.sign(signer, purpose, signedType, body))
	return self.tip()
}

// A SidecarRevoke of subject by signer at the next position.
func (self *postureFixture) sidecarRevoke(signer *postureFixtureSidecar, subject *postureFixtureSidecar, reason bridge.SidecarRevokeReason) uint64 {
	return self.statement(signer, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_SIDECAR_REVOKE,
		&bridge.SidecarRevoke{Header: self.header(), SidecarId: subject.id, Reason: reason})
}

// A Suspend of subject by signer.
func (self *postureFixture) suspend(signer *postureFixtureSidecar, subject []byte, suspendId []byte) uint64 {
	return self.statement(signer, bridge.SignedPurposeAcl, bridge.SignedType_SIGNED_SUSPEND,
		&bridge.Suspend{Header: self.header(), Subject: subject, SuspendId: suspendId})
}

// An Unsuspend of subject by signer.
func (self *postureFixture) unsuspend(signer *postureFixtureSidecar, subject []byte, suspendId []byte) uint64 {
	return self.statement(signer, bridge.SignedPurposeAcl, bridge.SignedType_SIGNED_UNSUSPEND,
		&bridge.Unsuspend{Header: self.header(), Subject: subject, SuspendId: suspendId})
}

// A tick at the next position.
func (self *postureFixture) tick() uint64 {
	body, err := proto.Marshal(&bridge.ApiTick{})
	if err != nil {
		self.t.Fatal(err)
	}
	self.append(bridge.AuthEntryKindTick, body)
	return self.tip()
}

// The Pending this device's sidecar role sends.
func (self *postureFixture) pending() *bridge.Pending {
	return &bridge.Pending{
		NetworkId: self.networkId, GenesisSha256: self.anchor[:], SidecarId: self.self.id, IdentityPublicKey: self.self.publicKey(),
	}
}

// A state at n, saying hasDocument, with rules that name n.
func (self *postureFixture) state(n uint64, hasDocument bool) *bridge.BridgeState {
	chain := self.chain(n)
	return &bridge.BridgeState{
		Auth:          &bridge.AuthPin{Version: n, Chain: chain[:]},
		GenesisSha256: self.anchor[:],
		HasDocument:   hasDocument,
		Rules:         []byte(fmt.Sprintf("rules at %d", n)),
		Names:         map[string]uint32{"laptop": 0x64400001},
		NameZones:     []string{"net.example"},
	}
}

// Entries from to through, both positions included.
func (self *postureFixture) log(from uint64, through uint64) *PostureLog {
	return &PostureLog{
		Entries: slices.Clone(self.entries[from-1 : through]),
		OpenRows: func(rowsSha256 []byte) (io.ReadCloser, error) {
			rows, ok := self.rowsBySha256[[sha256.Size]byte(rowsSha256)]
			if !ok {
				return nil, errors.New("no such rows")
			}
			return io.NopCloser(bytes.NewReader(rows)), nil
		},
	}
}

// A posture on store, failing the test on a load alarm.
func (self *postureFixture) open(store PostureStore) (*Posture, PostureDecision) {
	posture, decision := NewPosture(store, testPostureSettings())
	return posture, decision
}

// Settings small enough for tests to reach their bounds.
func testPostureSettings() *PostureSettings {
	settings := DefaultPostureSettings()
	settings.ReadByteCount = 4 * 1024
	return settings
}

// A posture taken to enforcing at the fixture's base 1 and pin 3: Pending, then a state with its log.
func (self *postureFixture) enforcing(store PostureStore, hasDocument bool) *Posture {
	self.t.Helper()
	if self.tip() == 0 {
		self.base(self.ownerPhone, hasDocument)
		self.tick()
		self.tick()
	}
	posture, _ := self.open(store)
	if _, err := posture.SetPending(self.pending()); err != nil {
		self.t.Fatal(err)
	}
	decision, err := posture.SetState(self.state(self.tip(), hasDocument), self.log(1, self.tip()))
	if err != nil {
		self.t.Fatal(err)
	}
	if !decision.State.Enforcing() {
		self.t.Fatalf("state %v", decision.State)
	}
	return posture
}

// Records in memory, with faults a test arms. Safe for concurrent use.
type memoryPostureStore struct {
	stateLock   sync.Mutex
	nameRecords map[string][]byte
	// names whose Open fails as present but unreadable
	unreadableNames map[string]bool
	// Open of the manifest blocks on this until it is closed, when set
	openGate chan struct{}
	opened   chan struct{}
	// the step at which the store dies, counted over writes' syncs and renames and removes; 0 never
	killAtStep int
	steps      int
	killed     bool
	// every Write, by name, in order
	writes []string
}

// An empty store.
func newMemoryPostureStore() *memoryPostureStore {
	return &memoryPostureStore{nameRecords: map[string][]byte{}, unreadableNames: map[string]bool{}}
}

// The store as a kill left it: its durable records, with no fault armed.
func (self *memoryPostureStore) survivor() *memoryPostureStore {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	survivor := newMemoryPostureStore()
	for name, record := range self.nameRecords {
		survivor.nameRecords[name] = record
	}
	return survivor
}

var errMemoryPostureStoreKilled = errors.New("the store's process was killed")

// Counts a step, and dies at the armed one.
func (self *memoryPostureStore) stepWithLock() error {
	if self.killed {
		return errMemoryPostureStoreKilled
	}
	self.steps += 1
	if self.killAtStep != 0 && self.steps == self.killAtStep {
		self.killed = true
		return errMemoryPostureStoreKilled
	}
	return nil
}

func (self *memoryPostureStore) Open(name string) (io.ReadCloser, error) {
	if name == postureManifestName && self.openGate != nil {
		close(self.opened)
		<-self.openGate
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.killed {
		return nil, errMemoryPostureStoreKilled
	}
	if self.unreadableNames[name] {
		return nil, fmt.Errorf("%w: unreadable", ErrPostureStoreFailed)
	}
	record, ok := self.nameRecords[name]
	if !ok {
		return nil, ErrPostureStoreAbsent
	}
	return io.NopCloser(bytes.NewReader(record)), nil
}

// The write's bytes, then a sync step and a rename step: a kill at the sync leaves nothing, at the rename the old.
func (self *memoryPostureStore) Write(name string, write func(writer io.Writer) error) error {
	buffer := &bytes.Buffer{}
	if err := write(buffer); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if err := self.stepWithLock(); err != nil {
		return err
	}
	if err := self.stepWithLock(); err != nil {
		return err
	}
	self.nameRecords[name] = buffer.Bytes()
	self.writes = append(self.writes, name)
	return nil
}

func (self *memoryPostureStore) Remove(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if err := self.stepWithLock(); err != nil {
		return err
	}
	delete(self.nameRecords, name)
	return nil
}

func (self *memoryPostureStore) List() ([]string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.killed {
		return nil, errMemoryPostureStoreKilled
	}
	names := []string{}
	for name := range self.nameRecords {
		names = append(names, name)
	}
	slices.Sort(names)
	return names, nil
}

// The record's bytes, for a test to change.
func (self *memoryPostureStore) record(name string) []byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.nameRecords[name]
}

// Replaces a record's bytes.
func (self *memoryPostureStore) setRecord(name string, record []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.nameRecords[name] = record
}

// The name of the record of kind the manifest names, such as rows.
func (self *memoryPostureStore) recordOf(kind string) string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for name := range self.nameRecords {
		if strings.HasPrefix(name, kind+"-") {
			return name
		}
	}
	return ""
}

// Whether the decision raised an alarm of kind.
func postureAlarmed(decision PostureDecision, kind PostureAlarmKind) bool {
	return slices.ContainsFunc(decision.Alarms, func(alarm PostureAlarm) bool {
		return alarm.Kind == kind
	})
}
