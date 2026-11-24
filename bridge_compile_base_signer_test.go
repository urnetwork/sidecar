// QD-1200 at the compile: a BridgeState carries the key its newest base verified under at S(b-1)
// (base_signer_identity_public_key), its signer's identity key, which the device role's posture tries for that base's
// signer under the state (device/posture_apply.go's readBase). The compile names it whatever reaches the host and
// whatever happened to the signer since: for an admin's device admitted after the last fold whose ACL save no rule lets
// reach the host, for a personal network's second device revoked after its save, and for a member's device the tail
// made an admin's; and a reader present since the bootstrap, a new device restored at the base and a rows-only reader,
// a forwarding role's judge, name the same key, as the Forwarder hands it to its device role.
// bridge_compile_base_signer_posture_test.go hands each such state and its run to the device role's posture. Before
// QD-1200 a state named the signer's key only among its identities, the subjects its rules let reach the host.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// An ACL document's save by signer, as a writer publishes a save that does not fold (QD-1193): a base at the tip
// keeping the newest base's fold, its rows that base's with a document of no rule, and its head that base's with the
// document's policy. Answers its position.
func (self *testBridgeLedgerNet) saveDocument(signer testConfigDevice) uint64 {
	self.t.Helper()
	previous := self.log.State().Base()
	configVersion := previous.GetConfigVersion() + 1
	head, err := self.heads[previous.GetConfigVersion()].WithFile(ConfigHeadPolicyPath, []byte("{}"))
	if err != nil {
		self.t.Fatal(err)
	}
	self.heads[configVersion] = head
	rows := self.log.baseRowsOf(self.t, previous)
	aclRows := &protocol.AclRows{}
	if err := proto.Unmarshal(rows.GetAcl(), aclRows); err != nil {
		self.t.Fatal(err)
	}
	aclRows.HasDocument = true
	rows.Acl = testConfigMarshal(self.t, aclRows)
	foldedThrough := previous.GetFoldedThrough()
	verdict, err := self.pushThrough(self.makeBase(signer, rows, foldedThrough, configVersion, self.statesAt[foldedThrough].threshold))
	if err != nil || !verdict.Accepted() {
		self.t.Fatalf("the save: %v, %v", err, verdict.Refusal)
	}
	return self.n
}

// A rows-only reader judging with the net's judge, as a forwarding role's compile judges, started at the newest base
// among the reader under test's kept entries.
func (self *testBridgeLedgerNet) rowsOnlyReader() *ConfigLog {
	self.t.Helper()
	reader, err := RestoreConfigLogRowsOnly(self.readerSettings(), self.log.Retained(), self.rowsOnlySource(), nil)
	if err != nil {
		self.t.Fatal(err)
	}
	return reader
}

// Whether the base at n verifies under key, as the device role's posture checks a base's signature.
func (self *testConfigNet) baseVerifiesUnder(n uint64, key []byte) bool {
	self.t.Helper()
	entry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(self.entries[n-1], entry); err != nil {
		self.t.Fatal(err)
	}
	signed, _, err := configParseBase(entry)
	if err != nil {
		self.t.Fatal(err)
	}
	return bridge.VerifySigned(signed, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_PROJECTION_HEADER, bridge.SignedKeyAlgEd25519, key) == nil
}

// Whether rows name a sidecar a config writer: a standing member's device, not read_only, whose member's role is in the
// AdminSet, as IsConfigWriter and the device role's posture read them.
func testBridgeRowsNameWriter(rows *bridge.ProjectionRows, sidecarId Id) bool {
	for _, row := range rows.GetSidecars() {
		memberId, ok := configRowMember(row)
		if Id(row.GetSidecarId()) != sidecarId || !ok || row.GetRevokedAt() != 0 || configRowReadOnly(row) {
			continue
		}
		if slices.ContainsFunc(rows.GetMembers(), func(member *bridge.MemberRow) bool {
			return Id(member.GetMemberId()) == memberId && configRoleInAdminSet(member.GetRole())
		}) {
			return true
		}
	}
	return false
}

// Whether a state's identities name a sidecar.
func testBridgeStateNames(state *bridge.BridgeState, sidecarId Id) bool {
	return slices.ContainsFunc(state.GetIdentities(), func(identity *bridge.BridgeIdentity) bool {
		return Id(identity.GetSidecarId()) == sidecarId
	})
}

// A reader whose state a compile reads, by what holds it.
type testBridgeCompileReader struct {
	name string
	log  *ConfigLog
}

// The readers whose states a compile reads, a daemon's and a forwarding role's, over the net's log.
func (self *testBridgeCompileNet) readers() []testBridgeCompileReader {
	return []testBridgeCompileReader{
		{name: "present", log: self.log},
		{name: "restored", log: self.restoredReader()},
		{name: "rows-only", log: self.rowsOnlyReader()},
	}
}

// A later writer's save on the compile net, as QD-1200 names its cases: the net, the save's signer and its position.
// The save's rows name the signer no config writer, and the host's identities do not name it.
type testBridgeCompileLaterSave struct {
	net    *testBridgeCompileNet
	signer testConfigDevice
	saved  uint64
}

// An admin's device admitted after base 1's fold saves an ACL document of no rule, a base keeping that fold, so no rule
// lets it reach the host, the member's laptop.
func newTestBridgeCompileLaterAdminSave(t testing.TB) testBridgeCompileLaterSave {
	net := newTestBridgeCompileNet(t)
	admin := net.admitAdmin("team")
	return testBridgeCompileLaterSave{net: net, signer: admin, saved: net.saveDocument(admin)}
}

// A personal network's second device saves an ACL document, a base keeping base 1's fold, and is revoked as lost
// before the next compile; a new device of the owner's, the host, is admitted after.
func newTestBridgeCompileRevokedSave(t testing.TB) testBridgeCompileLaterSave {
	ledger := newTestBridgeLedgerNet(t)
	second := ledger.device("owner second device", ledger.ownerMemberId)
	ledger.admitDevice(ledger.owner, second, 0)
	saved := ledger.saveDocument(second)
	ledger.mustPost(ledger.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, ledger.revocation(second, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	host := ledger.device("owner new device", ledger.ownerMemberId)
	ledger.admitDevice(ledger.owner, host, 0)
	net := &testBridgeCompileNet{testBridgeLedgerNet: ledger, host: host, bindings: NewBridgeBindingCache(7*24*time.Hour, 16)}
	net.blockFile = net.sign(net.owner, bridge.SignedType_SIGNED_BRIDGE_BLOCK, testBridgeCompileBlock())
	return testBridgeCompileLaterSave{net: net, signer: second, saved: saved}
}

// The other member's device, which the owner's fold names as a member's and no admin's, is made an admin's by an
// AdminSet in the tail and saves an ACL document keeping that fold.
func newTestBridgeCompilePromotedSave(t testing.TB) testBridgeCompileLaterSave {
	net := newTestBridgeCompileNet(t)
	net.foldLedger(net.n, nil)
	rows := net.log.baseRowsOf(t, net.log.State().Base())
	if net.log.State().IsConfigWriter(net.other.sidecarId) ||
		!slices.ContainsFunc(rows.GetSidecars(), func(row *bridge.SidecarRow) bool { return Id(row.GetSidecarId()) == net.other.sidecarId }) {
		t.Fatal("the fold's rows do not name the member's device, or it writes config before its member is an admin")
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_ADMIN_SET, &protocol.AdminSet{
		Header: net.header(), Owners: [][]byte{net.ownerMemberId.Bytes()}, Admins: [][]byte{net.other.memberId.Bytes()},
	})
	return testBridgeCompileLaterSave{net: net, signer: net.other, saved: net.saveDocument(net.other)}
}

// Compiles the save's state on every reader, failing the test unless each names the key the save verified under, the
// save's rows naming its signer no config writer and the state's identities not naming it, and all compile the same
// bytes. Answers the present reader's compile.
func (self testBridgeCompileLaterSave) compileOnEveryReader(t testing.TB) *BridgeCompiled {
	t.Helper()
	net := self.net
	if net.log.State().Base().GetVersion() != self.saved || testBridgeRowsNameWriter(net.log.baseRowsOf(t, net.log.State().Base()), self.signer.sidecarId) {
		t.Fatal("the save is not the newest base, or its rows name its signer a config writer")
	}
	var present *BridgeCompiled
	for _, reader := range net.readers() {
		compiled, rules := testBridgeCompile(t, net.viewOf(reader.log), net.local())
		state := compiled.State
		if !state.GetHasDocument() || testBridgeCompileSubject(rules, self.signer.sidecarId) != nil || testBridgeStateNames(state, self.signer.sidecarId) {
			t.Fatalf("%s: has_document %t, or the save's signer a subject or named", reader.name, state.GetHasDocument())
		}
		if key := state.GetBaseSignerIdentityPublicKey(); !bytes.Equal(key, self.signer.publicKey()) || !net.baseVerifiesUnder(self.saved, key) {
			t.Errorf("%s: the state names %x", reader.name, key)
		}
		if present == nil {
			present = compiled
		} else if compiled.Digest != present.Digest {
			t.Errorf("%s compiles %x, the present reader %x", reader.name, compiled.Digest, present.Digest)
		}
	}
	return present
}

// Base 1 and the owner's fold of the ledger each verified under the owner's device's key, which the state names; a
// state before base 1 names none.
func TestCompileNamesTheKeyItsNewestBaseVerifiedUnder(t *testing.T) {
	net := newTestBridgeCompileNet(t)
	compiled, _ := testBridgeCompile(t, net.view(), net.local())
	if key := compiled.State.GetBaseSignerIdentityPublicKey(); !bytes.Equal(key, net.owner.publicKey()) || !net.baseVerifiesUnder(1, key) {
		t.Fatalf("on base 1 the state names %x", key)
	}
	net.foldLedger(net.n, nil)
	folded := net.n
	compiled, _ = testBridgeCompile(t, net.view(), net.local())
	if key := compiled.State.GetBaseSignerIdentityPublicKey(); !bytes.Equal(key, net.owner.publicKey()) || !net.baseVerifiesUnder(folded, key) {
		t.Fatalf("on the fold the state names %x", key)
	}
	if key := bridgeCompileBaseSignerKey(net.statesAt[0]); key != nil {
		t.Errorf("S(0) names %x", key)
	}
}

// An admin's device admitted after the last fold saves an ACL document no rule of which lets it reach the host: every
// reader's state names the key the save verified under.
func TestCompileNamesALaterAdminsKeyThatNoRuleLetsReachTheHost(t *testing.T) {
	newTestBridgeCompileLaterAdminSave(t).compileOnEveryReader(t)
}

// A personal network's second device saves an ACL document and is revoked before the next compile: every reader's state
// for the owner's new device names the key the save verified under at S(b-1), a new device restored at the save among
// them, though the second device stands nowhere now.
func TestCompileNamesTheKeyOfASaveWhoseSignerWasRevokedSince(t *testing.T) {
	save := newTestBridgeCompileRevokedSave(t)
	if save.net.log.State().IsConfigWriter(save.signer.sidecarId) {
		t.Fatal("the revoked device still writes config")
	}
	save.compileOnEveryReader(t)
}

// A member's device the tail made an admin's saves an ACL document keeping the fold: every reader's state names the key
// the save verified under.
func TestCompileNamesTheKeyOfABaseByAWriterTheTailPromoted(t *testing.T) {
	newTestBridgeCompilePromotedSave(t).compileOnEveryReader(t)
}

// The Forwarder's own compile, its rows-only judge restored at the newest base it stored: after a second device of the
// owner's saves an ACL document keeping base 1's fold and is revoked, the state it hands its device role names the key
// the save verified under, beside a run that starts at the save.
func TestTheForwardersStateNamesTheKeyOfALaterWritersSave(t *testing.T) {
	world := newTestForwarderWorld(t)
	forwarder := world.forwarder()
	net := world.net
	second := net.device("owner second device", net.ownerMemberId)
	net.admitDevice(net.owner, second, 0)
	saved := world.ledger.saveDocument(second)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(second, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	handed := []*bridge.BridgeState{}
	world.sink.stateLock.Lock()
	world.sink.onState = func(state *bridge.BridgeState) error {
		handed = append(handed, proto.Clone(state).(*bridge.BridgeState))
		return nil
	}
	world.sink.stateLock.Unlock()
	world.hint(forwarder)
	if len(handed) != 1 || handed[0].GetAuth().GetVersion() != net.n {
		t.Fatalf("the sink was handed %d states: %v", len(handed), world.events.list())
	}
	state := handed[0]
	if key := state.GetBaseSignerIdentityPublicKey(); !bytes.Equal(key, second.publicKey()) || !net.baseVerifiesUnder(saved, key) || testBridgeStateNames(state, second.sidecarId) {
		t.Errorf("the handed state names %x", key)
	}
	if !slices.Contains(world.events.list(), fmt.Sprintf("state %d of %d entries", net.n, net.n-saved+1)) {
		t.Errorf("the run does not start at the save: %v", world.events.list())
	}
	if status := forwarder.Status(); status.CompileErrorCount != 0 || !proto.Equal(status.CompiledPin, state.GetAuth()) {
		t.Errorf("status %+v", status)
	}
}

// A compiled state on a later writer's save and what vouches for it, crossing into the external test as
// RouteGrantHostFixture does, so the root keeps its device-independent build: the host's Pending, the state, the run
// from the save through the state's pin and the save's rows.
type BaseSignerPostureCase struct {
	Name    string
	Pending *bridge.Pending
	State   *bridge.BridgeState
	// AuthEntry bytes from the state's newest base, the save, through its pin.
	Entries [][]byte
	// The save's rows by their SHA-256.
	Rows map[[sha256.Size]byte][]byte
	// The save's position.
	BaseN uint64
}

// The present reader's compile of each of QD-1200's cases, with what the device role's posture needs to take it from
// pending: an admin's save no rule lets reach the host, a save whose signer was revoked since, and a save by a writer
// the tail promoted.
func CompileBaseSignerPostureCases(t *testing.T) []BaseSignerPostureCase {
	t.Helper()
	cases := []BaseSignerPostureCase{}
	for _, c := range []struct {
		name string
		save func(t testing.TB) testBridgeCompileLaterSave
	}{
		{name: "a later admin's save", save: newTestBridgeCompileLaterAdminSave},
		{name: "a save whose signer was revoked", save: newTestBridgeCompileRevokedSave},
		{name: "a promoted writer's save", save: newTestBridgeCompilePromotedSave},
	} {
		save := c.save(t)
		net := save.net
		compiled := save.compileOnEveryReader(t)
		base := net.log.State().Base()
		rowsSha256 := [sha256.Size]byte(base.GetRowsSha256())
		rows, found := net.source.rows[rowsSha256]
		if !found {
			t.Fatalf("%s: the save's rows are not published", c.name)
		}
		cases = append(cases, BaseSignerPostureCase{
			Name:    c.name,
			Pending: CompileBridgePending(net.log.State(), &SidecarIdentity{SidecarId: net.host.sidecarId, IdentityPublicKey: net.host.publicKey()}),
			State:   compiled.State,
			Entries: slices.Clone(net.entries[save.saved-1:]),
			Rows:    map[[sha256.Size]byte][]byte{rowsSha256: rows},
			BaseN:   save.saved,
		})
	}
	return cases
}
