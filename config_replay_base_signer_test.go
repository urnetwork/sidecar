// A reader that starts at a base judges the base's signer where a reader present at b-1 judges it: at S(b-1), which it
// rebuilds as b's rows with b's tail re-applied by its verdicts, or as the genesis state when no base precedes b. The
// writer's fold rule lets a base keep the fold below its own signer's admission (a policy-only save keeps the previous
// base's folded_through), so b's rows alone may not name the signer at all: a personal network's second owner device
// saving an ACL document signs exactly such a base. These tests hold a new device, a rows-only gate and a long-running
// reader to one verdict on each base: they take a base a writer the tail admitted or promoted signed, and fork on one
// signed by a device no rows admit, by a writer the tail revoked, or, as the first base, by any device but the genesis
// owner's.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A personal network whose owner's second device, admitted by its first after base 1, signs a base keeping base 1's
// fold, as `ur acl push` on that device publishes one: the base's rows are base 1's, which name only the first device,
// and its tail holds the admission. Answers the net, the second device and the base's header.
func newTestConfigSecondOwnerDeviceBase(t *testing.T) (*testConfigNet, testConfigDevice, *bridge.ProjectionHeader) {
	t.Helper()
	net := newTestConfigNet(t)
	second := net.device("owner second device", net.ownerMemberId)
	net.admitDevice(net.owner, second, 0)
	previousBase := net.log.State().Base()
	rows := net.log.baseRowsOf(t, previousBase)
	if sidecars := rows.GetSidecars(); len(sidecars) != 1 || !bytes.Equal(sidecars[0].GetSidecarId(), net.owner.sidecarId.Bytes()) {
		t.Fatalf("base 1's rows name %d sidecars", len(sidecars))
	}
	verdict := net.pushBase(second, rows, previousBase.GetFoldedThrough(), previousBase.GetConfigVersion()+1, 0)
	if !verdict.Accepted() {
		t.Fatalf("the long-running reader refused the second device's base: %v", verdict.Refusal)
	}
	header := net.log.State().Base()
	if header.GetFoldedThrough() != 0 || header.GetVersion() != 3 {
		t.Fatalf("the base at %d folds through %d", header.GetVersion(), header.GetFoldedThrough())
	}
	return net, second, header
}

// The log's entries with entryBytes after them, as a reader that kept everything up to the tip and then received one
// more entry holds them.
func (self *testConfigNet) retainedWith(entryBytes []byte) *ConfigRetained {
	self.t.Helper()
	retained := self.log.Retained()
	retained.Entries = append(retained.Entries, entryBytes)
	return retained
}

// The verdict every kind of reader gives entryBytes at the tip's next position: a long-running reader applying it,
// a new device and a rows-only gate starting at it. Each must fork, naming the signer check.
func (self *testConfigNet) everyReaderForksOnBase(entryBytes []byte) {
	self.t.Helper()
	reader := self.newReader()
	if _, err := reader.Apply(entryBytes, self.source); !errors.Is(err, ErrConfigFork) || !strings.Contains(err.Error(), "no config writer") {
		self.t.Errorf("the long-running reader: %v, want the signer's fork", err)
	}
	retained := self.retainedWith(entryBytes)
	if _, err := RestoreConfigLog(testConfigLogSettings(), retained, self.source); !errors.Is(err, ErrConfigFork) || !strings.Contains(err.Error(), "no config writer") {
		self.t.Errorf("a new device: %v, want the signer's fork", err)
	}
	if _, err := RestoreConfigLogRowsOnly(testConfigLogSettings(), retained, self.rowsOnlySource(), nil); !errors.Is(err, ErrConfigFork) || !strings.Contains(err.Error(), "no config writer") {
		self.t.Errorf("a rows-only gate: %v, want the signer's fork", err)
	}
}

// The case e2e-control-plane-concurrency found (TestE2eControlPlaneConcurrencyColdGate): a new device and a rows-only
// gate starting at the second owner device's base take it, as the long-running reader did, and hold its S(b); the new
// device's head check reads the head under an anchor that admits the second device, which pushed that head.
func TestAColdReaderTakesABaseASecondOwnerDeviceSignedPastItsRowsFold(t *testing.T) {
	net, second, header := newTestConfigSecondOwnerDeviceBase(t)
	retained := net.log.Retained()

	net.source.checks = nil
	restored, err := RestoreConfigLog(testConfigLogSettings(), retained, net.source)
	if err != nil {
		t.Fatalf("a new device at the base: %v", err)
	}
	if restored.Pin().GetVersion() != header.GetVersion() {
		t.Fatalf("the new device holds %d", restored.Pin().GetVersion())
	}
	if !restored.State().IsConfigWriter(second.sidecarId) {
		t.Error("the new device holds the second device as no config writer")
	}
	anchored := false
	for _, check := range net.source.checks {
		if check.Previous != nil {
			continue
		}
		anchored = true
		if check.Anchor == nil || !bytes.Equal(check.Anchor.IdentityKey(second.sidecarId), second.publicKey()) {
			t.Error("the anchor the head is read under does not admit the device that pushed it")
		}
		if !bytes.Equal(check.Anchor.IdentityKey(net.owner.sidecarId), net.owner.publicKey()) {
			t.Error("the anchor lost the first device's identity key")
		}
	}
	if !anchored {
		t.Fatal("the new device checked no head at its anchor")
	}
	testConfigStatesEqual(t, restored.State(), net.log.State())

	gate, err := RestoreConfigLogRowsOnly(testConfigLogSettings(), retained, net.rowsOnlySource(), nil)
	if err != nil {
		t.Fatalf("a rows-only gate at the base: %v", err)
	}
	testConfigStatesEqual(t, gate.State(), net.log.State())

	// and on past the base, each applying what follows as a long-running reader does
	third := net.device("owner third device", net.ownerMemberId)
	net.admitDevice(second, third, 0)
	net.everyReaderAgrees()
}

// A base signed by a device no rows ever admitted, over the same log, the tail holding the second device's admission:
// the long-running reader, a new device and a rows-only gate each fork on it, as before.
func TestAColdReaderRefusesABaseByADeviceNoRowsAdmit(t *testing.T) {
	net := newTestConfigNet(t)
	second := net.device("owner second device", net.ownerMemberId)
	net.admitDevice(net.owner, second, 0)
	previousBase := net.log.State().Base()
	stranger := net.device("stranger", net.ownerMemberId)
	forged := net.makeBase(stranger, net.log.baseRowsOf(t, previousBase), previousBase.GetFoldedThrough(), previousBase.GetConfigVersion()+1, 0)
	net.everyReaderForksOnBase(forged)
}

// A writer the base's rows still name standing, revoked in the base's tail, signs a base keeping the fold below its
// revocation. The long-running reader forks, the signer being no config writer at b-1; a new device and a rows-only
// gate fork too, where judging the rows alone took it.
func TestAColdReaderRefusesABaseByAWriterItsTailRevoked(t *testing.T) {
	net := newTestConfigNet(t)
	second := net.device("owner second device", net.ownerMemberId)
	net.admitDevice(net.owner, second, 0)
	net.fold(net.owner, net.n, 2)
	folded := net.log.State().Base()
	rows := net.log.baseRowsOf(t, folded)
	if row := net.statesAt[folded.GetFoldedThrough()].SidecarRow(second.sidecarId); row == nil || row.GetRevokedAt() != 0 {
		t.Fatal("the fold's rows do not hold the second device standing")
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(second, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	if net.log.State().IsConfigWriter(second.sidecarId) {
		t.Fatal("a revoked device writes config")
	}
	forged := net.makeBase(second, rows, folded.GetFoldedThrough(), folded.GetConfigVersion()+1, 0)
	net.everyReaderForksOnBase(forged)
}

// A member device the base's rows name under a role outside the AdminSet, its member made an Admin in the tail by an
// AdminSet at k = 1, signs a base keeping the fold: every reader takes it and holds one S(b).
func TestAColdReaderTakesABaseByADeviceItsTailPromoted(t *testing.T) {
	net := newTestConfigNet(t)
	member, device := net.consentedMember("promoted")
	net.fold(net.owner, net.n, 2)
	folded := net.log.State().Base()
	if net.log.State().IsConfigWriter(device.sidecarId) {
		t.Fatal("a member's device writes config before its member is an admin")
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_ADMIN_SET, &protocol.AdminSet{
		Header: net.header(), Owners: [][]byte{net.ownerMemberId.Bytes()}, Admins: [][]byte{member.Bytes()},
	})
	if !net.log.State().IsConfigWriter(device.sidecarId) {
		t.Fatal("the admin's device writes no config")
	}
	rows := net.log.baseRowsOf(t, folded)
	verdict := net.pushBase(device, rows, folded.GetFoldedThrough(), folded.GetConfigVersion()+1, net.statesAt[folded.GetFoldedThrough()].threshold)
	if !verdict.Accepted() {
		t.Fatalf("the long-running reader refused the admin's base: %v", verdict.Refusal)
	}
	net.everyReaderAgrees()
}

// The first base, judged at S(0), whose one config writer is the genesis owner's device: a base 1 signed by another
// device, its rows naming that device the owner's, forks every reader; base 1 by the genesis device loads cold.
func TestAColdReaderJudgesTheFirstBaseByTheGenesisOwner(t *testing.T) {
	net := newTestConfigNet(t)
	if _, err := RestoreConfigLogRowsOnly(testConfigLogSettings(), net.log.Retained(), net.rowsOnlySource(), nil); err != nil {
		t.Fatalf("a rows-only gate at base 1: %v", err)
	}
	if _, err := RestoreConfigLog(testConfigLogSettings(), net.log.Retained(), net.source); err != nil {
		t.Fatalf("a new device at base 1: %v", err)
	}

	forger := net.device("forger", net.ownerMemberId)
	genesisChain := bridge.GenesisChain(net.signedGenesis)
	rows := &bridge.ProjectionRows{
		Members: []*bridge.MemberRow{{MemberId: net.ownerMemberId.Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_OWNER}},
		Sidecars: []*bridge.SidecarRow{{
			SidecarId:         forger.sidecarId.Bytes(),
			AdmissionSigners:  [][]byte{forger.sidecarId.Bytes()},
			IdentityPublicKey: forger.publicKey(),
			IdentityAlg:       configIdentityAlgEd25519,
			MemberId:          net.ownerMemberId.Bytes(),
			AdmissionSha256:   genesisChain[:],
		}},
		Settings: ConfigProjectionSettings(net.source.settings[[sha256.Size]byte(testConfigHeadSha256(1))]),
	}
	rowsBytes := testConfigMarshal(t, rows)
	rowsSha256 := sha256.Sum256(rowsBytes)
	net.source.rows[rowsSha256] = rowsBytes
	header := &bridge.ProjectionHeader{
		NetworkId:        net.networkId.Bytes(),
		Version:          1,
		PrevChain:        genesisChain[:],
		ConfigVersion:    1,
		ConfigHeadSha256: testConfigHeadSha256(1),
		RowsSha256:       rowsSha256[:],
		RowsByteCount:    uint32(len(rowsBytes)),
	}
	forged := testConfigMarshal(t, &bridge.AuthEntry{
		NetworkId: net.networkId.Bytes(),
		N:         1,
		PrevChain: genesisChain[:],
		Kind:      bridge.AuthEntryKindBase,
		TimeMs:    testConfigStartMs + 1000,
		Body:      net.sign(forger, bridge.SignedType_SIGNED_PROJECTION_HEADER, header),
	})

	reader, err := NewConfigLog(testConfigLogSettings(), net.signedGenesis)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Apply(forged, net.source); !errors.Is(err, ErrConfigFork) || !strings.Contains(err.Error(), "no config writer") {
		t.Errorf("the long-running reader: %v, want the signer's fork", err)
	}
	retained := &ConfigRetained{SignedGenesis: net.signedGenesis, Entries: [][]byte{forged}, Rows: map[[sha256.Size]byte][]byte{}}
	if _, err := RestoreConfigLog(testConfigLogSettings(), retained, net.source); !errors.Is(err, ErrConfigFork) || !strings.Contains(err.Error(), "no config writer") {
		t.Errorf("a new device: %v, want the signer's fork", err)
	}
	if _, err := RestoreConfigLogRowsOnly(testConfigLogSettings(), retained, net.rowsOnlySource(), nil); !errors.Is(err, ErrConfigFork) || !strings.Contains(err.Error(), "no config writer") {
		t.Errorf("a rows-only gate: %v, want the signer's fork", err)
	}
}
