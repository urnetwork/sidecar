// A restored binding's admission and its two kinds (QD-952, owner decision 314) on the test network: the kind is fixed
// at the proposal's entry, PROPOSAL_KIND_RESTORED with self_admit on and PROPOSAL_KIND_RESTORED_COSIGNED with it off,
// and the activation reads that kind from the row and no setting. Filed with self_admit off it activates only once an
// Owner's, Admin's or IT admin's device has cosigned; filed with it on it activates with no cosign; a base turning
// self_admit the other way between the entry and the tick changes neither; a new device and a rows-only gate that
// start at a base folding the proposal judge its tick by the row's kind; a base that keeps its fold and its self_admit
// re-opens the proposal in its tail with the same kind; and rows carry kind 4 and refuse kind 5.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A test network where member m's binding in effect is one a compromise void restored (§7.9's cascade): m's laptop
// binds key one, a stolen device of m's rebinds m to key two, and a compromise revocation of the stolen device from
// before that rebind voids key two, restoring key one. Returns the network, m, m's laptop and key one.
func newTestConfigRestoredNet(t *testing.T) (*testConfigNet, Id, testConfigDevice, testConfigRecoveryKey) {
	t.Helper()
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	keyOne := testConfigRecovery(member, "m one")
	net.mustPost(laptop, bridge.SignedType_SIGNED_RECOVERY_BIND, net.recoveryBind(keyOne))
	stolen := net.device("m stolen", member)
	net.admitDevice(laptop, stolen, 0)
	sinceN := net.n + 1
	keyTwo := testConfigRecovery(member, "m two")
	net.mustPost(stolen, bridge.SignedType_SIGNED_RECOVERY_REBIND, &protocol.RecoveryRebind{Header: net.header(), MemberId: member.Bytes(),
		PrevSha256: keyOne.sha256(), Ed25519PublicKeySha256: keyTwo.sha256(), Reason: bridge.RecoveryRebindReason_RECOVERY_REBIND_REASON_ROUTINE})
	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(stolen, sinceN))
	if state := net.log.State(); !state.BindingRestored(member) || !bytes.Equal(state.Member(member).GetRecoveryKeySha256(), keyOne.sha256()) {
		t.Fatal("the void did not restore key one")
	}
	return net, member, laptop, keyOne
}

// The ServiceSettings a head at configVersion holds, setting self_admit on or off.
func (self *testConfigNet) setHeadSelfAdmit(configVersion uint64, on bool) {
	mode := protocol.SelfAdmitMode_SELF_ADMIT_MODE_ON
	if !on {
		mode = protocol.SelfAdmitMode_SELF_ADMIT_MODE_OFF
	}
	self.source.settings[[sha256.Size]byte(testConfigHeadSha256(configVersion))] = &protocol.ServiceSettings{SelfAdmit: mode}
}

// A base at configVersion whose head turns self_admit on or off, folding the log through its tip.
func (self *testConfigNet) foldSelfAdmit(configVersion uint64, on bool) {
	self.t.Helper()
	self.setHeadSelfAdmit(configVersion, on)
	if verdict := self.fold(self.owner, self.n, configVersion); !verdict.Accepted() {
		self.t.Fatalf("the base at config version %d: %v", configVersion, verdict.Refusal)
	}
	if self.log.State().SelfAdmit() != on {
		self.t.Fatalf("self_admit is not %v after the base", on)
	}
}

// The kind a restored binding's admission takes when filed with self_admit on or off.
func testConfigRestoredKind(filedOn bool) bridge.ProposalKind {
	if filedOn {
		return bridge.ProposalKind_PROPOSAL_KIND_RESTORED
	}
	return bridge.ProposalKind_PROPOSAL_KIND_RESTORED_COSIGNED
}

// key proposes a new phone of member's, good for 7 days, failing the test unless the proposal opens, completing
// nothing, with kind. Returns its proposal_id and the phone.
func testConfigProposeRestored(t *testing.T, net *testConfigNet, member Id, key testConfigRecoveryKey, kind bridge.ProposalKind) ([]byte, testConfigDevice) {
	t.Helper()
	phone := net.device("m phone", member)
	proposed := net.postByRecovery(key, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, net.longProposal(bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(phone, nil, false, 0, 0)))
	if !proposed.Accepted() || len(proposed.CompletedProposalId) != 0 {
		t.Fatalf("the proposal: %v", proposed.Refusal)
	}
	proposalId := bytes.Clone(proposed.StatementId[:])
	testConfigExpectProposalKind(t, "the proposer's reader", net.log.State(), proposalId, kind)
	return proposalId, phone
}

// Fails the test unless state holds proposalId open in Recovery's window with kind.
func testConfigExpectProposalKind(t testing.TB, reader string, state *ConfigState, proposalId []byte, kind bridge.ProposalKind) {
	t.Helper()
	window, ok := state.RecoveryWindow(proposalId)
	if !ok || window.ClosedAt != 0 || bridge.ProposalKind(window.Row.GetKind()) != kind {
		t.Fatalf("%s: the proposal's window %+v, want it open with %s", reader, window, kind)
	}
}

// Filed with self_admit off, a restored binding's admission is PROPOSAL_KIND_RESTORED_COSIGNED: 72 h on, a tick
// activating it with no cosign is refused, at api's check (CheckTick) as at every reader; m's own device cannot give the
// cosign, since it is no admission signer's; an Owner's device can, which completes nothing; then the tick admits the
// phone at the tick's position.
func TestARestoredAdmissionFiledWithSelfAdmitOffActivatesOnlyWithACosign(t *testing.T) {
	net, member, laptop, keyOne := newTestConfigRestoredNet(t)
	net.foldSelfAdmit(2, false)
	proposalId, phone := testConfigProposeRestored(t, net, member, keyOne, bridge.ProposalKind_PROPOSAL_KIND_RESTORED_COSIGNED)
	if pending := net.log.State().PendingProposals(); len(pending) != 1 || !bytes.Equal(pending[0].GetProposalId(), proposalId) {
		t.Fatalf("pending %v", pending)
	}

	net.wait(72 * testConfigHourMs)
	tick := &bridge.ApiTick{ActivatedProposalIds: [][]byte{proposalId}}
	if err := net.log.CheckTick(tick, net.timeMs+1000); !errors.Is(err, ErrConfigAuthority) {
		t.Fatalf("api's check of the tick with no cosign: %v", err)
	}
	if verdict := net.activate(proposalId); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigAuthority) {
		t.Fatalf("the activation with no cosign: %v", verdict.Refusal)
	}
	if net.log.State().SidecarRow(phone.sidecarId) != nil {
		t.Fatal("a refused activation admitted the phone")
	}
	if verdict := net.cosign(laptop, proposalId); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigAuthority) {
		t.Errorf("m's own device's cosign: %v", verdict.Refusal)
	}
	cosigned := net.cosign(net.owner, proposalId)
	if !cosigned.Accepted() || len(cosigned.CompletedProposalId) != 0 || net.log.State().SidecarRow(phone.sidecarId) != nil {
		t.Fatalf("the owner's cosign: %v", cosigned.Refusal)
	}
	testConfigExpectProposalKind(t, "after the cosign", net.log.State(), proposalId, bridge.ProposalKind_PROPOSAL_KIND_RESTORED_COSIGNED)
	if err := net.log.CheckTick(tick, net.timeMs+1000); err != nil {
		t.Fatalf("api's check of the tick after the cosign: %v", err)
	}
	activated := net.activate(proposalId)
	if !activated.Accepted() {
		t.Fatalf("the activation after the cosign: %v", activated.Refusal)
	}
	if row := net.log.State().SidecarRow(phone.sidecarId); row == nil || row.GetAdmittedAt() != activated.Pin.GetVersion() {
		t.Errorf("the phone: %v", row)
	}
	if window, ok := net.log.State().RecoveryWindow(proposalId); !ok || window.Closed != ConfigProposalActivated {
		t.Errorf("the window: %+v", window)
	}
	net.everyReaderAgrees()
}

// A restored binding's admission keeps the kind its entry fixed when a base turns self_admit the other way before its
// tick, so the change decides nothing (owner decision 314): filed with self_admit on, it activates with no cosign though
// self_admit is off at the tick; filed with it off, it still needs an admission signer's cosign though self_admit is on.
// The base folds the proposal, so its row carries the kind, and every reader agrees at each entry after it. Under the
// reading QD-952 replaced, which took self_admit from rows at the tick, both cases went the other way.
func TestASelfAdmitChangeBeforeARestoredAdmissionsTickDecidesNothing(t *testing.T) {
	for _, filedOn := range []bool{true, false} {
		kind := testConfigRestoredKind(filedOn)
		net, member, _, keyOne := newTestConfigRestoredNet(t)
		net.foldSelfAdmit(2, filedOn)
		proposalId, phone := testConfigProposeRestored(t, net, member, keyOne, kind)
		net.foldSelfAdmit(3, !filedOn)
		if base := net.log.State().Base(); base.GetFoldedThrough() != base.GetVersion()-1 {
			t.Fatalf("filed with self_admit %v: the base does not fold the proposal", filedOn)
		}
		if rows := net.log.State().openProposalRows(); len(rows) != 1 || bridge.ProposalKind(rows[0].GetKind()) != kind {
			t.Fatalf("filed with self_admit %v: the rows %v", filedOn, rows)
		}
		net.everyReaderAgrees()

		net.wait(72 * testConfigHourMs)
		activated := net.activate(proposalId)
		if activated.Accepted() != filedOn {
			t.Fatalf("filed with self_admit %v: the activation with no cosign %v", filedOn, activated.Refusal)
		}
		if !filedOn {
			if !errors.Is(activated.Refusal, ErrConfigAuthority) {
				t.Errorf("filed with self_admit off: the activation with no cosign %v", activated.Refusal)
			}
			if cosigned := net.cosign(net.owner, proposalId); !cosigned.Accepted() {
				t.Fatalf("filed with self_admit off: the owner's cosign %v", cosigned.Refusal)
			}
			if activated = net.activate(proposalId); !activated.Accepted() {
				t.Fatalf("filed with self_admit off: the activation after the cosign %v", activated.Refusal)
			}
		}
		if row := net.log.State().SidecarRow(phone.sidecarId); row == nil || row.GetAdmittedAt() != activated.Pin.GetVersion() {
			t.Errorf("filed with self_admit %v: the phone %v", filedOn, row)
		}
		net.everyReaderAgrees()
	}
}

// A new device and a rows-only gate that start at a base folding a restored binding's admission take its kind from the
// row, which says self_admit was off at the proposal's entry while the base's own head turns it on: at the tick each
// refuses the activation no admission signer has cosigned, as the long-running reader does, and takes it once one has,
// admitting the phone at the same position.
func TestANewDeviceJudgesARestoredAdmissionsTickByTheRowsKind(t *testing.T) {
	net, member, _, keyOne := newTestConfigRestoredNet(t)
	net.foldSelfAdmit(2, false)
	proposalId, phone := testConfigProposeRestored(t, net, member, keyOne, bridge.ProposalKind_PROPOSAL_KIND_RESTORED_COSIGNED)
	net.foldSelfAdmit(3, true)
	retained := net.log.Retained()
	device, err := RestoreConfigLog(testConfigLogSettings(), retained, net.source)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := RestoreConfigLogRowsOnly(testConfigLogSettings(), retained, net.rowsOnlySource(), nil)
	if err != nil {
		t.Fatal(err)
	}
	readers := []struct {
		name   string
		log    *ConfigLog
		source ConfigRowsSource
	}{
		{name: "the long-running reader", log: net.log, source: net.source},
		{name: "a new device", log: device, source: net.source},
		{name: "a rows-only gate", log: gate, source: net.rowsOnlySource()},
	}

	net.wait(72 * testConfigHourMs)
	tick := &bridge.ApiTick{ActivatedProposalIds: [][]byte{proposalId}}
	for _, reader := range readers {
		state := reader.log.State()
		if !state.SelfAdmit() || state.Base().GetVersion() != net.n {
			t.Fatalf("%s: not at the base turning self_admit on", reader.name)
		}
		testConfigExpectProposalKind(t, reader.name, state, proposalId, bridge.ProposalKind_PROPOSAL_KIND_RESTORED_COSIGNED)
		if err := reader.log.CheckTick(tick, net.timeMs+1000); !errors.Is(err, ErrConfigAuthority) {
			t.Errorf("%s: the tick with no cosign: %v", reader.name, err)
		}
	}

	refused := net.activate(proposalId)
	cosigned := net.cosign(net.owner, proposalId)
	activated := net.activate(proposalId)
	if refused.Accepted() || !cosigned.Accepted() || !activated.Accepted() {
		t.Fatalf("the tick %v, the cosign %v, the activation %v", refused.Refusal, cosigned.Refusal, activated.Refusal)
	}
	for _, reader := range readers[1:] {
		for _, entryBytes := range net.entries[reader.log.Pin().GetVersion():] {
			if _, err := reader.log.Apply(entryBytes, reader.source); err != nil {
				t.Fatalf("%s: %v", reader.name, err)
			}
		}
		for _, want := range []ConfigVerdict{refused, cosigned, activated} {
			kept := reader.log.keptEntry(want.Pin.GetVersion())
			if kept == nil || kept.verdict.Accepted() != want.Accepted() || testConfigRefusalClass(kept.verdict.Refusal) != testConfigRefusalClass(want.Refusal) {
				t.Errorf("%s at %d: %+v, the long-running reader %v", reader.name, want.Pin.GetVersion(), kept, want.Refusal)
			}
		}
		if row := reader.log.State().SidecarRow(phone.sidecarId); row == nil || row.GetAdmittedAt() != activated.Pin.GetVersion() {
			t.Errorf("%s: the phone %v", reader.name, row)
		}
		testConfigStatesEqual(t, reader.log.State(), net.log.State())
	}
}

// A base that keeps both its fold and its self_admit, as a head edit's base does (ConfigWriter.SaveHead), leaves a
// restored binding's admission in its tail, where every reader re-opens it on the base's rows (DESIGN-DETAILS 5.2.4's
// Reapply) with the kind its entry fixed, of either value: filed with self_admit off it still needs the cosign at its
// tick, filed with it on it does not.
func TestARestoredAdmissionInABasesTailKeepsItsKind(t *testing.T) {
	for _, filedOn := range []bool{true, false} {
		kind := testConfigRestoredKind(filedOn)
		net, member, _, keyOne := newTestConfigRestoredNet(t)
		net.foldSelfAdmit(2, filedOn)
		foldedThrough := net.log.State().Base().GetFoldedThrough()
		proposalId, phone := testConfigProposeRestored(t, net, member, keyOne, kind)
		proposedAt := net.n
		net.setHeadSelfAdmit(3, filedOn)
		if verdict := net.fold(net.owner, foldedThrough, 3); !verdict.Accepted() {
			t.Fatalf("filed with self_admit %v: the base keeping its fold %v", filedOn, verdict.Refusal)
		}
		if base := net.log.State().Base(); base.GetFoldedThrough() != foldedThrough || proposedAt <= foldedThrough {
			t.Fatalf("filed with self_admit %v: the proposal is not in the base's tail", filedOn)
		}
		testConfigExpectProposalKind(t, "the long-running reader", net.log.State(), proposalId, kind)
		net.everyReaderAgrees()

		net.wait(72 * testConfigHourMs)
		activated := net.activate(proposalId)
		if activated.Accepted() != filedOn {
			t.Fatalf("filed with self_admit %v: the activation with no cosign %v", filedOn, activated.Refusal)
		}
		if !filedOn {
			if cosigned := net.cosign(net.owner, proposalId); !cosigned.Accepted() {
				t.Fatalf("filed with self_admit off: the owner's cosign %v", cosigned.Refusal)
			}
			if activated = net.activate(proposalId); !activated.Accepted() {
				t.Fatalf("filed with self_admit off: the activation after the cosign %v", activated.Refusal)
			}
		}
		if net.log.State().SidecarRow(phone.sidecarId) == nil {
			t.Errorf("filed with self_admit %v: the phone is not admitted", filedOn)
		}
		net.everyReaderAgrees()
	}
}

// A base that keeps its fold while its own head turns self_admit the other way leaves a restored binding's admission
// in its tail, where Reapply opens it on the base's rows, whose self_admit is not the one its entry was judged under
// (question proposal-kind-restored-cosigned-tail-self-admit asks which kind it should then hold). Whatever kind that
// is, every reader holds the same one and gives its tick the same verdict, the long-running reader, a new device and a
// rows-only gate alike (D-TEAM-19).
func TestARestoredAdmissionInTheTailOfASelfAdmitChangeIsJudgedAlike(t *testing.T) {
	for _, filedOn := range []bool{true, false} {
		net, member, _, keyOne := newTestConfigRestoredNet(t)
		net.foldSelfAdmit(2, filedOn)
		foldedThrough := net.log.State().Base().GetFoldedThrough()
		proposalId, _ := testConfigProposeRestored(t, net, member, keyOne, testConfigRestoredKind(filedOn))
		net.setHeadSelfAdmit(3, !filedOn)
		if verdict := net.fold(net.owner, foldedThrough, 3); !verdict.Accepted() {
			t.Fatalf("filed with self_admit %v: the base keeping its fold %v", filedOn, verdict.Refusal)
		}
		net.everyReaderAgrees()
		net.wait(72 * testConfigHourMs)
		net.activate(proposalId)
		net.cosign(net.owner, proposalId)
		net.activate(proposalId)
		net.everyReaderAgrees()
	}
}

// Rows carry a PROPOSAL_KIND_RESTORED_COSIGNED row through a base unchanged, to a new device and a rows-only gate alike,
// and api takes the base; the same rows with the row's kind past the enum's last value, 5, or unspecified, 0, are
// refused at api and a fork at a reader, so no verifier holds a kind it cannot judge.
func TestRowsCarryKindFourAndRefuseKindFive(t *testing.T) {
	net, member, _, keyOne := newTestConfigRestoredNet(t)
	net.foldSelfAdmit(2, false)
	proposalId, _ := testConfigProposeRestored(t, net, member, keyOne, bridge.ProposalKind_PROPOSAL_KIND_RESTORED_COSIGNED)
	rows := net.log.State().Rows()
	index := -1
	for i, row := range rows.GetProposals() {
		if bytes.Equal(row.GetProposalId(), proposalId) {
			index = i
		}
	}
	if index < 0 {
		t.Fatal("the rows hold no row of the proposal")
	}
	decoded := &bridge.ProjectionRows{}
	if err := proto.Unmarshal(testConfigMarshal(t, rows), decoded); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(decoded.GetProposals()[index], rows.GetProposals()[index]) ||
		bridge.ProposalKind(decoded.GetProposals()[index].GetKind()) != bridge.ProposalKind_PROPOSAL_KIND_RESTORED_COSIGNED {
		t.Fatalf("the row decoded: %v", decoded.GetProposals()[index])
	}

	net.setHeadSelfAdmit(3, false)
	for _, kind := range []uint32{5, 0} {
		bad := proto.Clone(rows).(*bridge.ProjectionRows)
		bad.Proposals[index].Kind = kind
		entryBytes := net.makeBase(net.owner, bad, net.n, 3, 0)
		signedHeader, rowsBytes, timeMs := net.baseParts(entryBytes)
		if err := net.apiAtTip().CheckBase(signedHeader, rowsBytes, timeMs); !errors.Is(err, ErrConfigRule) {
			t.Errorf("kind %d: api's check %v", kind, err)
		}
		if _, err := net.newReader().Apply(entryBytes, net.source); !errors.Is(err, ErrConfigFork) {
			t.Errorf("kind %d: a reader %v", kind, err)
		}
	}

	entryBytes := net.makeBase(net.owner, rows, net.n, 3, 0)
	signedHeader, rowsBytes, timeMs := net.baseParts(entryBytes)
	if err := net.apiAtTip().CheckBase(signedHeader, rowsBytes, timeMs); err != nil {
		t.Fatalf("api's check of the honest base: %v", err)
	}
	if verdict := net.push(entryBytes); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	want := rows.GetProposals()[index]
	for i, reader := range net.everyReader() {
		got := reader.State().openProposalRows()
		if len(got) != 1 || !proto.Equal(got[0], want) {
			t.Errorf("reader %d: the proposals %v, want %v", i, got, want)
		}
	}
	net.everyReaderAgrees()
}
